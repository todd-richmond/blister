/*
 * Copyright 2001-2026 Todd Richmond
 *
 * This file is part of Blister - a light weight, scalable, high performance
 * C++ server framework.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License. You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef LRUCache_h
#define LRUCache_h

#include <list>
#include <unordered_map>
#include "Thread.h"

/*
 * Time and size limited LRU Cache
 */
typedef uint64_t lruhash_t;

class BLISTER LRUCacheEntry {
public:
    LRUCacheEntry(const void *d, ulong s): data(NULL), sz(0), msec(0) {
	const char *p = (const char *)d;
	lruhash_t h = 0;

	if (LIKELY(s >= 8 && ((uintptr_t)p & 7) == 0)) {
	    const uint64_t *p64 = (const uint64_t *)p;
	    ulong s64 = s >> 3;

	    for (ulong u = 0; u < s64; ++u)
		h = h * 101 + p64[u];
	    p += s64 << 3;
	    s &= 7;
	}
	for (ulong u = 0; u < s; ++u)
	    h = h * 101 + (lruhash_t)p[u];
	hash = h;
    }
    LRUCacheEntry(const LRUCacheEntry &ce): data(ce.data), sz(ce.sz),
	hash(ce.hash), msec(ce.msec) {}

    __forceinline operator bool() const { return data != NULL; }
    __forceinline operator lruhash_t() const { return hash; }
    __forceinline msec_t touch(void) const { return msec; }

    __forceinline void touch(msec_t now) { msec = now;; }

    const void *data;
    ulong sz;

private:
    lruhash_t hash;
    mutable msec_t msec;
};

template<typename C>
class BLISTER LRUCache: nocopy {
public:
    typedef pair<lruhash_t, C> lru_kv;
    typedef list<lru_kv> lru_list;
    typedef typename lru_list::iterator list_iterator;
    typedef unordered_map<lruhash_t, list_iterator> lru_map;
    static constexpr int LRUCACHE_SIZE = 10 * 1024 * 1024;
    static constexpr int LRUCACHE_TIME = 5 * 60 * 1000;

    explicit LRUCache(ulong sz = LRUCACHE_SIZE, msec_t tm = LRUCACHE_TIME):
	cursz(0), maxsz(sz), maxtm(tm) {
	(void)static_cast<LRUCacheEntry *>((C *)0); // enforce base class
	cache_map.reserve(128);
    }
    ~LRUCache() { clear(); }

    void clear(void) {
	FastLocker lkr(lock);

	purge(maxsz, 0);
    }
    const C get(const void *data, ulong sz) {
	C entry(data, sz);
	typename lru_map::const_iterator it;
	Locker lkr(lock, false);
	msec_t now;

	if (LIKELY(maxtm)) {
	    now = mticks();
	    lkr.lock();
	    purge(0, now);
	} else {
	    lkr.lock();
	    purge(0, 0);
	}
	it = cache_map.find(entry);
	if (it == cache_map.end())
	    return entry;
	cache_list.splice(cache_list.begin(), cache_list, it->second);
	if (LIKELY(maxtm))
	    it->second->second.touch(now);
	return it->second->second;
    }
    bool put(C &entry, const void *data, ulong sz) {
	typename lru_map::iterator it;
	Locker lkr(lock, false);
	msec_t now;

	if (UNLIKELY(sz > maxsz)) {
	    entry.data = NULL;
	    entry.sz = 0;
	    return false;
	}
	now = maxtm ? mticks() : 0;
	lkr.lock();
	it = cache_map.find(entry);
	if (it != cache_map.end()) {
	    cursz -= it->second->second.sz;
	    cache_list.erase(it->second);
	    cache_map.erase(it);
	}
	purge(sz, now);
	entry.data = data;
	entry.sz = sz;
	entry.touch(now);
	cursz += entry.sz;
	cache_list.push_front(lru_kv(entry, entry));
	cache_map[entry] = cache_list.begin();
	return true;
    }
    void resize(ulong sz, msec_t tm = 0) {
	FastLocker lkr(lock);

	maxtm = tm;
	if (sz < maxsz)
	    purge(maxsz - sz, maxtm ? mticks() : 0);
	maxsz = sz;
    }

private:
    alignas(64) Lock lock;
    lru_list cache_list;
    lru_map cache_map;
    ulong cursz, maxsz;
    msec_t maxtm;

    __forceinline void pop(typename lru_list::const_reverse_iterator last) {
	cursz -= last->second.sz;
	delete [] (char *)last->second.data;
	cache_map.erase(last->first);
	cache_list.pop_back();
    }
    void purge(ulong sz, msec_t now) {
	typename lru_list::const_reverse_iterator last;

	if (maxtm && now) {
	    while ((last = cache_list.rbegin()) != cache_list.rend()) {
		if (LIKELY(now - last->second.touch() > maxtm))
		    pop(last);
		else
		    break;
	    }
	}
	while (UNLIKELY(cursz + sz > maxsz) && (last = cache_list.rbegin()) !=
	    cache_list.rend())
	    pop(last);
    }
};

#endif // LRUCache_h
