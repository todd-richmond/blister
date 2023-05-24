/*
 * Copyright 2001-2023 Todd Richmond
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

	hash = 0;
	while (s)
	    hash = hash * 101 + (lruhash_t)p[s--];
    }
    LRUCacheEntry(const LRUCacheEntry &ce): data(ce.data), sz(ce.sz),
	hash(ce.hash), msec(ce.msec) {}

    operator bool() const { return data != NULL; }
    operator lruhash_t() const { return hash; }

    msec_t touch(void) const { return msec; }
    void touch(void) { msec = mticks(); }

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
    }
    ~LRUCache() { clear(); }

    void clear(void) { FastLocker lkr(lock); purge(maxsz); }
    const C get(const void *data, ulong sz) {
	C entry(data, sz);
	FastLocker lkr(lock);
	typename lru_map::const_iterator it = cache_map.find(entry);

	purge(0);
	if (it == cache_map.end()) {
	    return entry;
	} else {
	    cache_list.splice(cache_list.begin(), cache_list, it->second);
	    if (maxtm)
		it->second->second.touch();
	    return it->second->second;
	}
    }
    bool put(C &entry, const void *data, ulong sz) {
	FastLocker lkr(lock);
	typename lru_map::iterator it = cache_map.find(entry);

	if (it != cache_map.end()) {
	    cursz -= it->second->second.sz;
	    cache_list.erase(it->second);
	    cache_map.erase(it);
	}
	if (sz > maxsz) {
	    entry.data = NULL;
	    entry.sz = 0;
	    purge(0);
	    return false;
	}
	entry.data = data;
	entry.sz = sz;
	purge(sz);
	cursz += entry.sz;
	if (maxtm)
	    entry.touch();
	cache_list.push_front(lru_kv(entry, entry));
	cache_map[entry] = cache_list.begin();
	return true;
    }
    void resize(ulong sz, msec_t tm = 0) {
	maxtm = tm;
	if (sz < maxsz)
	    purge(maxsz - sz);
	maxsz = sz;
    }

private:
    Lock lock;
    lru_list cache_list;
    lru_map cache_map;
    ulong cursz;
    ulong maxsz;
    msec_t maxtm;

    void pop(typename lru_list::const_reverse_iterator last) {
	cursz -= last->second.sz;
	delete [] (char *)last->second.data;
	cache_map.erase(last->first);
	cache_list.pop_back();
    }
    void purge(ulong sz) {
	typename lru_list::const_reverse_iterator last;

	if (maxtm) {
	    msec_t now = mticks();

	    while ((last = cache_list.rbegin()) != cache_list.rend()) {
		if (now - last->second.touch() > maxtm)
		    pop(last);
		else
		    break;
	    }
	}
	while (cursz + sz > maxsz && !cache_list.empty())
	    pop(cache_list.rbegin());
    }
};

#endif // LRUCache_h
