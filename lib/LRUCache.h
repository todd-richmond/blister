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

#include <concepts>
#include <list>
#include <memory>
#include <unordered_map>
#include "Thread.h"

/*
 * Time, size and count limited LRU Cache
 */
using lruhash_t = uint64_t;

class BLISTER LRUCacheEntry {
public:
    LRUCacheEntry(const void *d, ulong s): hash(rapid_hash(d, s)) {}

    __forceinline operator bool() const { return data != nullptr; }
    __forceinline operator lruhash_t() const { return hash; }
    __forceinline msec_t touch(void) const { return msec; }

    __forceinline void touch(msec_t now) { msec = now; }

    shared_ptr<const void> data;
    ulong sz = 0;

private:
    lruhash_t hash;
    msec_t msec = 0;
};

template<derived_from<LRUCacheEntry> C>
class BLISTER LRUCache: nocopy {
public:
    using lru_list = list<C>;
    using lru_map = unordered_map<lruhash_t, typename lru_list::iterator>;
    static constexpr ulong LRUCACHE_COUNT = 0;
    static constexpr ulong LRUCACHE_SIZE = 10UL * 1024 * 1024;
    static constexpr msec_t LRUCACHE_TIME = 5UL * 60 * 1000;

    explicit LRUCache(ulong sz = LRUCACHE_SIZE, msec_t tm = LRUCACHE_TIME,
	ulong cnt = LRUCACHE_COUNT): maxcnt(cnt), maxsz(sz), maxtm(tm) {
	ulong heur = sz / 1024 > 128 ? sz / 1024 : 128;

	cache_map.reserve(cnt && cnt < heur ? cnt : heur);
    }
    ~LRUCache() { clear(); }

    void clear(void) {
	lru_list freed;
	FastSpinLocker lkr(lock);

	swap(freed, cache_list);
	cache_map.clear();
	cursz = 0;
	last_purge = 0;
    }
    C get(const void *data, ulong sz) {
	C entry(data, sz);
	lru_list freed;
	msec_t now = LIKELY(maxtm) ? mticks() : 0;
	FastSpinLocker lkr(lock);

	if (LIKELY(maxtm) && now - last_purge > maxtm / 2) {
	    purge(now, freed);
	    last_purge = now;
	}
	auto it = cache_map.find(entry);
	if (it != cache_map.end() &&
	    (!maxtm || now - it->second->touch() <= maxtm)) {
	    cache_list.splice(cache_list.begin(), cache_list, it->second);
	    if (LIKELY(maxtm))
		it->second->touch(now);
	    return *it->second;
	}
	return entry;
    }
    bool put(C &entry, const void *data, ulong sz) {
	if (UNLIKELY(sz > maxsz)) {
	    entry.data = nullptr;
	    entry.sz = 0;
	    return false;
	}

	msec_t now = maxtm ? mticks() : 0;
	lru_list freed;
	shared_ptr<const void> old_data;

	entry.data = shared_ptr<const void>(data, [](const void *p) {
	    delete [] (const char *)p;
	});
	entry.sz = sz;
	entry.touch(now);

	FastSpinLocker lkr(lock);
	auto [it, added] = cache_map.try_emplace(lruhash_t(entry));

	if (added) {
	    cache_list.emplace_front(entry);
	    it->second = cache_list.begin();
	} else {
	    C &node = *it->second;

	    old_data = std::move(node.data);
	    cursz -= node.sz;
	    node = entry;
	    cache_list.splice(cache_list.begin(), cache_list, it->second);
	}
	cursz += sz;
	purge(now, freed);
	return true;
    }
    void resize(ulong sz, msec_t tm = LRUCACHE_TIME,
	ulong cnt = LRUCACHE_COUNT) {
	lru_list freed;
	FastSpinLocker lkr(lock);

	maxcnt = cnt;
	maxsz = sz;
	maxtm = tm;
	purge(maxtm ? mticks() : 0, freed);
    }

private:
    SpinLock lock;
    lru_list cache_list;
    lru_map cache_map;
    ulong cursz = 0, maxcnt, maxsz;
    msec_t maxtm, last_purge = 0;

    void evict(lru_list &freed) {
	cursz -= cache_list.back().sz;
	cache_map.erase(lruhash_t(cache_list.back()));
	freed.splice(freed.end(), cache_list, prev(cache_list.end()));
    }
    void purge(msec_t now, lru_list &freed) {
	if (maxtm && now) {
	    while (!cache_list.empty() &&
		LIKELY(now - cache_list.back().touch() > maxtm))
		evict(freed);
	}
	while (UNLIKELY(cursz > maxsz ||
	    (maxcnt && cache_map.size() > maxcnt)) && !cache_list.empty())
	    evict(freed);
    }
};

#endif // LRUCache_h
