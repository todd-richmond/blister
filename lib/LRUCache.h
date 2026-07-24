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
#include <memory>
#include <type_traits>
#include <unordered_map>
#include "Thread.h"

/*
 * Time and size limited LRU Cache
 */
using lruhash_t = uint64_t;

class BLISTER LRUCacheEntry {
public:
    LRUCacheEntry(const void *d, ulong s): data(nullptr), sz(0),
	hash(rapid_hash(d, s)), msec(0) {}
    LRUCacheEntry(const LRUCacheEntry &ce) = default;

    __forceinline operator bool() const { return data != nullptr; }
    __forceinline operator lruhash_t() const { return hash; }
    __forceinline msec_t touch(void) const { return msec; }

    __forceinline void touch(msec_t now) { msec = now; }

    shared_ptr<const void> data;
    ulong sz;

private:
    lruhash_t hash;
    mutable msec_t msec;
};

template<typename C>
class BLISTER LRUCache: nocopy {
public:
    using lru_kv = pair<lruhash_t, C>;
    using lru_list = list<lru_kv>;
    using lru_map = unordered_map<lruhash_t, typename lru_list::iterator>;
    static constexpr ulong LRUCACHE_SIZE = 10UL * 1024 * 1024;
    static constexpr msec_t LRUCACHE_TIME = 5UL * 60 * 1000;

    explicit LRUCache(ulong sz = LRUCACHE_SIZE, msec_t tm = LRUCACHE_TIME):
	cursz(0), maxsz(sz), maxtm(tm), last_purge(0) {
	static_assert(is_base_of_v<LRUCacheEntry, C>, "C must derive from LRUCacheEntry");
	cache_map.reserve(sz / 1024 > 128 ? sz / 1024 : 128);
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
    const C get(const void *data, ulong sz) {
	C entry(data, sz);
	lru_list freed;
	msec_t now = LIKELY(maxtm) ? mticks() : 0;
	FastSpinLocker lkr(lock);

	if (LIKELY(maxtm) && now - last_purge > maxtm / 2) {
	    purge(0, now, freed);
	    last_purge = now;
	}
	auto it = cache_map.find(entry);
	if (it != cache_map.end() && it->second->second.sz == sz &&
	    (!maxtm || now - it->second->second.touch() <= maxtm)) {
	    cache_list.splice(cache_list.begin(), cache_list, it->second);
	    if (LIKELY(maxtm))
		it->second->second.touch(now);
	    return it->second->second;
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
	shared_ptr<const void> newdata(data, [](const void *p) {
	    delete [] (const char *)p;
	});
	FastSpinLocker lkr(lock);
	auto it = cache_map.find(entry);

	if (it != cache_map.end()) {
	    ulong old_sz = it->second->second.sz;

	    old_data = it->second->second.data;
	    entry.data = newdata;
	    entry.sz = sz;
	    entry.touch(now);
	    it->second->second = entry;
	    cache_list.splice(cache_list.begin(), cache_list, it->second);
	    cursz -= old_sz;
	    purge(sz, now, freed);
	    cursz += sz;
	} else {
	    purge(sz, now, freed);
	    entry.data = newdata;
	    entry.sz = sz;
	    entry.touch(now);
	    cursz += sz;
	    cache_list.emplace_front(lruhash_t(entry), entry);
	    cache_map[entry] = cache_list.begin();
	}
	return true;
    }
    void resize(ulong sz, msec_t tm = 0) {
	lru_list freed;
	FastSpinLocker lkr(lock);

	maxtm = tm;
	if (sz < maxsz)
	    purge(maxsz - sz, maxtm ? mticks() : 0, freed);
	maxsz = sz;
    }

private:
    SpinLock lock;
    lru_list cache_list;
    lru_map cache_map;
    ulong cursz, maxsz;
    msec_t maxtm, last_purge;

    void purge(ulong sz, msec_t now, lru_list &freed) {
	if (maxtm && now) {
	    while (!cache_list.empty()) {
		auto &back_entry = cache_list.back();
		if (LIKELY(now - back_entry.second.touch() > maxtm)) {
		    cursz -= back_entry.second.sz;
		    cache_map.erase(back_entry.first);
		    freed.splice(freed.end(), cache_list,
			prev(cache_list.end()));
		} else {
		    break;
		}
	    }
	}
	while (UNLIKELY(cursz + sz > maxsz) && !cache_list.empty()) {
	    auto &back_entry = cache_list.back();

	    cursz -= back_entry.second.sz;
	    cache_map.erase(back_entry.first);
	    freed.splice(freed.end(), cache_list, prev(cache_list.end()));
	}
    }
};

#endif // LRUCache_h
