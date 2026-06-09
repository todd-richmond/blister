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

#ifndef Timing_h
#define Timing_h

#include <atomic>
#include <unordered_map>
#include <vector>
#include "Thread.h"

/*
 * The Timing class is used to track call durations to enable simple profiling.
 * It maintains buckets of usec intervals to aid in determining calls with
 * randomly dispersed run times. A simple pretty-print function makes evaluating
 * code optimization priorities easier
 *
 * keys are statically hashed when possible for performance which could cause
 * collisions, but key set will be small and performance hit would be 3x
 *
 * A global "dtiming" object allows for the simplest functionality but other
 * objects can be instantiated as well
 *
 * Timing can be used in either "direct" or "stack" mode. There are TimingEntry
 * and TimingFrame classes to simplify timing code blocks
 *
 * direct: lowest overhead for fine grained profile tasks
 *   function_c() {
 *     TimingEntry entry(T("function_c"));
 *     code_c();
 *   }
 *
 *   timing_t starta = dtiming.start();
 *   function_a();
 *   timing_t startb = dtiming.record(T("function_a"), starta);
 *   function_b();
 *   dtiming.record(T("function_b"), startb);
 *   function_c();
 *   dtiming.record(T("a+b+c"), starta);
 *   tcout << dtiming.data() << endl;
 *
 * stack: slower but tracks timing across a virtual callstack
 *   void call_b() {
 *     dtiming.start(T("function_b"));
 *     function_b();
 *     call_c();
 *     dtiming.record();
 *   }
 *
 *   void call_c() {
 *     TimingFrame tf(T("call_c"));
 *     function_c();
 *   }
 *
 *   dtiming.start(T("function_a"));
 *   function_a();
 *   call_b();
 *   dtiming.record();
 *   tcout << dtiming.data() << endl;
 */

using timing_t = usec_t;

class BLISTER Timing: nocopy {
public:
    static constexpr uint CACHESIZE = 4096;
    static constexpr uint TIMINGSLOTS = 10;

    Timing(): cache{}, flist(nullptr) {}
    ~Timing();

    uint depth(void) const { return static_cast<uint>(tls->entries.size()); }

    template<size_t N>
    __forceinline void add(const tchar (&key)[N], timing_t diff) {
	add(key, N - 1, stringhash(key), diff);
    }
    __forceinline void add(const tchar *key, timing_t diff) {
	add(key, 0, stringhash(key), diff);
    }
    __forceinline void add(const tstring &key, timing_t diff) {
	add(key.c_str(), static_cast<uint>(key.length()), stringhash(key), diff);
    }
    void clear(void);
    const tstring data(bool sort_by_key = false, uint columns = TIMINGSLOTS - 2)
	const;
    template<size_t N>
    __forceinline void erase(const tchar (&key)[N]) {
	erase(stringhash(key));
    }
    __forceinline void erase(const tchar *key) {
	erase(stringhash(key));
    }
    __forceinline void erase(const tstring &key) {
	erase(stringhash(key));
    }
    void erase(strhash_t hash);
    void record(void);
    template<size_t N>
    __forceinline timing_t record(const tchar (&key)[N], timing_t begin) {
	timing_t n = now();

	add(key, N - 1, stringhash(key), n - begin);
	return n;
    }
    __forceinline timing_t record(const tchar *key, timing_t begin) {
	timing_t n = now();

	add(key, 0, stringhash(key), n - begin);
	return n;
    }
    __forceinline timing_t record(const tstring &key, timing_t begin) {
	timing_t n = now();

	add(key.c_str(), 0, stringhash(key), n - begin);
	return n;
    }
    void restart(void);
    template<size_t N>
    __forceinline void start(const tchar (&key)[N]) {
	start(key, stringhash(key));
    }
    __forceinline void start(const tchar *key) { start(key, stringhash(key)); }
    __forceinline void start(const tstring &key) { start(key.c_str()); }
    void stop(void);
    static __forceinline timing_t now(void) { return uticks(); }
    static __forceinline timing_t start(void) { return now(); }

private:
    struct BLISTER Stats: nocopy {
	alignas(64) atomic_uint_fast32_t cnt{};
	atomic_uint_fast32_t cnts[TIMINGSLOTS]{};
	atomic_uint_fast64_t tot{};
	Stats *flist = nullptr;
	size_t hash = 0;
	uint klen = 0;
	tchar key[];

	static Stats *newstats(const tchar *k, uint klen, strhash_t h);
	static void delstats(Stats *s) { delete [] (char *)s; }
    };

    struct BLISTER Tlsdata {
	struct Entry {
	    const tchar *caller;
	    strhash_t hash;
	    timing_t start;
	};

	vector<Entry> entries;
    };

    using timingmap = unordered_map<strhash_t, Stats *>;

    atomic<Stats *> cache[CACHESIZE]{};
    atomic<Stats *> flist;
    mutable SpinRWLock lck;
    ThreadLocalClass<Tlsdata> tls;
    timingmap tmap;

    void add(const tchar *key, uint klen, strhash_t hash, timing_t diff);
    void start(const tchar *key, strhash_t hash);
    static const tchar *format(timing_t tot, tchar *buf);
};

extern BLISTER Timing &dtiming;

// time a code block
class BLISTER TimingEntry: nocopy {
public:
    template<class C> __forceinline explicit TimingEntry(const C &key,
	Timing &t = dtiming): key(key), start(t.start()), timing(t) {}
    template<size_t N> __forceinline explicit TimingEntry(const tchar (&key)[N],
	Timing &t = dtiming): key(key), start(t.start()), timing(t) {}
    __forceinline ~TimingEntry() {
	if (start != (timing_t)-1)
	    timing.add(key, Timing::now() - start);
    }

    __forceinline void record(void) {
	timing.record(key, start);
	stop();
    }
    void restart(void) { start = timing.start(); }
    void stop(void) { start = (timing_t)-1; }

private:
    const tchar *key;
    timing_t start;
    Timing &timing;
};

// time a stack call including destructors
class BLISTER TimingFrame: nocopy {
public:
    template<class C> __forceinline explicit TimingFrame(const C &key,
	Timing &t = dtiming): started(true), timing(t) {
	timing.start(key);
    }
    template<size_t N> __forceinline explicit TimingFrame(const tchar (&key)[N],
	Timing &t = dtiming): started(true), timing(t) {
	timing.start(key);
    }
    __forceinline ~TimingFrame() {
	if (started)
	    timing.record();
    }

    __forceinline void record(void) {
	timing.record();
	started = false;
    }
    void restart(void) {
	if (started)
	    timing.restart();
    }
    void stop(void) {
	timing.stop();
	started = false;
    }

private:
    bool started;
    Timing &timing;
};

#endif // _Timing_h
