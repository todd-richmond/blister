/*
 * Copyright 2001-2017 Todd Richmond
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

#include <vector>
#include STL_UNORDERED_MAP_H
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
 * direct: lowest overhead for basic or fine grained profile tasks
 *   function_c() {
 *     TimingEntry te(T("function_c"));
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
 */

typedef usec_t timing_t;

#define TIMING_KEY(i) __forceinline TimingKey(const tchar (&k)[i]): \
    StringHash(k), key(k) {}

class BLISTER TimingKey: public StringHash {
public:
    __forceinline TimingKey(const DynamicString &ds): StringHash(ds),
	key(ds.s) {}

    TIMING_KEY(1) TIMING_KEY(2) TIMING_KEY(3) TIMING_KEY(4)
    TIMING_KEY(5) TIMING_KEY(6) TIMING_KEY(7) TIMING_KEY(8)
    TIMING_KEY(9) TIMING_KEY(10) TIMING_KEY(11) TIMING_KEY(12)
    TIMING_KEY(13) TIMING_KEY(14) TIMING_KEY(15) TIMING_KEY(16)
    TIMING_KEY(17) TIMING_KEY(18) TIMING_KEY(19) TIMING_KEY(20)
    TIMING_KEY(21) TIMING_KEY(22) TIMING_KEY(23) TIMING_KEY(24)
    TIMING_KEY(25) TIMING_KEY(26) TIMING_KEY(27) TIMING_KEY(28)
    TIMING_KEY(29) TIMING_KEY(30) TIMING_KEY(31) TIMING_KEY(32)
    TIMING_KEY(33) TIMING_KEY(34) TIMING_KEY(35) TIMING_KEY(36)
    TIMING_KEY(37) TIMING_KEY(38) TIMING_KEY(39) TIMING_KEY(40)
    TIMING_KEY(41) TIMING_KEY(42) TIMING_KEY(43) TIMING_KEY(44)
    TIMING_KEY(45) TIMING_KEY(46) TIMING_KEY(47) TIMING_KEY(48)
    TIMING_KEY(49) TIMING_KEY(50) TIMING_KEY(51) TIMING_KEY(52)
    TIMING_KEY(53) TIMING_KEY(54) TIMING_KEY(55) TIMING_KEY(56)
    TIMING_KEY(57) TIMING_KEY(58) TIMING_KEY(59) TIMING_KEY(60)
    TIMING_KEY(61) TIMING_KEY(62) TIMING_KEY(63) TIMING_KEY(64)

    __forceinline operator const tchar *(void) const { return key; }
    size_t __forceinline hash(void) const { return operator size_t(); }

private:
    const tchar *key;
};

class BLISTER Timing: nocopy {
public:
    Timing() {}
    ~Timing() { clear(); }

    static const uint TIMINGSLOTS = 10;

    vector<tstring>::size_type depth(void) const { return tls->callers.size(); }

    template<class C> void __forceinline add(const C &key, timing_t diff) {
	add(TimingKey(key), diff);
    }
    void add(const TimingKey &key, timing_t diff);
    void clear(void);
    const tstring data(bool sort_by_key = false, uint columns = TIMINGSLOTS - 2)
	const;
    template<class C> void erase(const C &key) { erase(TimingKey(key)); }
    void record(void);
    template<class C> void __forceinline record(const C &key) {
	record(TimingKey(key));
    }
    template<class C> timing_t __forceinline record(const C &key, timing_t
	begin) {
	return record(TimingKey(key), begin);
    }
    timing_t __forceinline record(const TimingKey &key, timing_t begin) {
	timing_t n = now();

	add(key, n - begin);
	return n;
    }
    void restart(void);
    timing_t __forceinline start(void) const { return now(); }
    void start(const TimingKey &key);
    template<class C> void __forceinline start(const C &key) {
	start(TimingKey(key));
    }
    void stop(uint lvl = (uint)-1);
    static timing_t __forceinline now(void) { return uticks(); }

private:
    struct BLISTER Stats {
	explicit Stats(const tchar *k): cnt(0), key(tstrdup(k)), tot(0) {
	    ZERO(cnts);
	}
	~Stats() { free((char *)key); }

#if CPLUSPLUS >= 11
	TSNumber<ulong> cnt;
	TSNumber<ulong> cnts[TIMINGSLOTS];
	const tchar *key;
	TSNumber<timing_t> tot;
#else
	ulong cnt;
	ulong cnts[TIMINGSLOTS];
	const tchar *key;
	timing_t tot;
#endif
    };

    struct BLISTER Tlsdata {
	vector<tstring> callers;
	vector<timing_t> starts;
    };

    typedef unordered_map<size_t, Stats *> timingmap;

    mutable SpinRWLock lck;
    ThreadLocalClass<Tlsdata> tls;
    timingmap tmap;

    void erase(const TimingKey &key);
    void record(const TimingKey &key);
    static const tchar *format(timing_t tot, tchar *buf);
    static bool less_key(const Stats *a, const Stats *b) {
	return stringless(a->key, b->key);
    }
    static bool greater_time(const Stats *a, const Stats *b) {
	return a->tot == b->tot ? stringless(a->key, b->key) : a->tot >
	    b->tot;
    }
};

extern BLISTER Timing &dtiming;

// time a code block including destructors
class BLISTER TimingEntry: nocopy {
public:
    template<class C> __forceinline TimingEntry(const C &k, Timing &t =
	dtiming): key(k), start(t.start()), timing(t) {}
    __forceinline ~TimingEntry() {
	if (start != (timing_t)-1)
	    timing.add(key, timing.now() - start);
    }

    void __forceinline record(void) { start = timing.record(key, start); }
    void restart(void) { start = timing.start(); }
    void stop(void) { start = (timing_t)-1; }

private:
    const TimingKey key;
    timing_t start;
    Timing &timing;
};

// time a function block including destructors
class BLISTER TimingFrame: nocopy {
public:
    template<class C> __forceinline TimingFrame(const C &k, Timing &t =
	dtiming): key(k), started(true), timing(t) {
	timing.start(key);
    }
    __forceinline ~TimingFrame() {
	if (started)
	    timing.record();
    }

    void __forceinline record(void) { timing.record(); started = false; }
    void restart(void) {
	if (started) {
	    timing.restart();
	} else {
	    started = true;
	    timing.start(key);
	}
    }
    void stop(void) { timing.stop(1); started = false; }

private:
    const TimingKey key;
    bool started;
    Timing &timing;
};

#endif // _Timing_h
