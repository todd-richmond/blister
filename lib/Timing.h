/*
 * Copyright 2001-2016 Todd Richmond
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
 * randomly dispersed run times and includes a simple pretty-print function to
 * make prioritizing code optimization easier.
 *
 * A global "dtiming" object allows for the simplest functionality but other
 * objects can be instantiated as well
 * 
 * Timing can be used in either "direct" or "stack" mode. There are TimingEntry
 * and TimingFrame classes to simplify code even further
 *
 * direct: lowest overhead for most profile tasks
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

#define TIMINGCOLUMNS	8
#define TIMINGSLOTS	10

typedef usec_t timing_t;

class Timing {
public:
    Timing() {}
    ~Timing() { clear(); }

    vector<tstring>::size_type depth(void) const { return tls->callers.size(); }

    void add(const tchar *key, timing_t diff);
    void clear(void);
    const tstring data(bool sort_key = false, uint columns = TIMINGCOLUMNS) const;
    void erase(const tchar *key);
    void record(const tchar *key = NULL);
    timing_t record(const tchar *key, timing_t start) {
	timing_t n = now();

	add(key, n - start);
	return n;
    }
    void restart(void);
    timing_t start(void) const { return now(); }
    void start(const tchar *key);
    void stop(uint lvl = (uint)-1);
    static timing_t now(void) { return microticks(); }

private:
    struct Stats {
	explicit Stats(const tchar *k): cnt(0), key(tstrdup(k)), tot(0) {
	    ZERO(cnts);
	}
	~Stats() { free((char *)key); }
	
	ulong cnt;
	ulong cnts[TIMINGSLOTS];
	const tchar *key;
	timing_t tot;
    };

    struct Tlsdata {
	vector<tstring> callers;
	vector<timing_t> starts;
    };

    typedef unordered_map<const tchar *, Stats *, strhash<tchar>, streq<tchar> >
	timingmap;

    mutable SpinLock lck;
    ThreadLocalClass<Tlsdata> tls;
    timingmap tmap;

    static const tchar *format(timing_t tot, tchar *buf);
    static bool less_key(const Stats *a, const Stats *b) {
	return stringless(a->key, b->key);
    }
    static bool greater_time(const Stats *a, const Stats *b) {
	return a->tot == b->tot ? stringless(a->key, b->key) : a->tot >
	    b->tot;
    }
};

extern Timing &dtiming;

/*
 * Simple wrapper to add timing data upon object destruction which reduces
 * timing a function call down to a single line of code and allows it to
 * included destructor overhead
 */
class TimingEntry: nocopy {
public:
    TimingEntry(const tchar *k, Timing &t = dtiming): key(k), timing(t) {
	start = timing.start();
    }
    ~TimingEntry() {
	if (start != (timing_t)-1)
	    timing.add(key, timing.now() - start);
    }

    void record(void) { start = timing.record(key, start); }
    void restart(void) { start = timing.start(); }
    void stop(void) { start = (timing_t)-1; }

private:
    const tchar *key;
    timing_t start;
    Timing &timing;
};

class TimingFrame: nocopy {
public:
    TimingFrame(const tchar *k, Timing &t = dtiming): key(k), started(true),
	timing(t) {
	timing.start(key);
    }
    ~TimingFrame() {
	if (started)
	    timing.record();
    }

    void record(void) { timing.record(); started = false; }
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
    const tchar *key;
    bool started;
    Timing &timing;
};

#endif // _Timing_h

