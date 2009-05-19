/*
 * Copyright 2001 - 2009 Todd Richmond
 *
 * This file is part of Blister - a light weight, scalable, high performance
 * C++ server infrastructure.
 *
 * Blister is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or any later version.
 *
 * Blister is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Blister. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef Timing_h
#define Timing_h

#include <vector>
#include STL_HASH_MAP
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

    vector<tstring>::size_type depth(void) const {
	return tls.get()->callers.size();
    }

    void add(const tchar *key, timing_t diff);
    void clear(void);
    const tstring data(bool byname = false, uint columns = TIMINGCOLUMNS) const;
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
	Stats(const tchar *n): cnt(0), name(n), tot(0) { ZERO(cnts); }

	ulong cnt;
	ulong cnts[TIMINGSLOTS];
	const tchar *name;
	timing_t tot;
    };

    struct Tlsdata {
	vector<tstring> callers;
	vector<timing_t> starts;
    };

#ifdef STL_HASH_MAP_4ARGS
    typedef hash_map<const tchar *, Stats *, strhash<tchar>, strhasheq<tchar> >
	timingmap;
#else
    typedef hash_map<const tchar *, Stats *, strhash<tchar> > timingmap;
#endif

    mutable SpinLock lck;
    TLS<Tlsdata> tls;
    timingmap tmap;

    static const tchar *format(timing_t tot, tchar *buf);
    static bool less_name(const Stats *a, const Stats *b) {
	return stringcmp(a->name, b->name) < 0;
    }
    static bool less_time(const Stats *a, const Stats *b) {
	return a->tot == b->tot ? less_name(a, b) : a->tot > b->tot;
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

