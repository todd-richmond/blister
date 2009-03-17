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

#define TIMINGSLOTS	8

typedef usec_t timing_t;

class Timing {
public:
    Timing() {}
    ~Timing() { clear(); }

    timing_t add(const tchar *key, timing_t diff);
    void clear(void);
    const tstring data(bool compact = false) const;
    void erase(const tchar *key);
    timing_t now(void) const { return uticks(); }
    timing_t record(const tchar *key = NULL);
    timing_t record(const tchar *key, timing_t start) {
	timing_t n = now();

	return add(key, n > start ? n - start : 0);
    }
    timing_t start(void) const { return now(); }
    timing_t start(const tchar *key);
    void stop(uint lvl = (uint)-1);

private:
    struct Stats {
	Stats(): cnt(0), tot(0) { ZERO(cnts); }

	ulong cnt;
	ulong cnts[TIMINGSLOTS];
	timing_t tot;
    };

    struct Tlsdata {
	vector<tstring> callers;
	vector<timing_t> starts;
    };

    typedef hash_map<tstring, Stats *, strhash<tchar> > timingmap;

    mutable SpinLock lck;
    TLS<Tlsdata> tls;
    timingmap tmap;

    static const tchar *format(timing_t tot, tchar *buf);
};

extern Timing &dtiming;

#endif // _Timing_h
