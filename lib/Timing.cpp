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

#include "stdapi.h"
#include <algorithm>
#include "Timing.h"

// UNIX loaders may try to construct static objects > 1 time
static Timing &_dtiming(void) {
    static Timing timing;

    return timing;
}

Timing &dtiming(_dtiming());

void Timing::add(const tchar *key, timing_t diff) {
    SpinLocker lkr(lck);
    timingmap::const_iterator it = tmap.find(key);
    uint slot;
    Stats *stats;

    if (it == tmap.end())
	stats = tmap[tstrdup(key)] = new Stats;
    else
	stats = it->second;
    stats->cnt++;
    if (diff < 10000)
	slot = 0;
    else if (diff < 100000)
	slot = 1;
    else if (diff < 1000000)
	slot = 2;
    else if (diff < 5000000)
	slot = 3;
    else if (diff < 10000000)
	slot = 4;
    else if (diff < 30000000)
	slot = 5;
    else if (diff < 60000000)
	slot = 6;
    else
	slot = 7;
    stats->cnts[slot]++;
    stats->tot += diff;
}

void Timing::clear() {
    timingmap::iterator it;
    SpinLocker lkr(lck);

    while ((it = tmap.begin()) != tmap.end()) {
	const tchar *p = it->first;

	delete it->second;
	tmap.erase(it);
	free((tchar *)p);
    }
}

const tstring Timing::data(bool compact) const {
    timingmap::const_iterator it;
    vector<const tchar *> keys;
    tstring s;
    SpinLocker lkr(lck);

    if (!compact)
	s = T("key                            sum    cnt    avg 1ms 1cs .1s  1s  5s 10s 30s  1m\n");
    for (it = tmap.begin(); it != tmap.end(); it++)
	keys.push_back(it->first);
    sort(keys.begin(), keys.end(), strless<tchar>::less);
    for (vector<const tchar *>::const_iterator kit = keys.begin();
	kit != keys.end(); kit++) {
	tchar abuf[16], buf[128], cbuf[16], sbuf[16];
	const Stats *stats;

	it = tmap.find(*kit);
	stats = it->second;
	if (compact) {
	    if (!s.empty())
		s += (tchar)',';
	    sprintf(buf, "%s,%s,%lu", it->first, format(stats->tot, sbuf),
		stats->cnt);
	} else {
	    if (stats->cnt >= 1000000)
		tsprintf(cbuf, T("%6luk"), stats->cnt / 1000);
	    else
		tsprintf(cbuf, T("%6lu"), stats->cnt);
	    sprintf(buf, "%-27s%7s%7s%7s", it->first, format(stats->tot, sbuf),
		cbuf, format(stats->tot / stats->cnt, abuf));
	}
	s += buf;
	for (uint u = 0; u < TIMINGSLOTS; u++) {
	    ulong cnt = stats->cnts[u];

	    if (compact) {
		tsprintf(buf, T(",%lu"), cnt);
		s += buf;
	    } else if (cnt == 0) {
		s += "    ";
	    } else if (cnt < 100) {
		tsprintf(buf, T("%4lu"), cnt);
		s += buf;
	    } else if (cnt == stats->cnt) {
		s += "   *";
	    } else {
		tsprintf(buf, T("%3u%%"), (uint)(cnt * 100 / stats->cnt));
		s += buf;
	    }
	}
	if (!compact)
	    s += T("\n");
    }
    return s;
}

void Timing::erase(const tchar *key) {
    SpinLocker lkr(lck);
    timingmap::iterator it = tmap.find(key);

    if (it != tmap.end()) {
	const tchar *p = it->first;

	delete it->second;
	tmap.erase(it);
	free((tchar *)p);
    }
}

timing_t Timing::record(const tchar *key) {
    tstring caller;
    timing_t diff;
    timing_t n = now();
    Tlsdata *tlsd = tls.get();

    do {
	vector<tstring>::reverse_iterator it = tlsd->callers.rbegin();

	if (it == tlsd->callers.rend()) {
	    tcerr << T("timing mismatch for ") << (key ? key : T("stack")) <<
		endl;
	    return 0;
	}
	caller = *it;
	tlsd->callers.pop_back();
	if (!key)
	    key = caller.c_str();
	diff = n - *(tlsd->starts.rbegin());
	tlsd->starts.pop_back();
    } while (!caller.empty() && caller != key);
    if (!caller.empty() && !tlsd->callers.empty()) {
	tstring s;

	for (vector<tstring>::const_iterator it = tlsd->callers.begin();
	    it != tlsd->callers.end(); it++) {
	    if (!s.empty())
		s += T("->");
	    s += *it;
	}
	s += T("->");
	s += key;
	add(s.c_str(), diff);
    }
    add(key, diff);
    return now();
}

timing_t Timing::start(const tchar *key) {
    timing_t n;
    Tlsdata *tlsd = tls.get();

    tlsd->callers.push_back(key ? key : T(""));
    tlsd->starts.push_back(n = now());
    return n;
}

void Timing::stop(uint lvl) {
    Tlsdata *tlsd = tls.get();

    while (lvl-- && !tlsd->callers.empty()) {
	tlsd->callers.pop_back();
	tlsd->starts.pop_back();
    }
}

const tchar *Timing::format(timing_t t, tchar *buf) {
    float f(t / 1000000.0f);

    if (f < 9.9995)
	tsprintf(buf, T("%.3f"), f);
    else if (f < 99.995)
        tsprintf(buf, T("%.2f"), f);
    else
        tsprintf(buf, T("%.0f"), f + .5);
    return buf;
}

