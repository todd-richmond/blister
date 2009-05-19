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
    static timing_t limits[TIMINGSLOTS - 1] = {
	10, 100, 1000, 10000, 100000, 1000000, 5000000, 10000000, 30000000
    };

    if (it == tmap.end()) {
	key = tstrdup(key);
	stats = tmap[key] = new Stats(key);
    } else {
	stats = it->second;
    }
    for (slot = 0; slot < TIMINGSLOTS - 1; slot++) {
	if (diff <= limits[slot])
	    break;
    }
    stats->cnt++;
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

const tstring Timing::data(bool sortbyname, uint columns) const {
    timingmap::const_iterator it;
    uint last = 0, start = 0;
    SpinLocker lkr(lck);
    tstring s;
    vector<const Stats *>::const_iterator sit;
    vector<const Stats *> sorted;
    const Stats *stats;
    uint u;
    static const tchar *hdrs[TIMINGSLOTS] = {
	T("10u"), T(".1m"), T(" 1m"), T("10m"), T(".1s"), T(" 1s"), T(" 5s"),
	T("10s"), T("30s"), T("...")
    };

    for (it = tmap.begin(); it != tmap.end(); it++)
	sorted.push_back(it->second);
    sort(sorted.begin(), sorted.end(), sortbyname ? less_name : less_time);
    for (sit = sorted.begin(); sit != sorted.end(); sit++) {
	stats = *sit;
	for (u = TIMINGSLOTS - 1; u > last; u--) {
	    if (stats->cnts[u]) {
		last = u;
		break;
	    }
	}
    }
    if (columns) {
	if (columns > TIMINGSLOTS)
	    columns = TIMINGSLOTS;
	start = last < columns ? 0 : last - columns + 1;
	s = T("key                            msec   cnt   avg");
	for (u = start; u <= last; u++) {
	    s += (tchar)' ';
	    s += hdrs[u];
	}
	s += (tchar)'\n';
    }
    for (sit = sorted.begin(); sit != sorted.end(); sit++) {
	tchar abuf[16], buf[128], cbuf[16], sbuf[16];
	ulong sum = 0;
	timing_t tot;

	stats = *sit;
	tot = stats->tot;
	if (columns) {
	    for (u = 0; u <= start; u++)
		sum += stats->cnts[u];
	    if (stats->cnt >= 100000000)
		tsprintf(cbuf, T("%5lum"), stats->cnt / 1000000);
	    else if (stats->cnt >= 100000)
		tsprintf(cbuf, T("%5luk"), stats->cnt / 1000);
	    else
		tsprintf(cbuf, T("%5lu"), stats->cnt);
	    if (tot)
		tsprintf(buf, T("%-29s%6s%6s%6s"), stats->name, format(tot,
		    sbuf), cbuf, format(tot / stats->cnt, abuf));
	    else
		tsprintf(buf, T("%-35s%6s"), stats->name, cbuf);
	} else {
	    if (!s.empty())
		s += (tchar)',';
	    tsprintf(buf, T("%s,%s,%lu"), stats->name, format(tot, sbuf),
		stats->cnt);
	}
	s += buf;
	for (u = start; u <= last && tot; u++) {
	    ulong cnt = (columns && u == start) ? sum : stats->cnts[u];

	    if (!columns) {
		tsprintf(buf, T(",%lu"), cnt);
		s += buf;
	    } else if (cnt == 0) {
		s += T("    ");
	    } else if (cnt < 100) {
		tsprintf(buf, T(" %3lu"), cnt);
		s += buf;
	    } else if (cnt == stats->cnt) {
		s += T("   *");
	    } else {
		tsprintf(buf, T(" %2u%%"), (uint)(cnt * 100 / stats->cnt));
		s += buf;
	    }
	}
	if (columns)
	    s += (tchar)'\n';
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

const tchar *Timing::format(timing_t t, tchar *buf) {
    float f(t / 1000.0f);

    if (f < 10)
	tsprintf(buf, T("%.3f"), f);
    else if (f < 100)
        tsprintf(buf, T("%.2f"), f);
    else if (f < 10000)
        tsprintf(buf, T("%.0f"), f);
    else if (f < 1000000)
        tsprintf(buf, T("%.0fk"), f / 1000);
    else
        tsprintf(buf, T("%.0fm"), f / 1000000);
    return buf;
}

void Timing::record(const tchar *key) {
    timing_t n = now();
    tstring caller;
    timing_t diff;
    Tlsdata *tlsd = tls.get();

    do {
	vector<tstring>::reverse_iterator it = tlsd->callers.rbegin();

	if (it == tlsd->callers.rend()) {
	    tcerr << T("timing mismatch for ") << (key ? key : T("stack")) <<
		endl;
	    return;
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
}

void Timing::restart() {
    Tlsdata *tlsd = tls.get();

    if (!tlsd->callers.empty()) {
	tlsd->starts.pop_back();
	tlsd->starts.push_back(now());
    }
}

void Timing::start(const tchar *key) {
    Tlsdata *tlsd = tls.get();

    tlsd->callers.push_back(key ? key : T(""));
    tlsd->starts.push_back(now());
}

void Timing::stop(uint lvl) {
    Tlsdata *tlsd = tls.get();

    while (lvl-- && !tlsd->callers.empty()) {
	tlsd->callers.pop_back();
	tlsd->starts.pop_back();
    }
}

