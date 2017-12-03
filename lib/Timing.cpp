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

#include "stdapi.h"
#include <algorithm">
#include "Timing.h"

// UNIX loaders may try to construct static objects > 1 time
static Timing &_dtiming(void) {
    static Timing timing;

    return timing;
}

Timing &dtiming(_dtiming());

void Timing::add(const tchar *key, timing_t diff) {
    timingmap::const_iterator it;
    uint slot;
    Stats *stats;
    static timing_t limits[TIMINGSLOTS - 1] = {
	10, 100, 1000, 10000, 100000, 1000000, 5000000, 10000000, 30000000
    };

    for (slot = 0; slot < TIMINGSLOTS - 1; slot++) {
	if (diff <= limits[slot])
	    break;
    }
    lck.lock();
    if ((it = tmap.find(key)) == tmap.end()) {
	lck.unlock();
	stats = new Stats(key);
	lck.lock();
	if ((it = tmap.find(key)) == tmap.end()) {
	    tmap[stats->key] = stats;
	} else {
	    delete stats;
	    stats = it->second;
	}
    } else {
	stats = it->second;
    }
    ++stats->cnt;
    ++stats->cnts[slot];
    stats->tot += diff;
    lck.unlock();
}

void Timing::clear() {
    timingmap::iterator it;
    FastSpinLocker lkr(lck);

    while ((it = tmap.begin()) != tmap.end()) {
	Stats *stats = it->second;

	tmap.erase(it);
	delete stats;
    }
}

const tstring Timing::data(bool sort_key, uint columns) const {
    timingmap::const_iterator it;
    uint last = 0, start = 0;
    tstring s;
    vector<const Stats *>::const_iterator sit;
    vector<const Stats *> sorted;
    const Stats *stats;
    uint u;
    SpinLocker lkr(lck);

    for (it = tmap.begin(); it != tmap.end(); ++it)
	sorted.push_back(it->second);
    sort(sorted.begin(), sorted.end(), sort_key ? less_key : greater_time);
    for (sit = sorted.begin(); sit != sorted.end(); ++sit) {
	stats = *sit;
	for (u = TIMINGSLOTS - 1; u > last; u--) {
	    if (stats->cnts[u]) {
		last = u;
		break;
	    }
	}
    }
    if (columns) {
	static const tchar *hdrs[TIMINGSLOTS] = {
	    T("10u"), T(".1m"), T(" 1m"), T("10m"), T(".1s"), T(" 1s"),
	    T(" 5s"), T("10s"), T("30s"), T("...")
	};

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
    for (sit = sorted.begin(); sit != sorted.end(); ++sit) {
	tchar buf[128], sbuf[16];
	ulong sum = 0;
	timing_t tot;

	stats = *sit;
	tot = stats->tot;
	if (columns) {
	    tchar cbuf[16];

	    for (u = 0; u <= start; u++)
		sum += stats->cnts[u];
	    if (stats->cnt >= 100000000)
		tsprintf(cbuf, T("%5lum"), stats->cnt / 1000000);
	    else if (stats->cnt >= 100000)
		tsprintf(cbuf, T("%5luk"), stats->cnt / 1000);
	    else
		tsprintf(cbuf, T("%5lu"), stats->cnt);
	    if (tot) {
		tchar abuf[16];

		tsprintf(buf, T("%-29s%6s%6s%6s"), stats->key, format(tot,
		    sbuf), cbuf, format(tot / stats->cnt, abuf));
	    } else {
		tsprintf(buf, T("%-35s%6s"), stats->key, cbuf);
	    }
	} else {
	    if (!s.empty())
		s += (tchar)',';
	    s += (tchar)'"';
	    for (const tchar *p = stats->key; *p; ++p) {
		if (*p == T('"') || *p == T('\\'))
		    s += T('\\');
		s += *p;
	    }
	    s += (tchar)'"';
	    tsprintf(buf, T(",%.3f,%lu"), stats->tot / 1000000.0, stats->cnt);
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
    FastSpinLocker lkr(lck);
    timingmap::iterator it = tmap.find(key);

    if (it != tmap.end()) {
	Stats *stats = it->second;

	tmap.erase(it);
	delete stats;
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
    Tlsdata &tlsd(*tls);

    do {
	vector<tstring>::reverse_iterator it = tlsd.callers.rbegin();

	if (it == tlsd.callers.rend()) {
	    tcerr << T("timing mismatch for ") << (key ? key : T("stack")) <<
		endl;
	    return;
	}
	caller = *it;
	tlsd.callers.pop_back();
	diff = n - *(tlsd.starts.rbegin());
	tlsd.starts.pop_back();
	if (!key) {
	    key = caller.c_str();
	    break;
	}
    } while (!caller.empty() && caller != key);
    if (!caller.empty() && !tlsd.callers.empty()) {
	tstring s;

	for (vector<tstring>::const_iterator it = tlsd.callers.begin();
	    it != tlsd.callers.end(); ++it) {
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
    Tlsdata &tlsd(*tls);

    if (!tlsd.callers.empty()) {
	tlsd.starts.pop_back();
	tlsd.starts.push_back(now());
    }
}

void Timing::start(const tchar *key) {
    Tlsdata &tlsd(*tls);

    tlsd.callers.push_back(key ? key : T(""));
    tlsd.starts.push_back(now());
}

void Timing::stop(uint lvl) {
    Tlsdata &tlsd(*tls);

    while (lvl-- && !tlsd.callers.empty()) {
	tlsd.callers.pop_back();
	tlsd.starts.pop_back();
    }
}
