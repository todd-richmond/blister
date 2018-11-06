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
#include <algorithm>
#include "Timing.h"

// UNIX loaders may try to construct static objects > 1 time
static Timing &_dtiming(void) {
    static Timing timing;

    return timing;
}

Timing &dtiming(_dtiming());

void Timing::add(const TimingKey &key, timing_t diff) {
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
    lck.rlock();
    if ((it = tmap.find(key.hash())) == tmap.end()) {
	lck.runlock();
	stats = new Stats(key);
	lck.wlock();
	if ((it = tmap.find(key.hash())) == tmap.end()) {
	    tmap[key] = stats;
	} else {
	    delete stats;
	    stats = it->second;
	}
    } else {
	stats = it->second;
//lck.runlock();
//lck.wlock();
	lck.uplock();
    }
    ++stats->cnt;
    ++stats->cnts[slot];
    stats->tot += diff;
    lck.wunlock();
}

void Timing::clear() {
    timingmap::iterator it;
    FastSpinWLocker lkr(lck);

    while ((it = tmap.begin()) != tmap.end()) {
	Stats *stats = it->second;

	tmap.erase(it);
	delete stats;
    }
}

const tstring Timing::data(bool sort_key, uint columns) const {
    timingmap::const_iterator it;
    uint last = 0, begin = 0;
    tstring s;
    vector<const Stats *>::const_iterator sit;
    vector<const Stats *> sorted;
    const Stats *stats;
    uint u;
    FastSpinRLocker lkr(lck);
    static const tchar *hdrs[TIMINGSLOTS] = {
	T("10u"), T(".1m"), T("1m"), T("10m"), T(".1s"), T("1s"),
	T("5s"), T("10s"), T("30s"), T("...")
    };

    if (columns > TIMINGSLOTS)
	columns = TIMINGSLOTS;
    sorted.reserve(tmap.size());
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
    begin = !columns || last < columns ? 0 : last - columns + 1;
    s = columns ? T("key                            msec   cnt   avg") :
	T("key,msec,cnt,avg");
    for (u = begin; u <= last; u++) {
	if (columns) {
	    tchar buf[8];

	    tsprintf(buf, T("%4s"), hdrs[u]);
	    s += buf;
	} else {
	    s += (tchar)',';
	    s += hdrs[u];
	}
    }
    s += (tchar)'\n';
    for (sit = sorted.begin(); sit != sorted.end(); ++sit) {
	tchar buf[128], sbuf[16];
	ulong sum = 0;
	timing_t tot;

	stats = *sit;
	tot = stats->tot;
	if (columns) {
	    tchar cbuf[24];

	    for (u = 0; u <= begin; u++)
		sum += stats->cnts[u];
	    if (stats->cnt >= 10000000UL)
		tsprintf(cbuf, T("%4lum"), stats->cnt / 1000000UL);
	    else if (stats->cnt >= 10000UL)
		tsprintf(cbuf, T("%4luk"), stats->cnt / 1000UL);
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
	    s += (tchar)'"';
	    for (const tchar *p = stats->key; *p; ++p) {
		if (*p == T('"') || *p == T('\\'))
		    s += T('\\');
		s += *p;
	    }
	    s += (tchar)'"';
	    tsprintf(buf, T(",%.3g,%lu"), (double)stats->tot / 1000000.0,
		stats->cnt);
	}
	s += buf;
	for (u = begin; u <= last && tot; u++) {
	    ulong cnt = (columns && u == begin) ? sum : stats->cnts[u];

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
	s += (tchar)'\n';
    }
    return s;
}

void Timing::erase(const TimingKey &key) {
    FastSpinWLocker lkr(lck);
    timingmap::iterator it = tmap.find(key.hash());

    if (it != tmap.end()) {
	Stats *stats = it->second;

	tmap.erase(it);
	delete stats;
    }
}

const tchar *Timing::format(timing_t t, tchar *buf) {
    double d((double)t / 1000.0);

    if (d < 10)
	tsprintf(buf, T("%.3f"), d);
    else if (d < 100)
	tsprintf(buf, T("%.2f"), d);
    else if (d < 10000)
	tsprintf(buf, T("%.0f"), d);
    else if (d < 1000000)
	tsprintf(buf, T("%.0fk"), d / 1000);
    else
	tsprintf(buf, T("%.0fm"), d / 1000000);
    return buf;
}

void Timing::record(void) {
    timing_t n = now();
    tstring caller;
    timing_t diff;
    const tchar *key;
    Tlsdata &tlsd(*tls);
    vector<tstring>::reverse_iterator rit = tlsd.callers.rbegin();

    if (rit == tlsd.callers.rend()) {
	tcerr << T("timing mismatch for stack") << endl;
	return;
    }
    caller = *rit;
    tlsd.callers.pop_back();
    diff = n - *(tlsd.starts.rbegin());
    tlsd.starts.pop_back();
    key = caller.c_str();
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

void Timing::record(const TimingKey &key) {
    timing_t n = now();
    tstring caller;
    timing_t diff;
    Tlsdata &tlsd(*tls);

    do {
	vector<tstring>::reverse_iterator it = tlsd.callers.rbegin();

	if (it == tlsd.callers.rend()) {
	    tcerr << T("timing mismatch for ") << (const tchar *)key << endl;
	    return;
	}
	caller = *it;
	tlsd.callers.pop_back();
	diff = n - *(tlsd.starts.rbegin());
	tlsd.starts.pop_back();
    } while (!caller.empty() && caller != (const tchar *)key);
    if (!caller.empty() && !tlsd.callers.empty()) {
	tstring s;

	for (vector<tstring>::const_iterator it = tlsd.callers.begin();
	    it != tlsd.callers.end(); ++it) {
	    if (!s.empty())
		s += T("->");
	    s += *it;
	}
	s += T("->");
	s += (const tchar *)key;
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

void Timing::start(const TimingKey &key) {
    Tlsdata &tlsd(*tls);

    tlsd.callers.push_back((const tchar *)key);
    tlsd.starts.push_back(now());
}

void Timing::stop(uint lvl) {
    Tlsdata &tlsd(*tls);

    while (lvl-- && !tlsd.callers.empty()) {
	tlsd.callers.pop_back();
	tlsd.starts.pop_back();
    }
}
