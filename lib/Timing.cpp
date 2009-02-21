#include "stdapi.h"
#include <algorithm>
#include "Timing.h"

// UNIX loaders may try to construct static objects > 1 time
static Timing &_dtiming(void) {
    static Timing timing;

    return timing;
}

Timing &dtiming(_dtiming());

timing_t Timing::add(const char *key, timing_t diff) {
    uint slot;
    SpinLocker lkr(lck);
    Stats *stats = tmap[key];

    if (!stats)
	stats = tmap[key] = new Stats;
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
    return diff;
}

void Timing::clear() {
    timingmap::iterator it;
    SpinLocker lkr(lck);

    while ((it = tmap.begin()) != tmap.end()) {
	delete (*it).second;
	tmap.erase(it);
    }
}

const string Timing::data(bool compact) const {
    timingmap::const_iterator it;
    vector<string> keys;
    string s;
    SpinLocker lkr(lck);

    if (!compact)
	s = "key                            sum    cnt    avg 1ms 1cs .1s  1s  5s 10s 30s  1m\n";
    for (it = tmap.begin(); it != tmap.end(); it++)
	keys.push_back((*it).first);
    sort(keys.begin(), keys.end());
    for (vector<string>::const_iterator kit = keys.begin(); kit != keys.end(); kit++) {
	char abuf[16], buf[128], sbuf[16];
	const Stats *stats;

	it = tmap.find((*kit).c_str());
	stats = (*it).second;
	if (compact) {
	    if (!s.empty())
		s += ',';
	    sprintf(buf, "%s,%s,%lu", (*it).first.c_str(),
		format(stats->tot, sbuf), stats->cnt);
	} else {
	    sprintf(buf, "%-27s%7s%7lu%7s", (*it).first.c_str(),
		format(stats->tot, sbuf), stats->cnt,
		format(stats->tot / stats->cnt, abuf));
	}
	s += buf;
	for (uint u = 0; u < TIMINGSLOTS; u++) {
	    ulong cnt = stats->cnts[u];

	    if (compact) {
		sprintf(buf, ",%lu", cnt);
		s += buf;
	    } else if (cnt == 0) {
		s += "    ";
	    } else if (cnt < 100) {
		sprintf(buf, "%4lu", cnt);
		s += buf;
	    } else if (cnt == stats->cnt) {
		s += "   *";
	    } else {
		sprintf(buf, "%3u%%", (uint)(cnt * 100 / stats->cnt));
		s += buf;
	    }
	}
	if (!compact)
	    s += "\n";
    }
    return s;
}

void Timing::erase(const char *key) {
    SpinLocker lkr(lck);
    timingmap::iterator it = tmap.find(key);

    if (it != tmap.end()) {
	delete (*it).second;
	tmap.erase(it);
    }
}

timing_t Timing::record(const char *key) {
    string caller;
    timing_t diff;
    Tlsdata *tlsd = tls.get();

    do {
	vector<string>::reverse_iterator it = tlsd->callers.rbegin();

	if (it == tlsd->callers.rend()) {
	    cerr << "timing mismatch for " << (key ? key : "stack") << endl;
	    return 0;
	}
	caller = *it;
	tlsd->callers.pop_back();
	if (!key)
	    key = caller.c_str();
	diff = uticks() - *(tlsd->starts.rbegin());
	tlsd->starts.pop_back();
    } while (!caller.empty() && caller != key);
    if (!caller.empty() && !tlsd->callers.empty()) {
	string s;

	for (vector<string>::const_iterator it = tlsd->callers.begin();
	    it != tlsd->callers.end(); it++) {
	    if (!s.empty())
		s += "->";
	    s += *it;
	}
	s += "->";
	s += key;
	add(s.c_str(), diff);
    }
    return add(key, diff);
}

timing_t Timing::start(const char *key) {
    Tlsdata *tlsd = tls.get();
    timing_t t = now();

    tlsd->callers.push_back(key ? key : "");
    tlsd->starts.push_back(t);
    return t;
}

void Timing::stop(uint lvl) {
    Tlsdata *tlsd = tls.get();

    while (lvl-- && !tlsd->callers.empty()) {
	tlsd->callers.pop_back();
	tlsd->starts.pop_back();
    }
}

const char *Timing::format(timing_t t, char *buf) {
    float f(t / 1000000.0f);

    if (f < 9.9995)
	sprintf(buf, "%.3f", f);
    else if (f < 99.995)
        sprintf(buf, "%.2f", f);
    else
        sprintf(buf, "%.0f", f + .5);
    return buf;
}

