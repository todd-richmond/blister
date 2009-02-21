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

    timing_t add(const char *key, timing_t diff);
    void clear(void);
    const string data(bool compact = false) const;
    void erase(const char *key);
    timing_t now(void) const { return uticks(); }
    timing_t record(const char *key = NULL);
    timing_t record(const char *key, timing_t start) {
	timing_t n = now();

	return add(key, n > start ? n - start : 0);
    }
    timing_t start(void) const { return now(); }
    timing_t start(const char *key);
    void stop(uint lvl = (uint)-1);

private:
    struct Stats {
	Stats(): cnt(0), tot(0) { ZERO(cnts); }

	ulong cnt;
	ulong cnts[TIMINGSLOTS];
	timing_t tot;
    };

    struct Tlsdata {
	vector<string> callers;
	vector<timing_t> starts;
    };

    typedef hash_map<string, Stats *, strhash<char> > timingmap;

    mutable SpinLock lck;
    TLS<Tlsdata> tls;
    timingmap tmap;

    static const char *format(timing_t tot, char *buf);
};

extern Timing &dtiming;

#endif // _Timing_h
