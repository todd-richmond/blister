/*
 * Copyright 2001-2019 Todd Richmond
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

#ifndef Log_h
#define Log_h

#include "Socket.h"
#include "Streams.h"
#include "Thread.h"

class Config;

/*
 * The Log class logs program information at escalating levels patterned after
 * UNIX syslog. It has additional facilities to copy high priority log lines to
 * a separate alert file, mail recipient or syslog daemon. Also, there are
 * performance enhancements including buffered writes (managed by background
 * thread) and code macros to reduce function calls for data that will be
 * ignored
 *
 * Log levels include the 8 levels from syslog as well as "trace" that allows
 * better segregation of verbose, low level msgs from normal debug output. A
 * thread-local prefix string can also be set so that logs made during a
 * progressively deeper stack will all start with the same string
 *
 * Each line in the log starts with a configurable string which defaults to
 * a date/time string with millisecond resolution. The following data can be
 * set to one of 4 styles
 *   Simple(default): standard log string prefixed with the log time and level
 *   Syslog: syslog file format with level and prefix strings followed by ':'
 *   KeyVal: all log components are written as attr=val pairs
 *   NoLevel: same as "Simple", but the log level is omitted
 *   NoTime: same as "Simple", but the log time is omitted
 *
 * Log files can be configured for age, count and size limits. The class will
 * automatically rollover files based on extension number or timestamp. File
 * locking is managed both inter and intra process so that a single file can
 * be shared across multiple processes or child forks
 *
 * A global "dlog" object allows for the simplest functionality but other
 * objects can be instantiated as well. A kv() member function eases logging
 * attr=val pairs with proper quoting
 *
 * dlog << Log::Warn << T("value=") << value << endlog;
 * dlogw(T("value="), value);
 * dlogw(Log::kv(T("value"), value));
 * DLOGW(T("value=") << value);
 */

class BLISTER Log: nocopy {
public:
    enum Level {
	None, Emerg, Alert, Crit, Err, Warn, Note, Info, Debug, Trace
    };
    enum Type { Simple, Syslog, KeyVal, NoLevel, NoTime };

    class Escalator {
    public:
	Escalator(Level l1, Level l2, ulong per, ulong min, ulong to): count(0),
	    mincount(min), period(per), timeout(to), level1(l1), level2(l2),
	    start(0) {}

    private:
	friend class Log;

	ulong count, mincount, period, timeout;
	SpinLock lck;
	Level level1, level2;
	msec_t start;
    };

    template<class C>
    class KV {
    public:
	KV(const tchar *k, const C &v): key(k), val(v) {}
	KV(const tstring &k, const C &v): key(k.c_str()), val(v) {}

	tostream &print(tostream &os) const {
	    os << key << '=';
	    return value(os);
	}
	tostream &printstr(tostream &os) const {
	    os << key << '=';
	    return Log::quote(os, val);
	}

    private:
	const tchar *key;
	const C &val;

	tostream &value(tostream &os) const {
	    bufferstream<tchar> buf;

	    buf << val << '\0';
	    return Log::quote(os, buf.str());
	}
    };

    explicit Log(Level level = Info);
    ~Log();

    bool alertfile(void) const { return afd.enable; }
    void alertfile(bool b) { afd.enable = b; }
    void alertfile(Level L, const tchar *file = NULL, uint cnt = 0,
	ulong sz = 10UL * 1024 * 1024, ulong tm = 0);
    const tchar *alertname(void) const { return afd.filename(); }
    const tchar *alertpath(void) const { return afd.pathname(); }
    bool buffer(void) const { return bufenable; }
    void buffer(bool enable);
    void buffer(uint sz = 32U * 1024, ulong msec = 1000) {
	bufsz = sz; buftm = msec; buffer(true);
    }
    uint bufsize(void) const { return bufsz; }
    ulong buftime(void) const { return buftm; }
    bool file(void) const { return ffd.enable; }
    void file(bool b) { ffd.enable = b; }
    void file(Level l, const tchar *file = NULL, uint cnt = 0,
	ulong sz = 10UL * 1024 * 1024, ulong tm = 0);
    const tchar *filename(void) const { return ffd.filename(); }
    const tchar *filepath(void) const { return ffd.pathname(); }
    const tchar *format(void) const { return fmt.c_str(); }
    void format(const tchar *s);
    bool gmttime(void) const { return gmt; }
    void gmttime(bool b) { gmt = b; }
    Level level(void) const { return lvl; }
    void level(Level l) { ffd.lvl = lvl = l; }
    void level(const tchar *l) { level(str2enum(l)); }
    void mail(bool b) { mailenable = b; }
    void mail(Level l, const tchar *to, const tchar *from = T("<>"),
	const tchar *host = T("localhost"));
    const tchar *prefix(void) const { return tls->prefix.c_str(); }
    void prefix(const tchar *p) { tls->prefix = p ? p : T(""); }
    const tchar *source(void) const { return src.c_str(); }
    void source(const tchar *s) { src = s; }
    bool syslog(void) const { return syslogenable; }
    void syslog(bool b) { syslogenable = b; }
    void syslog(Level l, const tchar *host = NULL, uint fac = 1);
    uint syslogfacility(void) const { return syslogfac; }
    void syslogfacility(uint fac) { syslogfac = fac; }
    Type type(void) const { return _type; }
    void type(Type t) { _type = t; }

    bool close(void);
    Log &endlog(void) {
	Tlsdata &tlsd(*tls);

	if (tlsd.clvl != None)
	    endlog(tlsd, tlsd.clvl);
	return *this;
    }
    void flush(void) { Locker lkr(lck); _flush(); }
    void logv(int l, ...);
    void roll(void) { Locker lkr(lck); ffd.roll(); }
    void set(const Config &cfg, const tchar *sect = T("log"));
    bool setids(uid_t uid, gid_t gid) const;
    void setmp(bool b = false);
    void start(void);
    void stop(void);
    static tostream &quote(tostream &os, const tchar *s);

    Log &operator <<(Escalator &escalator);
    template<class C> Log &operator <<(const C &c) {
	Tlsdata &tlsd(*tls);

	if (tlsd.clvl != None) {
	    if (tlsd.space) {
		tlsd.space = false;
		tlsd.strm << ' ';
	    }
	    tlsd.strm << c;
	}
	return *this;
    }

    Log &operator <<(Log::Level l) {
	Tlsdata *tlsd;

	if (l <= lvl && !(tlsd = &tls.get())->suppress)
	    tlsd->clvl = l;
	return *this;
    }

    template<class C>
    Log &operator <<(const KV<C> &_kv) {
	Tlsdata &tlsd(*tls);

	if (tlsd.clvl != None) {
	    if (tlsd.strm.size())
		tlsd.strm << ' ';
	    _kv.print(tlsd.strm);
	    tlsd.space = true;
	}
	return *this;
    }

#define _func_(n, l) \
    template<class C> void n(const C &c) { log(l, c); } \
    template<class C, class D> void n(const C &c, const D &d) { log(l, c, d); } \
    template<class C, class D, class E> void n(const C &c, const D &d, const E \
	&e) { log(l, c, d, e); }\
    template<class C, class D, class E, class F> void n(const C &c, const D &d, \
	const E &e, const F &f) { log(l, c, d, e, f); } \
    template<class C, class D, class E, class F, class G> void n(const C &c, \
	const D &d, const E &e, const F &f, const G &g) { log(l, c, d, e, f, \
	g); } \
    template<class C, class D, class E, class F, class G, class H> void n( \
	const C &c, const D &d, const E &e, const F &f, const G &g, const H \
	&h) { log(l, c, d, e, f, g, h); }

    _func_(emerg, Emerg)
    _func_(alert, Alert)
    _func_(crit, Crit)
    _func_(err, Err)
    _func_(warn, Warn)
    _func_(note, Note)
    _func_(info, Info)
    _func_(debug, Debug)
    _func_(trace, Trace)

#undef _func_
#define _log_(s) \
    Tlsdata *tlsd; \
    if (l <= lvl && !(tlsd = &tls.get())->suppress) { \
	tlsd->strm << s; \
	endlog(*tlsd, l); \
    }

    template<class C> void log(Level l, const C &c) { _log_(c); }
    template<class C, class D> void log(Level l, const C &c, const D &d) {
	_log_(c << ' ' << d);
    }
    template<class C, class D, class E> void log(Level l, const C &c,
	const D &d, const E &e) {
	_log_(c << ' ' << d << ' ' << e);
    }
    template<class C, class D, class E, class F> void log(Level l, const C &c,
	const D &d, const E &e, const F &f) {
	_log_(c << ' ' << d << ' ' << e << ' ' << f);
    }
    template<class C, class D, class E, class F, class G> void log(Level l,
	const C &c, const D &d, const E &e, const F &f, const G &g) {
	_log_(c << ' ' << d << ' ' << e << ' ' << f << ' ' << g);
    }
    template<class C, class D, class E, class F, class G, class H>
	void log(Level l, const C &c, const D &d, const E &e, const F &f,
	const G &g, const H &h) {
	_log_(c << ' ' << d << ' ' << e << ' ' << f << ' ' << g << ' ' << h);
    }

#undef _log_

    template<class C> static const KV<C> kv(const tchar *key, const C &val) {
	return KV<C>(key, val);
    }
    template<class C> static const KV<C> kv(const tstring &key, const C &val) {
	return KV<C>(key, val);
    }
    template<class C> static const KV<C> cmd(const C &c) {
	return KV<C>(T("cmd"), c);
    }
    template<class C> static const KV<C> error(const C &c) {
	return KV<C>(T("err"), c);
    }
    template<class C> static const KV<C> mod(const C &c) {
	return KV<C>(T("mod"), c);
    }
    static const tchar *section(void) { return T("log"); }
    static Level str2enum(const tchar *lvl);

private:
    class BLISTER FlushThread: public Thread {
    public:
	explicit FlushThread(Log &lg): l(lg), qflag(false) {}

	void quit(void) { qflag = true; }

    private:
	Log &l;
	volatile bool qflag;

	int onStart(void);
    };

    class BLISTER LogFile: nocopy {
    public:
	uint cnt;
	bool enable;
	tstring file;
	bool gmt, mp;
	ulong len, sec, sz;
	bool locked;
	Level lvl;

	LogFile(bool denable, Level dlvl, const tchar *dfile, bool m): cnt(0),
	    gmt(false), mp(m), len(0), sec(0), sz(0), locked(false), lvl(dlvl),
	    fd(-1) {
	    set(dlvl, dfile, 3, 5UL * 1024 * 1024, 0);
	    enable = denable;
	}
	~LogFile() { close(); }

	bool active(void) const { return fd != -1; }
	const tchar *filename(void) const { return file.c_str(); }
	ulong length(void) const { return len; }
	void length(ulong l) { len = l; }
	const tchar *pathname(void) const { return path.c_str(); }
	void unlock(void) const;

	bool close(void);
	void lock(void);
	void print(const tchar *buf, uint chars);
	void print(const tstring &s) { print(s.c_str(), (uint)s.size()); }
	bool reopen(void);
	void roll(void);
	void set(const Config &cfg, const tchar *sect, const tchar *sub,
	    bool enable, const tchar *level, const tchar *file);
	void set(Level lvl, const tchar *file, uint cnt, ulong sz, ulong sec);

    private:
	int fd;
	tstring path;
    };

    struct BLISTER Tlsdata {
	tstring prefix;
	tstring strbuf;
	tbufferstream strm;
	Level clvl;
	bool space;
	bool suppress;

	Tlsdata(): clvl(None), space(false), suppress(false) {}
    };

    Lock lck;
    Condvar cv;
    ThreadLocalClass<Tlsdata> tls;
    LogFile afd, ffd;
    bool bufenable, mailenable, syslogenable;
    uint bufsz;
    ulong buftm;
    tbufferstream bufstrm;
    tstring fmt;
    FlushThread ft;
    bool gmt, mp;
    tstring last_format;
    time_t last_sec;
    Level lvl, maillvl, sysloglvl;
    tstring hostname, mailfrom, mailhost, mailto;
    tstring src;
    Sockaddr syslogaddr;
    uint syslogfac;
    tstring sysloghost;
    Socket syslogsock;
    Type _type;
    tstring::size_type upos;
    static const tchar * const LevelStr[];
    static const tchar * const LevelStr2[];

    void endlog(Tlsdata &tlsd, Level lvl);
    void _flush(void);
};

template<> inline tostream &Log::KV<bool>::value(tostream &os) const {
    return os << (val ? 't' : 'f');
}
template<> inline tostream &Log::KV<const tchar *>::value(tostream &os) const {
    return Log::quote(os, val);
}
template<> inline tostream &Log::KV<tchar *>::value(tostream &os) const {
    return Log::quote(os, val);
}
template<> inline tostream &Log::KV<tstring>::value(tostream &os) const {
    return Log::quote(os, val.c_str());
}
template<> inline tostream &Log::KV<char>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<double>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<float>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<int>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<long>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<llong>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<short>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<uchar>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<uint>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<ulong>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<ullong>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<ushort>::value(tostream &os) const {
    return os << val;
}
template<> inline tostream &Log::KV<wchar>::value(tostream &os) const {
    return os << val;
}

template<class C> inline tostream &operator <<(tostream &os, const Log::KV<C>
    &kv) {
    return kv.print(os);
}

template<size_t N> inline tostream &operator <<(tostream &os, const
    Log::KV<tchar[N]> &kv) {
    return kv.printstr(os);
}

inline Log &operator <<(Log &l, Log &(* const func)(Log &)) { return func(l); }
inline Log &endlog(Log &l) { return l.endlog(); }

extern BLISTER Log &dlog;

#define DLOGL(l, args)  { if (l <= dlog.level()) dlog << l << args << endlog; }
#define DLOGM(args)	DLOGL(Log::Emerg, args)
#define DLOGA(args)	DLOGL(Log::Alert, args)
#define DLOGC(args)	DLOGL(Log::Crit, args)
#define DLOGE(args)	DLOGL(Log::Err, args)
#define DLOGW(args)	DLOGL(Log::Warn, args)
#define DLOGN(args)	DLOGL(Log::Note, args)
#define DLOGI(args)	DLOGL(Log::Info, args)
#define DLOGD(args)	DLOGL(Log::Debug, args)
#define DLOGT(args)	DLOGL(Log::Trace, args)

#define dlogl(l, ...)   { if (l <= dlog.level()) dlog.log(l, __VA_ARGS__); }
#define dlogm(...)	dlogl(Log::Emerg, __VA_ARGS__)
#define dloga(...)	dlogl(Log::Alert, __VA_ARGS__)
#define dlogc(...)	dlogl(Log::Crit, __VA_ARGS__)
#define dloge(...)	dlogl(Log::Err, __VA_ARGS__)
#define dlogw(...)	dlogl(Log::Warn, __VA_ARGS__)
#define dlogn(...)	dlogl(Log::Note, __VA_ARGS__)
#define dlogi(...)	dlogl(Log::Info, __VA_ARGS__)
#define dlogd(...)	dlogl(Log::Debug, __VA_ARGS__)
#define dlogt(...)	dlogl(Log::Trace, __VA_ARGS__)

#define dlogvl(l, ...)  { \
    if (l <= dlog.level()) \
	dlog.logv(l, __VA_ARGS__, (char *)NULL); \
}
#define dlogvm(...)	dlogvl(Log::Emerg, __VA_ARGS__)
#define dlogva(...)	dlogvl(Log::Alert, __VA_ARGS__)
#define dlogvc(...)	dlogvl(Log::Crit, __VA_ARGS__)
#define dlogve(...)	dlogvl(Log::Err, __VA_ARGS__)
#define dlogvw(...)	dlogvl(Log::Warn, __VA_ARGS__)
#define dlogvn(...)	dlogvl(Log::Note, __VA_ARGS__)
#define dlogvi(...)	dlogvl(Log::Info, __VA_ARGS__)
#define dlogvd(...)	dlogvl(Log::Debug, __VA_ARGS__)
#define dlogvt(...)	dlogvl(Log::Trace, __VA_ARGS__)

#endif // _Log_h
