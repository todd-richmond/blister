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
 *   Simple(default): standard log string prefixed with the log level
 *   Syslog: syslog file format with level and prefix strings followed by ':'
 *   KeyVal: all log components are written as attr=val pairs
 *   NoLevel: same as "Simple", but the log level is omitted
 *
 * Log files can be configured for age, count and size limits. The class will
 * automatically rollover files based on extension number or timestamp. File
 * locking is managed both inter and intra process so that a single file can
 * be shared across multiple processes or child forks
 *
 * A global "dlog" object allows for the simplest functionality but other
 * objects can be instantiated as well. A "kv" inner class eases logging
 * multiple attr=val pairs
 *
 * dlog << Log::Warn << T("errno ") << errno << endlog;
 * dlogw(T("errno"), errno);
 * dlogw(Log::kv(T("errno"), errno));
 * DLOGW(T("errno ") << errno);
 */

class Log: nocopy {
public:
    enum Level {
	None, Emerg, Alert, Crit, Err, Warn, Note, Info, Debug, Trace
    };
    enum Type { Simple, Syslog, KeyVal, NoLevel };

    class kv {
    public:
	template<class C> kv(const tchar *k, const C &v) {
	    bufferstream<tchar> buf;

	    buf << v << '\0';
	    set(k, buf.str());
	}
	kv(const tchar *k, const tchar *v) { set(k, v); }

	const tstring &str(void) const { return s; }

    private:
	tstring s;

	void set(const tchar *k, const tchar *v);
    };

    Log(Level level = Info);
    ~Log();

    bool alert(void) const { return afd.enable; }
    void alert(bool b) { afd.enable = b; }
    void alert(Level L, const tchar *file = NULL, uint cnt = 0,
	ulong sz = 10 * 1024 * 1024, ulong tm = 0);
    const tchar *alertname(void) const { return afd.filename(); }
    const tchar *alertpath(void) const { return afd.pathname(); }
    bool buffer(void) const { return bufenable; }
    void buffer(bool b);
    void buffer(uint sz = 32 * 1024, ulong msec = 1000) {
	bufsz = sz; buftm = msec; buffer(true);
    }
    uint bufsize(void) const { return bufsz; }
    ulong buftime(void) const { return buftm; }
    bool file(void) const { return ffd.enable; }
    void file(bool b) { ffd.enable = b; }
    void file(Level l, const tchar *file = NULL, uint cnt = 0,
	ulong sz = 10 * 1024 * 1024, ulong tm = 0);
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
    void logv(Level l, ...);
    const tchar *prefix(void) const { return tls->prefix.c_str(); }
    void prefix(const tchar *p) { tls->prefix = p ? p : T(""); }
    void roll(void) { Locker lkr(lck); ffd.roll(); }
    void set(const Config &cfg, const tchar *sect = T("log"));
    bool setids(uid_t uid, gid_t gid) const;
    void setmp(bool b = false);
    void start(void);
    void stop(void);

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

    Log &operator <<(const Log::Level &l) {
	Tlsdata *tlsd;

	if (l <= lvl && !(tlsd = &tls.get())->suppress)
	    tlsd->clvl = l;
	return *this;
    }

    Log &operator <<(const kv &kv) {
        Tlsdata &tlsd(*tls);

	if (tlsd.clvl != None) {
	    if (tlsd.strm.size())
		tlsd.strm << ' ';
	    tlsd.strm << kv.str();
	    tlsd.space = true;
	}
	return *this;
    }

    template<class C> void log(Level l, const C &c) {
	Tlsdata *tlsd;

	if (l <= lvl && !(tlsd = &tls.get())->suppress) {
	    tlsd->strm << c;
	    endlog(*tlsd, l);
	}
    }

    template<class C, class D> void log(Level l, const C &c, const D &d) {
	Tlsdata *tlsd;

	if (l <= lvl && !(tlsd = &tls.get())->suppress) {
	    tlsd->strm << c << ' ' << d;
	    endlog(*tlsd, l);
	}
    }

    template<class C, class D, class E> void log(Level l, const C &c,
	const D &d, const E &e) {
	Tlsdata *tlsd;

	if (l <= lvl && !(tlsd = &tls.get())->suppress) {
	    tlsd->strm << c << ' ' << d << ' ' << e;
	    endlog(*tlsd, l);
	}
    }

    template<class C, class D, class E, class F> void log(Level l, const C &c,
	const D &d, const E &e, const F &f) {
	Tlsdata *tlsd;

	if (l <= lvl && !(tlsd = &tls.get())->suppress) {
	    tlsd->strm << c << ' ' << d << ' ' << e << ' ' << f;
	    endlog(*tlsd, l);
	}
    }

    static const kv cmd(const tchar *c) { return kv(T("cmd"), c); }
    static const kv cmd(const tstring &c) { return cmd(c.c_str()); }
    static const kv mod(const tchar *m) { return kv(T("mod"), m); }
    static const kv mod(const tstring &m) { return mod(m.c_str()); }
    static const tchar *section(void) { return T("log"); }
    static Level str2enum(const tchar *lvl);

private:
    class FlushThread: public Thread {
    public:
	FlushThread(Log &lg): l(lg), qflag(false) {}

	void quit(void) { qflag = true; }

    private:
	Log &l;
	volatile bool qflag;

	int onStart(void);
    };

    class LogFile {
    public:
	uint cnt;
	bool enable;
	tstring file;
	bool gmt, mp;
	ulong len, sz, tm;
	bool locked;
	Level lvl;

    	LogFile(bool denable, Level dlvl, const tchar *dfile, bool m):
	    gmt(false), mp(m), len(0), locked(false), fd(-1) {
	    set(dlvl, dfile, 3, 5 * 1024 * 1024, 0);
	    enable = denable;
	}
	~LogFile() { close(); }

	bool active(void) const { return fd != -1; }
	const tchar *filename(void) const { return file.c_str(); }
	ulong length(void) const { return len; }
	void length(ulong l) { len = l; }
	const tchar *pathname(void) const { return path.c_str(); }

	bool close(void);
	void flush(void);
	void lock(void);
	void print(const tchar *buf, size_t len);
	void print(const tstring &s) { print(s.c_str(), s.size()); }
	bool reopen(void);
	void roll(void);
	void set(const Config &cfg, const tchar *sect, const tchar *sub,
	    bool enable, const tchar *level, const tchar *file);
	void set(Level l, const tchar *f, uint cnt, ulong sz, ulong tm);
	void unlock(void) {
	    if (locked) {
		unlockfd(fd);
		locked = false;
	    }
	}

    private:
	int fd;
	tstring path;

	static ulong lockfd(int fd);
	static void unlockfd(int fd);
    };

    struct Tlsdata {
    	Level clvl;
    	tstring prefix;
	bool space;
	tstring strbuf;
	bool suppress;
	bufferstream<tchar> strm;

	Tlsdata(): clvl(None), space(false), suppress(false) {}
    };

    Lock lck;
    Condvar cv;
    ThreadLocalClass<Tlsdata> tls;
    LogFile afd, ffd;
    bool bufenable, mailenable, syslogenable;
    uint bufsz;
    ulong buftm;
    bufferstream<tchar> bufstrm;
    tstring fmt;
    FlushThread ft;
    bool gmt, mp;
    tstring last_format;
    time_t last_sec;
    Level lvl, maillvl, sysloglvl;
    tstring mailfrom, mailhost, mailto;
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

inline tostream &operator <<(tostream &os, const Log::kv &kv) {
    return os << kv.str();
}

inline Log &operator <<(Log &l, Log &(*manip)(Log &)) { return manip(l); }
inline Log &endlog(Log &l) { return l.endlog(); }

extern Log &dlog;

#define LOGL(l, lvl, args) { if (lvl <= l.level()) l << lvl << args << endlog; }
#define DLOGL(lvl, args) LOGL(dlog, lvl, args)
#define DLOGM(args)	DLOGL(Log::Emerg, args);
#define DLOGA(args)	DLOGL(Log::Alert, args);
#define DLOGC(args)	DLOGL(Log::Crit, args);
#define DLOGE(args)	DLOGL(Log::Err, args);
#define DLOGW(args)	DLOGL(Log::Warn, args);
#define DLOGN(args)	DLOGL(Log::Note, args);
#define DLOGI(args)	DLOGL(Log::Info, args);
#define DLOGD(args)	DLOGL(Log::Debug, args);
#define DLOGT(args)	DLOGL(Log::Trace, args);

#define logl(l, lvl, ...) { if (lvl <= l.level()) l.log(lvl, __VA_ARGS__); }
#define dlogl(lvl, ...) logl(dlog, lvl, __VA_ARGS__)
#define dlogm(...)	dlogl(Log::Emerg, __VA_ARGS__);
#define dloga(...)	dlogl(Log::Alert, __VA_ARGS__);
#define dlogc(...)	dlogl(Log::Crit, __VA_ARGS__);
#define dloge(...)	dlogl(Log::Err, __VA_ARGS__);
#define dlogw(...)	dlogl(Log::Warn, __VA_ARGS__);
#define dlogn(...)	dlogl(Log::Note, __VA_ARGS__);
#define dlogi(...)	dlogl(Log::Info, __VA_ARGS__);
#define dlogd(...)	dlogl(Log::Debug, __VA_ARGS__);
#define dlogt(...)	dlogl(Log::Trace, __VA_ARGS__);

#define loglv(l, lvl, ...) { if (lvl <= l.level()) l.logv(lvl, __VA_ARGS__, NULL); }
#define dloglv(lvl, ...) loglv(dlog, lvl, __VA_ARGS__)
#define dlogmv(...)	dloglv(Log::Emerg, __VA_ARGS__);
#define dlogav(...)	dloglv(Log::Alert, __VA_ARGS__);
#define dlogcv(...)	dloglv(Log::Crit, __VA_ARGS__);
#define dlogev(...)	dloglv(Log::Err, __VA_ARGS__);
#define dlogwv(...)	dloglv(Log::Warn, __VA_ARGS__);
#define dlognv(...)	dloglv(Log::Note, __VA_ARGS__);
#define dlogiv(...)	dloglv(Log::Info, __VA_ARGS__);
#define dlogdv(...)	dloglv(Log::Debug, __VA_ARGS__);
#define dlogtv(...)	dlog(vLog::Trace, __VA_ARGS__);

#endif // _Log_h
