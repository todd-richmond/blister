/*
 * Copyright 2001-2026 Todd Richmond
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

#include <type_traits>
#include "Socket.h"
#include "Streams.h"
#include "Thread.h"

class Config;

/*
 * The Log class logs program information at escalating levels patterned after
 * UNIX syslog. It has additional facilities to copy high priority log lines to
 * a separate alert file, mail recipient or syslog daemon. There are also
 * performance enhancements including buffered writes (managed by background
 * thread) and variadic macros to reduce function calls for data that will be
 * ignored dlog?(...)
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
 * Logging a string that ends with '=' will quote the following argument if
 * required. A kv() method eases logging quoted attr=val pairs
 *
 * An Escalator will suppress similar logs either after or during x period of
 * time for y minutes
 *
 * Log files can be configured for age, count and size limits. The class will
 * automatically rollover files based on extension number or timestamp. File
 * locking is managed both inter and intra process so that a single file can
 * be shared across multiple processes or child forks
 *
 * A global "dlog" object allows for the simplest functionality but other
 * objects can be instantiated as well.
 *
 * dlogw(T("value="), value);
 * dlogw(Log::kv(T("value"), value));
 * dlog.warn(T("value="), value);
 * dlog.warn().log(T("value=")).log(value).endlog();
 * dlog << Log::Warn << T("value=") << value << endlog;
 */

class BLISTER Log: nocopy {
public:
    enum Level {
	None, Emerg, Alert, Crit, Err, Warn, Note, Info, Debug, Trace
    };
    enum Type { Simple, Syslog, KeyVal, NoLevel, NoTime };

    class BLISTER Escalator {
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

    template<typename T>
    struct KV {
	__forceinline KV(const tchar *k, const T &v): key(k), val(v) {}
	KV(const tstring &k, const T &v): key(k.c_str()), val(v) {}

	const tchar *key;
	const T &val;
    };

    explicit Log(Level level = Info);
    ~Log();

    template<typename T>
    // cppcheck-suppress returnTempReference
    __forceinline Log &operator <<(const T &val) { return log(val); }
    __forceinline Log &operator <<(void(Log &)) { endlog(); return *this; }
    // cppcheck-suppress [constParameterReference, returnTempReference]
    __forceinline Log &operator <<(Escalator &e) { return log(e); }

    bool alertfile(void) const { return afd.enable; }
    void alertfile(bool b) { afd.enable = b; }
    void alertfile(Level L, const tchar *file = NULL, uint cnt = 0,
	ulong sz = 10UL * 1024 * 1024, ulong tm = 0);
    const tchar *alertname(void) const { return afd.filename(); }
    const tchar *alertpath(void) const { return afd.pathname(); }
    bool buffer(void) const { return bufenable; }
    void buffer(bool b);
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
    void mail(Level l, const tchar *to, const tchar *from = T("<>"), const tchar
	*host = T("localhost"));
    const tchar *prefix(void) const { return tls->prefix.c_str(); }
    void prefix(const tchar *p) { tls->prefix = p ? p : T(""); }
    void separate(bool b = true) { tls.get().sep = b ? ' ' : '\0'; }
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
    // main thread does not call TLS destruction
    void destruct(void) { tls.erase(); }
    __forceinline void endlog(void) {
	Tlsdata &tlsd(*tls);

	if (tlsd.clvl != None)
	    endlog(tlsd);
    }
    void flush(void) { Locker lkr(lck); _flush(); }
    // cppcheck-suppress-begin returnTempReference
    template <typename T>
    __forceinline Log &log(const T &val) { return log(tls.get(), val); }
    __forceinline Log &log(const tchar *val) { return log(tls.get(), val); }
#pragma warning(disable: 26461)
    __forceinline Log &log(tchar *val) {
	return log(tls.get(), (const tchar *)val);
    }
    // cppcheck-suppress constParameterReference
    __forceinline Log &log(Escalator &e) { return log(tls.get(), e); }
    __forceinline Log &log(Log::Level l) { return log(tls.get(), l); }
    template<typename T>
    __forceinline Log &log(const KV<T> &val) { return log(tls.get(), val); }
    template <typename T, typename... U>
    __forceinline Log &log(const T &first, const U&...  rest) {
	log(tls.get(), first, rest...);

	return *this;
    }
    // cppcheck-suppress-end returnTempReference
    void logv(int l, ...);
    bool reopen(void) { Locker lkr(lck); return ffd.reopen(); }
    void roll(void) { Locker lkr(lck); ffd.roll(); }
    void set(const Config &cfg, const tchar *sect = T("log"));
    bool setids(uid_t uid, gid_t gid) const;
    void setmp(bool b = false);
    void start(void);
    void stop(void);

    template <typename... T>
    void log(Log::Level l, const T&... args) {
	if (l <= lvl) {
	    Tlsdata &tlsd(*tls);

	    if (LIKELY(!tlsd.suppress)) {
		tlsd.clvl = l;
		log(tlsd, args...);
		endlog(tlsd);
	    }
	}
    }
    template <typename... T>
    __forceinline void emerg(const T&... args) { log(Emerg, args...); }
    __forceinline Log &emerg(void) { return log(Emerg); }
    template <typename... T>
    __forceinline void alert(const T&... args) { log(Alert, args...); }
    __forceinline Log &alert(void) { return log(Alert); }
    template <typename... T>
    __forceinline void crit(const T&... args) { log(Crit, args...); }
    __forceinline Log &crit(void) { return log(Crit); }
    template <typename... T>
    __forceinline void err(const T&... args) { log(Err, args...); }
    __forceinline Log &err(void) { return log(Err); }
    template <typename... T>
    __forceinline void warn(const T&... args) { log(Warn, args...); }
    __forceinline Log &warn(void) { return log(Warn); }
    template <typename... T>
    __forceinline void note(const T&... args) { log(Note, args...); }
    __forceinline Log &note(void) { return log(Note); }
    template <typename... T>
    __forceinline void info(const T&... args) { log(Info, args...); }
    __forceinline Log &info(void) { return log(Info); }
    template <typename... T>
    __forceinline void debug(const T&... args) { log(Debug, args...); }
    __forceinline Log &debug(void) { return log(Debug); }
    template <typename... T>
    __forceinline void trace(const T&... args) { log(Trace, args...); }
    __forceinline Log &trace(void) { return log(Trace); }

    template<typename T>
    static __forceinline const KV<T> kv(const tchar *key, const T &val) {
	return KV<T>(key, val);
    }
    template<typename T>
    static __forceinline const KV<T> kv(const tstring &key, const T &val) {
	return KV<T>(key, val);
    }
    template<typename T>
    static __forceinline const KV<T> cmd(const T &val) {
	return KV<T>(T("cmd"), val);
    }
    template<typename T>
    static __forceinline const KV<T> error(const T &val) {
	return KV<T>(T("err"), val);
    }
    template<typename T>
    static __forceinline const KV<T> mod(const T &val) {
	return KV<T>(T("mod"), val);
    }
    static tostream &quote(tostream &os, const tchar *s);
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

	bool close(void);
	void lock(void);
	void print(const tchar *buf, uint chars);
	void print(const tstring &s) { print(s.c_str(), (uint)s.size()); }
	bool reopen(void);
	void roll(void);
	void set(const Config &cfg, const tchar *sect, const tchar *sub,
	    bool enable, const tchar *level, const tchar *file);
	void set(Level lvl, const tchar *file, uint cnt, ulong sz, ulong sec);
	void unlock(void) const;

    private:
	int fd;
	tstring path;
    };

    struct BLISTER Tlsdata {
	tstring prefix;
	tstring strbuf;
	tbufferstream strm;
	Level clvl;
	char sep;
	bool suppress;

	Tlsdata(): clvl(None), sep('\0'), suppress(false) {}
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

    void endlog(Tlsdata &tlsd);
    void _flush(void);
    template <typename T>
    Log &log(Tlsdata &tlsd, const T &val) {
	if (tlsd.clvl != None) {
	    if (tlsd.sep == '=') {
		tlsd.sep = ' ';
		if (!is_fundamental_v<T>) {
		    tbufferstream buf;

		    buf << val << '\0';
		    quote(tlsd.strm, buf.str());
		    return *this;
		}
	    } else if (tlsd.sep && tlsd.strm.size()) {
		tlsd.strm << tlsd.sep;
	    }
	    tlsd.strm << val;
	}
	return *this;
    }
    Log &log(Tlsdata &tlsd, const tchar *val) {
	if (tlsd.clvl != None) {
	    if (tlsd.sep == '=') {
		if (val)
		    quote(tlsd.strm, val);
		tlsd.sep = ' ';
	    } else if (val) {
		if (tlsd.sep && tlsd.strm.size())
		    tlsd.strm << tlsd.sep;
		if (*val) {
		    tlsd.strm << val;
		    if (tlsd.strm.str()[tlsd.strm.size() - 1] == '=')
			tlsd.sep = '=';
		} else {
		    tlsd.sep = '\0';
		}
	    }
	}
	return *this;
    }
#pragma warning(disable: 26461)
    __forceinline Log &log(Tlsdata &tlsd, tchar *val) {
	return log(tlsd, (const tchar *)val);
    }
    // cppcheck-suppress constParameterReference
    Log &log(Tlsdata &tlsd, Escalator &e);
    __forceinline Log &log(Tlsdata &tlsd, Log::Level l) {
	if (l <= lvl && LIKELY(!tlsd.suppress))
	    tlsd.clvl = l;
	return *this;
    }
    template<typename T>
    Log &log(Tlsdata &tlsd, const KV<T> &val) {
	if (tlsd.clvl != None) {
	    if (tlsd.strm.size())
		tlsd.strm << ' ';
	    tlsd.strm << val.key << '=';
	    tlsd.sep = '=';
	    log(tlsd, val.val);
	}
	return *this;
    }
    __forceinline void log(Tlsdata &) {}
    template <typename T, typename... U>
    __forceinline void log(Tlsdata &tlsd, const T &first, const U&...
	rest) {
	log(tlsd, first);
	log(tlsd, rest...);	// recursive call using pack expansion
    }
};

// optimized template specializations
template<> inline Log &Log::log(Tlsdata &tlsd, const bool &val) {
    return log(tlsd, val ? 't' : 'f');
}
template<> inline Log &Log::log(Tlsdata &tlsd, const tstring &val) {
    return log(tlsd, val.c_str());
}

inline Log &operator <<(Log &l, Log &(* const func)(Log &)) { return func(l); }
inline void endlog(Log &l) { l.endlog(); }

extern BLISTER Log &dlog;

// performance macros to bypass computing ignored data
#define LOGL(o, l, ...)	{ if (l <= o.level()) o.log(l, __VA_ARGS__); }

#define logm(o, ...)	LOGL(o, Log::Emerg, __VA_ARGS__)
#define loga(o, ...)	LOGL(o, Log::Alert, __VA_ARGS__)
#define logc(o, ...)	LOGL(o, Log::Crit, __VA_ARGS__)
#define loge(o, ...)	LOGL(o, Log::Err, __VA_ARGS__)
#define logw(o, ...)	LOGL(o, Log::Warn, __VA_ARGS__)
#define logn(o, ...)	LOGL(o, Log::Note, __VA_ARGS__)
#define logi(o, ...)	LOGL(o, Log::Info, __VA_ARGS__)
#define logd(o, ...)	LOGL(o, Log::Debug, __VA_ARGS__)
#define logt(o, ...)	LOGL(o, Log::Trace, __VA_ARGS__)

#define dlogl(l, ...)	LOGL(dlog, l,  __VA_ARGS__)
#define dlogm(...)	logm(dlog, __VA_ARGS__)
#define dloga(...)	loga(dlog, __VA_ARGS__)
#define dlogc(...)	logc(dlog, __VA_ARGS__)
#define dloge(...)	loge(dlog, __VA_ARGS__)
#define dlogw(...)	logw(dlog, __VA_ARGS__)
#define dlogn(...)	logn(dlog, __VA_ARGS__)
#define dlogi(...)	logi(dlog, __VA_ARGS__)
#define dlogd(...)	logd(dlog, __VA_ARGS__)
#define dlogt(...)	logt(dlog, __VA_ARGS__)

#endif // _Log_h
