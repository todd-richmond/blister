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

#include <deque>
#include "Socket.h"
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
 * a date/time string with microsecond resolution. The following data can be
 * set to one of 5 styles
 *   Simple(default): standard log string prefixed with the log time and level
 *   Syslog: syslog file format with level and prefix strings followed by ':'
 *   KeyVal: all log components are written as attr=val pairs
 *   NoLevel: same as "Simple", but the log level is omitted
 *   NoTime: same as "Simple", but the log time is omitted
 *
 * Logging a string that ends with '=' will quote the following argument if
 * required. A kv() method eases logging quoted attr=val pairs
 * Streaming Log::None discards the whole buffered message
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
    struct Tlsdata;

public:
    enum Level {
	None, Emerg, Alert, Crit, Err, Warn, Note, Info, Debug, Trace
    };
    enum Type { Simple, Syslog, KeyVal, NoLevel, NoTime };

    class BLISTER Escalator: nocopy {
    public:
	// per and to are in seconds
	Escalator(Level l1, Level l2, ulong per, ulong min, ulong to):
	    mincount(min), period(per), timeout(to), level1(l1), level2(l2) {}

    private:
	friend class Log;

	// logging through an Escalator is logically const to the caller
	mutable SpinLock lck;
	mutable ulong count = 0, start = 0;
	mutable ulong mincount;
	ulong period, timeout;
	Level level1, level2;
    };

    template<typename T>
    struct KV {
	constexpr KV(tstring_view k, const T &v): key(k), val(v) {}

	tstring_view key;
	T val;
    };

    explicit Log(Level level = Info);
    ~Log();

    template<typename T>
    __forceinline Log &operator <<(T &&val) {
	(void)log(std::forward<T>(val)); return *this;
    }
    __forceinline Log &operator <<(void (*f)(Log &)) { f(*this); return *this; }
    friend Log &operator <<(Log &l, Log &(*f)(Log &)) { return f(l); }

    bool alertfile(void) const {
	return afd.enable.load(memory_order_relaxed);
    }
    void alertfile(bool b) { setlvl(afd.enable, b); }
    void alertfile(Level l, const tchar *file = nullptr, uint cnt = 0,
	ulong sz = 10UL * 1024 * 1024, ulong tm = 0);
    tstring alertname(void) const { return lockedcopy(afd.file); }
    tstring alertpath(void) const { return lockedcopy(afd.path); }
    bool buffer(void) const { return bufenable.load(memory_order_relaxed); }
    void buffer(bool b);
    void buffer(uint sz, ulong msec = 1000) {
	bufsz.store(sz, memory_order_relaxed);
	buftm.store(msec, memory_order_relaxed);
	buffer(true);
    }
    uint bufsize(void) const { return bufsz.load(memory_order_relaxed); }
    ulong buftime(void) const { return buftm.load(memory_order_relaxed); }
    bool file(void) const { return ffd.enable.load(memory_order_relaxed); }
    void file(bool b) { setlvl(ffd.enable, b); }
    void file(Level l, const tchar *file = nullptr, uint cnt = 0,
	ulong sz = 10UL * 1024 * 1024, ulong tm = 0);
    tstring filename(void) const { return lockedcopy(ffd.file); }
    tstring filepath(void) const { return lockedcopy(ffd.path); }
    tstring format(void) const { return lockedcopy(fmt); }
    void format(const tchar *s);
    bool gmttime(void) const { return gmt.load(memory_order_relaxed); }
    void gmttime(bool b);
    Level level(void) const { return lvl.load(memory_order_relaxed); }
    void level(Level l) { setlvl(ffd.lvl, l); }
    void level(const tchar *l) { level(str2enum(l)); }
    void mail(bool b) { setlvl(mailenable, b); }
    void mail(Level l, const tchar *to, const tchar *from = T("<>"), const tchar
	*host = T("localhost"));
    const tchar *prefix(void) const { return tls->prefix.c_str(); }
    void prefix(const tchar *p) { tls->prefix = p ? p : T(""); }
    void separate(bool b = true) { tls->sep = b ? ' ' : '\0'; }
    tstring source(void) const { return lockedcopy(src); }
    void source(const tchar *s) {
	FastLocker lkr(lck);

	src = s ? s : T("");
    }
    bool syslog(void) const {
	return syslogenable.load(memory_order_relaxed);
    }
    void syslog(bool b);
    void syslog(Level l, const tchar *host = nullptr, uint fac = 1);
    uint syslogfacility(void) const {
	return syslogfac.load(memory_order_relaxed);
    }
    void syslogfacility(uint fac) {
	syslogfac.store(fac, memory_order_relaxed);
    }
    Type type(void) const { return _type.load(memory_order_relaxed); }
    void type(Type t) { _type.store(t, memory_order_relaxed); }

    bool close(void);
    // main thread does not call TLS destruction
    void destruct(void) const { tls.erase(); }
    __forceinline void endlog(void) {
	Tlsdata &tlsd(*tls);

	if (tlsd.clvl != None)
	    endlog(tlsd);
    }
    void flush(void);
    template<typename T, typename... U>
	requires (!same_as<remove_cvref_t<T>, Tlsdata>)
    __forceinline Log &log(T &&first, U &&...rest) {
	return logtls(wraparg(std::forward<T>(first)),
	    wraparg(std::forward<U>(rest))...);
    }
    void logv(int l, ...);
    bool reopen(void);
    void roll(void);
    void set(const Config &cfg, const tchar *sect = T("log"));
    bool setids(uid_t uid, gid_t gid);
    void setmp(bool b = false);
    void start(void);
    void stop(void);

    template<typename... T> requires (sizeof...(T) > 0)
    __forceinline void log(Log::Level l, T &&...args) {
	if (UNLIKELY(l > None && l <= level()))
	    _log(l, wraparg(std::forward<T>(args))...);
    }
#define LOG_LEVEL_FN(name, l) \
    template<typename... T> \
    __forceinline void name(T &&...args) { \
	log(l, std::forward<T>(args)...); \
    } \
    __forceinline Log &name(void) { \
	log(tls.get(), l); \
	return *this; \
    }
    LOG_LEVEL_FN(emerg, Emerg)
    LOG_LEVEL_FN(alert, Alert)
    LOG_LEVEL_FN(crit,  Crit)
    LOG_LEVEL_FN(err,   Err)
    LOG_LEVEL_FN(warn,  Warn)
    LOG_LEVEL_FN(note,  Note)
    LOG_LEVEL_FN(info,  Info)
    LOG_LEVEL_FN(debug, Debug)
    LOG_LEVEL_FN(trace, Trace)
#undef LOG_LEVEL_FN

    template<typename K, typename T> requires const_array<K>
    __forceinline static constexpr auto kv(const K &key, T &&val) {
	return kv(litview(key), std::forward<T>(val));
    }
    template<typename T>
    __forceinline static constexpr auto kv(tstring_view key, T &&val) {
	using W = decltype(wraparg(std::forward<T>(val)));

	return KV<conditional_t<is_reference_v<W>, const remove_cvref_t<W> &,
	    W>>(key, wraparg(std::forward<T>(val)));
    }
#define LOG_KV_FN(name, key) \
    template<typename U> \
    __forceinline static constexpr auto name(U &&val) { \
	return kv(tstring_view(T(key), sizeof (key) - 1), \
	    std::forward<U>(val)); \
    }
    LOG_KV_FN(cmd,      "cmd")
    LOG_KV_FN(duration, "msec")
    LOG_KV_FN(error,    "err")
    LOG_KV_FN(mod,      "mod")
    LOG_KV_FN(status,   "sts")
#undef LOG_KV_FN
    static tbufferstream &quote(tbufferstream &os, tstring_view s);
    static const tchar *section(void) { return T("log"); }
    static Level str2enum(const tchar *lvl);

private:
    struct RawStr {
	tstring_view sv;
    };

    template<typename A>
    static constexpr bool const_tchar_array = const_array<A> &&
	is_same_v<remove_cvref_t<remove_extent_t<remove_reference_t<A>>>,
	tchar>;

    template<size_t N>
    __forceinline static constexpr tstring_view litview(
	const tchar (&val)[N]) {
	// literals fill their array so need no length scan
	const size_t len = N <= 1 ? 0 : val[N - 2] ? N - 1 : tstrlen(val);

	return tstring_view(val, len);
    }
    // collapse arg types so _log instances are shared across call sites
    template<typename T>
    __forceinline static constexpr decltype(auto) wraparg(T &&val) {
	using V = remove_cvref_t<T>;

	if constexpr (const_tchar_array<T>)
	    return RawStr{litview(val)};
	else if constexpr (cstr_ptr<T>)
	    return static_cast<const tchar *>(val);
	else if constexpr (is_scalar_v<V>)
	    return V(val);
	else
	    return std::forward<T>(val);
    }

    class DLL_LOCAL FlushThread: public Thread {
    public:
	explicit FlushThread(Log &lg): l(lg) {}

	void quit(void) { qflag = true; }
	void rearm(void) { qflag = false; }

    private:
	Log &l;
	atomic_bool qflag = false;

	int onStart(void) override;
    };

    // holding lck blocks new flushes, so only in-progress unlocked I/O remains
    class DLL_LOCAL PauseFlush: nocopy {
    public:
	explicit PauseFlush(Log &l): lkr(l.lck) {
	    while (l.flushing)
		l.cv.wait(INFINITE);
	}

    private:
	FastLocker lkr;
    };

    class DLL_LOCAL LogFile: nocopy {
    public:
	LogFile(bool denable, Level dlvl, const tchar *dfile, bool m): mp(m),
	    lvl(dlvl) {
	    set(dlvl, dfile, 3, 5UL * 1024 * 1024, 0);
	    enable = denable;
	}
	~LogFile() { close(); }

	bool close(void);
	void lock(void);
	void print(tstring_view s);
	bool reopen(void);
	void roll(void);
	void set(const Config &cfg, const tchar *sect, const tchar *sub,
	    bool enable, const tchar *level, const tchar *file);
	void set(Level lvl, const tchar *file, uint cnt, ulong sz, ulong sec);
	void unlock(void) const;

    private:
	friend class Log;

	uint cnt = 0;
	atomic<bool> enable{false};
	int fd = -1;
	tstring file;
	bool gmt = false, mp;
	ullong len = 0;
	ulong sec = 0, sz = 0;
	Level lvl;
	tstring path;

	bool lockend(void);
	int lockrange(short type) const;
    };

    struct BLISTER Tlsdata {
	tstring prefix;
	tstring strbuf, tailbuf;
	tbufferstream strm;
	Level clvl = None;
	tchar sep = '\0';
	bool suppress = false;
    };

    mutable Lock lck;
    Condvar cv { lck };
    ThreadLocalClass<Tlsdata> tls;
    LogFile afd{false, Err, T("stderr"), true}, ffd{true, Info, T("stdout"),
	true};
    atomic<bool> bufenable{false}, syslogenable{false};
    bool flushing = false, mailenable = false;
    atomic<uint> bufsz{32U * 1024};
    atomic<ulong> buftm{1000};
    // queue lets threads keep logging during a slow file rollover
    unique_ptr<tbufferstream> bufcur = make_unique<tbufferstream>();
    vector<unique_ptr<tbufferstream>> buffree;
    deque<unique_ptr<tbufferstream>> bufpending;
    tstring fmt;
    ThreadGroup ftg;
    FlushThread ft { *this };
    atomic<bool> gmt{false}, mp{true};
    tstring last_format;
    time_t last_sec = -1;
    Level maillvl = None, sysloglvl = None;
    tstring hostname, mailfrom, mailhost, mailto;
    tstring src;
    Sockaddr syslogaddr;
    atomic<uint> syslogfac{1};
    tstring sysloghost;
    Socket syslogsock{SOCK_DGRAM};
    atomic<Type> _type{Simple};
    tstring::size_type upos = 0;
    alignas(CACHELINE_SZ) atomic<Level> lvl;
    static constexpr tstring_view LevelStr[] = {
	T("none"), T("emrg"), T("alrt"), T("crit"), T("err "), T("warn"),
	T("note"), T("info"), T("debg"), T("trce")
    };
    static constexpr tstring_view LevelStr2[] = {
	T("nothing"), T("emergency"), T("alert"), T("critical"), T("error"),
	T("warning"), T("notice"), T("information"), T("debug"), T("trace")
    };

    void endlog(Tlsdata &tlsd);
    void drainbuffers(bool unlockedio);
    tstring lockedcopy(const tstring &s) const {
	FastLocker lkr(lck);

	return s;
    }
    void rotatebuf(void);
    template<typename M, typename V>
    void setlvl(M &member, V val) {
	FastLocker lkr(lck);

	member = val;
	updatelvl();
    }
    void updatelvl(void) {
	lvl.store((max)({afd.enable ? afd.lvl : None,
	    ffd.enable ? ffd.lvl : None, mailenable ? maillvl : None,
	    syslogenable ? sysloglvl : None}), memory_order_relaxed);
    }
    void _format(const tchar *s);
    void _mail(Level l, const tchar *to, const tchar *from, const tchar *host);
    void _syslog(Level l, const tchar *host, uint fac);
    template<typename... T>
    void _log(Log::Level l, T &&...args) {
	Tlsdata &tlsd(*tls);

	if (LIKELY(!tlsd.suppress)) {
	    tlsd.clvl = l;
	    logall(tlsd, std::forward<T>(args)...);
	    endlog(tlsd);
	}
    }
    template<typename... T>
    __forceinline Log &logtls(T &&...args) {
	logall(tls.get(), std::forward<T>(args)...);
	return *this;
    }
    template<typename T>
    Log &log(Tlsdata &tlsd, const T &val) {
	if (LIKELY(tlsd.clvl != None)) {
	    if constexpr (is_same_v<T, bool>) {
		return log(tlsd, (tchar)(val ? 't' : 'f'));
	    } else if constexpr (is_convertible_v<const T &, tstring_view>) {
		return logstr(tlsd, tstring_view(val));
	    } else {
		if (tlsd.sep == '=') {
		    tlsd.sep = ' ';
		    if constexpr (!is_fundamental_v<T>) {
			if constexpr (is_enum_v<T>) {
			    tlsd.strm.write((underlying_type_t<T>)val);
			} else if constexpr (requires { val.c_str(); }) {
			    if (const tchar *p = val.c_str())
				quote(tlsd.strm, p);
			} else {
			    tbufferstream buf;

			    buf << val;
			    quote(tlsd.strm, buf.view());
			}
			return *this;
		    }
		} else if (tlsd.sep && tlsd.strm.size()) {
		    tlsd.strm.put(tlsd.sep);
		}
		tlsd.strm.write(val);
	    }
	}
	return *this;
    }
    Log &log(Tlsdata &tlsd, const tchar *val) {
	if (LIKELY(val))
	    return logstr(tlsd, val);
	if (tlsd.clvl != None && tlsd.sep == '=')
	    tlsd.sep = ' ';
	return *this;
    }
    __forceinline Log &log(Tlsdata &tlsd, const RawStr &val) {
	return logstr<true>(tlsd, val.sv);
    }
    Log &log(Tlsdata &tlsd, const Escalator &e);
    __forceinline Log &log(Tlsdata &tlsd, Log::Level l) {
	if (l == None) {
	    tlsd.clvl = None;
	    tlsd.sep = '\0';
	    tlsd.strm.reset();
	} else if (l <= level() && LIKELY(!tlsd.suppress)) {
	    tlsd.clvl = l;
	}
	return *this;
    }
    template<typename T>
    Log &log(Tlsdata &tlsd, const KV<T> &val) {
	if (LIKELY(tlsd.clvl != None)) {
	    if (tlsd.strm.size())
		tlsd.strm.put(T(' '));
	    tlsd.strm.write(val.key.data(), (streamsize)val.key.size());
	    tlsd.strm.put(T('='));
	    tlsd.sep = '=';
	    log(tlsd, val.val);
	}
	return *this;
    }
    template<typename... T>
    __forceinline void logall(Tlsdata &tlsd, T &&...args) {
	(log(tlsd, std::forward<T>(args)), ...);
    }
    // raw skips escaping for code controlled const arrays
    template<bool raw = false>
    Log &logstr(Tlsdata &tlsd, tstring_view val) {
	if (LIKELY(tlsd.clvl != None)) {
	    if (tlsd.sep == '=') {
		quote(tlsd.strm, val);
		tlsd.sep = ' ';
	    } else {
		write_str<raw>(tlsd, val.data(), (streamsize)val.size());
	    }
	}
	return *this;
    }
    template<bool raw = false>
    __forceinline static void write_str(Tlsdata &tlsd, const tchar *data,
	streamsize sz) {
	if (LIKELY(sz > 0)) {
	    if (tlsd.sep && tlsd.strm.size())
		tlsd.strm.put(tlsd.sep);
	    if constexpr (raw)
		tlsd.strm.write(data, sz);
	    else
		strm_write_esc(tlsd.strm, data, sz);
	    if (data[sz - 1] == '=')
		tlsd.sep = '=';
	}
    }
    static void strm_write_esc(tbufferstream &strm, const tchar *data, streamsize sz);
};

inline void endlog(Log &l) { l.endlog(); }

extern BLISTER Log &dlog;

// performance macros to bypass computing ignored data
#define LOGL(o, l, ...)	\
    do { \
	if (UNLIKELY((l) > Log::None && (l) <= (o).level())) \
	    (o).log((l), __VA_ARGS__); \
    } while (false)

#define logm(o, ...)	LOGL(o, Log::Emerg, __VA_ARGS__)
#define loga(o, ...)	LOGL(o, Log::Alert, __VA_ARGS__)
#define logc(o, ...)	LOGL(o, Log::Crit, __VA_ARGS__)
#define loge(o, ...)	LOGL(o, Log::Err, __VA_ARGS__)
#define logw(o, ...)	LOGL(o, Log::Warn, __VA_ARGS__)
#define logn(o, ...)	LOGL(o, Log::Note, __VA_ARGS__)
#define logi(o, ...)	LOGL(o, Log::Info, __VA_ARGS__)
#define logd(o, ...)	LOGL(o, Log::Debug, __VA_ARGS__)
#define logt(o, ...)	LOGL(o, Log::Trace, __VA_ARGS__)

#define dlogl(l, ...)	LOGL(dlog, l, __VA_ARGS__)
#define dlogm(...)	logm(dlog, __VA_ARGS__)
#define dloga(...)	loga(dlog, __VA_ARGS__)
#define dlogc(...)	logc(dlog, __VA_ARGS__)
#define dloge(...)	loge(dlog, __VA_ARGS__)
#define dlogw(...)	logw(dlog, __VA_ARGS__)
#define dlogn(...)	logn(dlog, __VA_ARGS__)
#define dlogi(...)	logi(dlog, __VA_ARGS__)
#define dlogd(...)	logd(dlog, __VA_ARGS__)
#define dlogt(...)	logt(dlog, __VA_ARGS__)

#endif // Log_h
