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

#ifndef Load_h
#define Load_h

#ifdef _WIN32
#include <conio.h>
#endif
#include <fcntl.h>
#include <float.h>
#include <math.h>
#include <signal.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <ranges>
#include <unordered_map>
#include "Log.h"
#include "Thread.h"

using attrmap = unordered_map<tstring, tstring, strhash, streq>;

/*
 * Scripted multithreaded load generator shared by httpload and smtpload. The
 * workload file holds "var attr=value", "sleep [%]msec" and protocol commands
 * that each thread runs once per loop. Subclasses parse and run commands
 */
class Load: public Thread {
public:
    Load(): id(threads++) {}

    template <class L, class F>
    static int run(int argc, tchar *argv[], const tchar *wld,
	const tchar *defhost, const tchar *flags, F opt);

protected:
    class LoadCmd {
    public:
	LoadCmd(const tchar *c, const tchar *a, bool s = false):
	    arg(a ? a : T("")), cmd(c), delay(s) {}
	virtual ~LoadCmd() = default;

	tstring arg, cmd;
	ulong count = 0, err = 0, tcount = 0, terr = 0;
	ulong maxusec = 0, tmaxusec = 0, tminusec = 0, tusec = 0, usec = 0;
	bool delay;			// sleep command

	void complete(bool sts, ulong diff) {
	    count++;
	    tcount++;
	    if (!sts) {
		err++;
		terr++;
	    }
	    usec += diff;
	    tusec += diff;
	    maxusec = max(maxusec, diff);
	    tminusec = tminusec ? min(tminusec, diff) : diff;
	    tmaxusec = max(tmaxusec, diff);
	}
    };
    struct BodyFile {
	unique_ptr<char[]> cache;
	tstring path;
	ulong size = 0;
    };

    ulong id;
    static inline vector<BodyFile> bodies;
    static inline vector<unique_ptr<LoadCmd>> cmds;
    static inline uint to = 30000;
    static inline attrmap vars;

    // per request $() values from str into buf
    bool subst(const tstring &str, tchar *buf, size_t sz) const {
	if (str.size() >= sz)
	    return false;
	tstrcpy(buf, str.c_str());
	return expand(buf, sz, lvars);
    }
    uint pick(void) {
	return allfiles ? next() : (uint)(dist(rng) % bodies.size());
    }
    static void fail(LoadCmd &cmd) {
	statlock.lock();
	cmd.err++;
	cmd.terr++;
	statlock.unlock();
    }
    static const char *load(uint idx, usec_t &iousec, unique_ptr<char[]> &buf);
    // per request values are only formatted when a command uses them
    static void need(const tstring &str) {
	needid = needid || str.contains(T("$(id)"));
	needpass = needpass || str.contains(T("$(pass)"));
	needuser = needuser || str.contains(T("$(user)"));
    }
    static bool setattr(attrmap &amap, uint line);

private:
    attrmap lvars;
    mt19937 rng{random_device {}()};
    uniform_int_distribution<ulong> dist;
    static inline bool allfiles = false, hostarg = false, needid = false,
	needpass = false, needuser = false, ruser = false;
    static inline atomic<ulong> count = 0, tcount = 0, tusec = 0, usec = 0;
    static inline Lock lock;		// before cv which uses it
    static inline Condvar cv{lock};
    static inline uint mthread = 0, startfile = 0;
    static inline atomic<uint> threads = 0;
    static inline ulong muser = 0;
    static inline atomic<uint> nextfile = 0;
    static inline atomic_bool qflag = false, rflag = false;
    static inline atomic_long remain = 0;
    static inline SpinLock statlock{SPIN_LIMIT};

    // per thread setup, request, result check and per loop cleanup
    virtual void begin(void) = 0;
    virtual bool exec(LoadCmd &cmd, usec_t &io) = 0;
    virtual bool check(LoadCmd &cmd, bool ret, ulong diff) = 0;
    virtual void end(void) = 0;

    int onStart(void) override;
    static void add(const tchar *file);
    static bool expand(tchar *str, size_t buf_size, const attrmap &amap = vars);
    static tstring format(ulong u);
    static tstring format(float f);
    template <class L>
    static bool init(const tchar *host, const tchar *defhost,
	const tchar *file, const tchar *bodyfile, ulong cachesz, int fcnt,
	long loops);
    static uint next(void) {
	return startfile + nextfile.fetch_add(1, memory_order_relaxed) %
	    ((uint)bodies.size() - startfile);
    }
    static void print(tostream &os, usec_t last);
    static unique_ptr<char[]> read(const BodyFile &body);
    static void reset(bool all);
    static void signal_handler(int sig);
    static tchar *trim(tchar *str);
};

inline bool Load::expand(tchar *str, size_t buf_size, const attrmap &amap) {
    const tchar *orig = str;
    tchar *p;

    while ((p = tstrstr(str, T("$("))) != nullptr) {
	if (p != str && p[-1] == '$') {	    // $$() -> $()
	    memmove(p - 1, p, (tstrlen(p) + 1) * sizeof (tchar));
	    str = p + 1;
	    continue;
	}

	tchar *end = tstrchr(p, ')');

	if (!end)
	    return false;
	*end++ = '\0';

	auto it = amap.find(p + 2);

	if (it == amap.end())
	    return false;

	size_t len = it->second.size(), end_len = tstrlen(end) + 1;

	if ((size_t)(p - orig) + len + end_len > buf_size)
	    return false;
	memmove(p + len, end, end_len * sizeof (tchar));
	memcpy(p, it->second.c_str(), len * sizeof (tchar));
	str = p + len;			// don't rescan the substituted value
    }
    return true;
}

inline tchar *Load::trim(tchar *str) {
    tchar *end = str + tstrlen(str);

    while (istspace(*str))
	str++;
    while (end > str && istspace(end[-1]))
	*--end = '\0';
    return str;
}

// "attr = value" from the rest of the line being tokenized
inline bool Load::setattr(attrmap &amap, uint line) {
    tchar *attr = tstrtok(nullptr, T("=")), *val;

    if (!attr) {
	tcerr << T("invalid attribute: line ") << line << endl;
	return false;
    }
    attr = trim(attr);
    if (hostarg && !tstricmp(attr, T("host")))
	return true;
    val = tstrtok(nullptr, T(""));
    if (!val) {
	tcerr << T("invalid value: line ") << line << endl;
	return false;
    }
    amap[attr] = trim(val);
    return true;
}

template <class L>
bool Load::init(const tchar *host, const tchar *defhost, const tchar *file,
    const tchar *bodyfile, ulong cachesz, int fcnt, long loops) {
    tchar buf[1024];
    tifstream is(file);
    uint line = 0;

    if (!is) {
	tcerr << T("invalid file: ") << file << endl;
	return false;
    }
    if (bodyfile) {
	namespace fs = std::filesystem;
	fs::path bpath(bodyfile);

	if (fs::is_directory(bpath)) {
	    for (const auto &entry : fs::directory_iterator(bpath))
		if (entry.path().filename().native()[0] != '.')
		    add(astringtotstring(entry.path().string()).c_str());
	} else if (fs::is_regular_file(bpath)) {
	    add(bodyfile);
	} else {
	    tcerr << T("invalid body file: ") << bodyfile << endl;
	    return false;
	}
    }
    remain = loops;
    if (allfiles && !bodies.empty()) {
	if (fcnt > 0 && (uint)fcnt < (uint)bodies.size())
	    bodies.resize((size_t)fcnt);
	else if (fcnt < 0 && (uint)(-fcnt) < (uint)bodies.size())
	    startfile = (uint)bodies.size() - (uint)(-fcnt);
	remain = remain * (long)(bodies.size() - startfile);
    }
    // cache files up front so senders never wait on disk or a lock
    if (loops != 1) {
	for (auto &b : bodies | views::drop(startfile)) {
	    if (b.size > cachesz)
		continue;
	    if (!(b.cache = read(b)))
		return false;
	    cachesz -= b.size;
	}
    }
    hostarg = host != nullptr;
    vars[T("host")] = host ? host : defhost;
    while (is.getline(buf, (streamsize)size(buf))) {
	tchar *cmd;

	line++;
	buf[tstrcspn(buf, T("\r"))] = '\0';
	if (!buf[0] || buf[0] == '#' || buf[0] == '/')
	    continue;
	if (!expand(buf, size(buf))) {
	    tcerr << T("variable syntax err on line ") << line << T(": ") <<
		buf << endl;
	    return false;
	}
	cmd = tstrtok(buf, T(" \t"));
	if (!cmd)
	    continue;
	if (!tstricmp(cmd, T("var"))) {
	    if (!setattr(vars, line))
		return false;
	} else if (!tstricmp(cmd, T("sleep"))) {
	    cmds.push_back(make_unique<LoadCmd>(cmd, tstrtok(nullptr,
		T(" \t")), true));
	} else if (!L::parse(cmd, line)) {
	    return false;
	}
    }
    if (!is.eof()) {
	tcerr << T("line too long: ") << line + 1 << endl;
	return false;
    }
    return true;
}

inline unique_ptr<char[]> Load::read(const BodyFile &body) {
    int fd = open(tchartoachar(body.path.c_str()), O_RDONLY | O_BINARY |
	O_SEQUENTIAL);
    unique_ptr<char[]> ret;

    if (fd != -1) {
	ret = make_unique_for_overwrite<char[]>((size_t)body.size + 1);
	if (::read(fd, ret.get(), body.size) == (int)body.size)
	    ret[body.size] = '\0';
	else
	    ret.reset();
	close(fd);
    }
    if (!ret)
	tcerr << T("unable to read body file: ") << body.path << endl;
    return ret;
}

// a cached body or one read into buf
inline const char *Load::load(uint idx, usec_t &iousec,
    unique_ptr<char[]> &buf) {
    const BodyFile &body = bodies[idx];

    if (body.cache) {
	iousec = 0;
	return body.cache.get();
    }
    iousec = uticks();
    buf = read(body);
    iousec = uticks() - iousec;
    return buf.get();
}

inline void Load::add(const tchar *file) {
    namespace fs = std::filesystem;
    std::error_code ec;
    auto sz = fs::file_size(fs::path(file), ec);

    if (ec)
	tcerr << T("invalid body file: ") << file << endl;
    else
	bodies.push_back({.cache = {}, .path = tstring(file),
	    .size = (ulong)sz});
}

inline int Load::onStart(void) {
    const auto setvar = [&](const tchar *var, const tchar *fmt) {
	tchar buf[1024];

	if (auto it = vars.find(var); it != vars.end())
	    fmt = it->second.c_str();
	tsprintf(buf, fmt, id);				// NOSONAR
	lvars[var] = buf;
    };

    begin();
    if (id > Processor::count())
	msleep(dist(rng) % 1000U * ((mthread / 20) + 1));
    while (!qflag && remain.fetch_sub(1, memory_order_relaxed) > 0) {
	ulong cusec = 0, diff, smsec = 0;
	usec_t start, last;

	id = ruser ? dist(rng) % muser : id % muser;
	if (needid)
	    lvars[T("id")] = std::format(T("{}"), id);
	if (needuser)
	    setvar(T("user"), T("user_%06lu"));
	if (needpass)
	    setvar(T("pass"), T("pass_%06lu"));
	start = last = uticks();
	for (const auto &cmd : cmds) {
	    usec_t io = 0, now;
	    bool ret;

	    if (qflag)
		break;
	    if (cmd->delay) {
		const tchar *p = cmd->arg.c_str();
		ulong len;

		if (*p == '%') {
		    len = atoi<ulong>(p + 1);
		    if (len)
			len = dist(rng) % len;
		} else {
		    len = atoi<ulong>(p);
		}
		smsec += len;
		msleep(len);
		last = uticks();
		continue;
	    }
	    ret = exec(*cmd, io);
	    now = uticks();
	    diff = (ulong)(now - last - io);
	    cusec += diff;
	    last = now;
	    statlock.lock();
	    cmd->complete(ret, diff);
	    statlock.unlock();
	    if (!check(*cmd, ret, diff))
		break;
	}
	end();
	diff = (ulong)(uticks() - start);
	usec += cusec;
	tusec += diff - smsec * 1000;
	++count;
	++tcount;
	dlog << Log::Info << Log::cmd(T("all")) << Log::kv(T("duration"),
	    diff / 1000) << endlog;
    }
    lock.lock();
    if (!--threads)
	cv.set();
    lock.unlock();
    return 0;
}

inline tstring Load::format(ulong u) { return std::format(T(" {:7}"), u); }

inline tstring Load::format(float f) {
    if (f < FLT_EPSILON)
	return T("       0");
    else if (f >= 100)
	return std::format(T(" {:7}"), lround(f));
    else
	return std::format(T(" {:7.2g}"), f);
}

inline void Load::print(tostream &os, usec_t last) {
    const auto per = [](ulong n, ulong div) {
	return div ? (float)n / (float)div : 0;
    };
    ulong lusec = (ulong)(uticks() - last);
    ulong tminusec = 0, maxusec = 0, tmaxusec = 0;
    ulong ops = 0, tops = 0, err = 0, terr = 0;
    bufferstream<tchar> bs;

    bs << T("CMD     ops/sec msec/op maxmsec  errors OPS/SEC MSEC/OP  ERRORS ")
	T("MINMSEC MAXMSEC") << endl;
    statlock.lock();
    for (const auto &cmd : cmds) {
	if (cmd->delay)
	    continue;
	ops += cmd->count;
	tops += cmd->tcount;
	err += cmd->err;
	terr += cmd->terr;
	if (cmd->maxusec > maxusec)
	    maxusec = cmd->maxusec;
	if (cmd->tminusec && (!tminusec || cmd->tminusec < tminusec))
	    tminusec = cmd->tminusec;
	if (cmd->tmaxusec > tmaxusec)
	    tmaxusec = cmd->tmaxusec;
	bs << std::format(T("{:<7}"), cmd->cmd) <<
	    format(per(cmd->count, lusec) * 1000000) <<
	    format(per(cmd->usec, cmd->count) / 1000) <<
	    format(cmd->maxusec / 1000) << format(cmd->err) <<
	    format(per(cmd->tcount, tusec) * 1000000) <<
	    format(per(cmd->tusec, cmd->tcount) / 1000) <<
	    format(cmd->terr) << format(cmd->tminusec / 1000) <<
	    format(cmd->tmaxusec / 1000) << endl;
    }
    statlock.unlock();
    bs << T("ALL    ") << format(per(count, lusec) * 1000000) <<
	format(per(usec, count) / 1000) <<
	format(maxusec / 1000) << format(err) <<
	format(per(tcount, tusec) * 1000000) <<
	format(per(tusec, tcount) / 1000) << format(terr) <<
	format(tminusec / 1000) << format(tmaxusec / 1000) << endl;
    bs << T("AVG/TOT") << format(per(ops, lusec) * 1000000) <<
	format(per(usec, ops) / 1000) << format(maxusec / 1000) <<
	format(err) << format(per(tops, tusec) * 1000000) <<
	format(per(tusec, tops) / 1000) << format(terr) <<
	format(tminusec / 1000) << format(tmaxusec / 1000) << endl << endl;
    os.write(bs.str(), bs.pcount());
    os.flush();
}

inline void Load::reset(bool all) {
    statlock.lock();
    for (const auto &cmd : cmds) {
	cmd->count = 0;
	cmd->err = 0;
	cmd->usec = cmd->maxusec = 0;
	if (all) {
	    cmd->tcount = 0;
	    cmd->terr = 0;
	    cmd->tusec = cmd->tminusec = cmd->tmaxusec = 0;
	}
    }
    statlock.unlock();
    usec = 0;
    count = 0;
    if (all) {
	tusec = 0;
	tcount = 0;
    }
}

inline void Load::signal_handler(int sig) {
    if (sig == SIGHUP) {
	rflag = true;
    } else if (qflag) {
	_exit(-1);
    } else {
	qflag = true;
    }
    signal(SIGHUP, signal_handler);
}

// opt handles the subclass flags listed in the usage text
template <class L, class F>
int Load::run(int argc, tchar *argv[], const tchar *wld,
    const tchar *defhost, const tchar *flags, F opt) {
    const tchar *bodyfile = nullptr, *file = nullptr, *host = nullptr;
    ulong cachesz = 64, stattime = 3000;
    int filecnt = 0, i;
    tofstream fs;
    usec_t last;
    long loops = 1;
    uint nthreads = 1;
    tstring s;
    Thread *thread;
    bool wflag = false;

    dlog.level(Log::Note);
    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-a"))) {
	    allfiles = true;
	    if (i + 1 < argc && atoi<int>(argv[i + 1]) != 0)
		filecnt = atoi<int>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-b")) && i + 1 < argc) {
	    bodyfile = argv[++i];
	} else if (!tstricmp(argv[i], T("-c")) && i + 1 < argc) {
	    cachesz = atoi<ulong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-h")) && i + 1 < argc) {
	    host = argv[++i];
	} else if (!tstricmp(argv[i], T("-l")) && i + 1 < argc) {
	    loops = atoi<long>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-m")) && i + 1 < argc) {
	    muser = atoi<ulong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-q"))) {
	    dlog.level(Log::Level(dlog.level() - 1));
	} else if (!tstricmp(argv[i], T("-r"))) {
	    ruser = true;
	} else if (!tstricmp(argv[i], T("-s")) && i + 1 < argc) {
	    stattime = atoi<ulong>(argv[++i]) * 1000;
	} else if (!tstricmp(argv[i], T("-t")) && i + 1 < argc) {
	    nthreads = (uint)atoi<ulong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-w")) && i + 1 < argc) {
	    to = (uint)atoi<ulong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-v"))) {
	    dlog.level(Log::Level(dlog.level() + 1));
	} else if (opt(argv[i])) {
	    continue;
	} else if (!file && *argv[i] != '-') {
	    file = argv[i];
	} else {
	    break;
	}
    }
    if (argc == 1 || i < argc || !nthreads) {
	const tchar *program = tstrrchr(argv[0], '/');

	if (!program)
	    program = tstrrchr(argv[0], '\\');
	tcerr << T("usage: ") << (program ? program + 1 : argv[0]) <<
	    T(" [-a [numfiles]] [-b bodyfile|bodydir] [-c cachemb] ") <<
	    flags << T("\n\t[-h host[:port]] [-l loops] [-m maxuser] ")
	    T("[-q|-v]* [-r] [-s stattime]\n")
	    T("\t[-t threads] [-w timeout] cmdfile") << endl;
	return 1;
    }
    setvbuf(stdout, nullptr, _IOFBF, 4096);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    mthread = nthreads;
    if (!muser)
	muser = nthreads;
    if (!file)
	file = wld;
    if (!init<L>(host, defhost, file, bodyfile, cachesz * 1024 * 1024,
	filecnt, loops))
	return 1;
    dlog << Log::Info << T("test ") << file << T(" (") << nthreads <<
	T(" thread") << (nthreads == 1 ? T("") : T("s")) << T(", ") <<
	loops << T(" loop") << (loops == 1 ? T("") : T("s")) << ')' << endlog;
    for (uint u = 0; u < nthreads; u++) {
	thread = new L;
	thread->start(32 * 1024);
    }
    do {
	last = uticks();
	lock.lock();
	cv.wait(stattime);
	lock.unlock();
#ifdef _WIN32
	while (kbhit()) {
	    switch (getch()) {
	    case 'q': qflag = true;
		break;
	    case 'r': rflag = true;
		break;
	    case 'w': wflag = true;
		break;
	    case '?': tcout << T("(q)uit (r)eset (w)rite") << endl;
		break;
	    default: break;
	    }
	}
#endif
	if (qflag) {
	    break;
	} else if (rflag) {
	    rflag = false;
	    reset(true);
	    tcout << T("*** RESET STATISTICS ***") << endl << endl;
	} else {
	    print(tcout, last);
	    if (wflag) {
		wflag = false;
		tcout << T("Comment: ");
		getline(tcin, s);
		if (!fs.is_open())
		    fs.open(T("load.dat"), ios::out | ios::app);
		fs << T("**** ") << s << T(" ****") << endl;
		print(fs, last);
		fs << endl << endl;
	    }
	    reset(false);
	}
    } while (!qflag && threads);
    dlog.level(Log::None);
    if (fs.is_open())
	fs.close();
    while ((thread = ThreadGroup::MainThreadGroup.wait()) != nullptr)
	delete thread;
    return ranges::any_of(cmds, [](const auto &c) { return c->terr != 0; }) ?
	1 : 0;
}

#endif // Load_h
