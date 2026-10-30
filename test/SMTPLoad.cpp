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

#include "stdapi.h"
#ifdef _WIN32
#include <conio.h>
#endif
#include <fcntl.h>
#include <float.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <ranges>
#include <unordered_map>
#include "Log.h"
#include "SMTPClient.h"

using attrmap = unordered_map<tstring, tstring, strhash, streq>;

static constexpr const tchar *default_host = T("localhost:25");
static atomic_bool qflag = false, rflag = false;
static bool dflag = false, pflag = false;

class SMTPLoad: public Thread {
public:
    SMTPLoad(): id(threads++) {}

    [[nodiscard]] static bool init(const tchar *host, uint maxthread, ulong maxuser,
	bool randuser, uint timeout, long loops, const tchar *file,
	const tchar *bodyfile, ulong cachesz, bool all, int fcnt);
    static void print(tostream &os, usec_t last);
    static ulong working(void) { return threads; }
    static void reset(bool all = false);
    static void uninit(void);
    static void pause(ulong msec) { lock.lock(); cv.wait(msec); lock.unlock(); }

private:
    enum class Op: uchar {
	Auth, Bcc, Body, Cc, Cmd, Connect, Data, Ehlo, From, Header, Helo,
	Lhlo, Quit, Rcpt, Rset, Sleep, Subject, Vrfy, Xclient
    };

    class LoadCmd {
    public:
	LoadCmd(const tchar *comment, const tchar *command, const tchar
	    *argument, const tchar *status = nullptr): arg(argument ? argument :
	    T("")), cmd(command), cmt(comment),
	    sts((ushort)(status ? ttoi(status) : 200)),
	    vars(arg.contains(T("$("))) {
	    for (auto &c : cmd)
		c = (tchar)totlower(c);

	    const auto *it = ranges::find(ops, tstring_view(cmd),
		&pair<tstring_view, Op>::first);

	    op = it == ranges::end(ops) ? Op::Cmd : it->second;
	}

	Sockaddr addr;
	tstring arg, cmd, cmt;
	ulong count = 0, err = 0, tcount = 0, terr = 0;
	ulong maxusec = 0, minusec = 0, tmaxusec = 0, tminusec = 0, tusec = 0,
	    usec = 0;
	Op op;
	static constexpr pair<tstring_view, Op> ops[] = {
	    { T("auth"), Op::Auth }, { T("bcc"), Op::Bcc },
	    { T("body"), Op::Body }, { T("cc"), Op::Cc },
	    { T("connect"), Op::Connect }, { T("data"), Op::Data },
	    { T("ehlo"), Op::Ehlo }, { T("from"), Op::From },
	    { T("hdr"), Op::Header }, { T("header"), Op::Header },
	    { T("helo"), Op::Helo }, { T("lhlo"), Op::Lhlo },
	    { T("quit"), Op::Quit }, { T("rcpt"), Op::Rcpt },
	    { T("rset"), Op::Rset }, { T("sleep"), Op::Sleep },
	    { T("subj"), Op::Subject }, { T("subject"), Op::Subject },
	    { T("to"), Op::Rcpt }, { T("vrfy"), Op::Vrfy },
	    { T("xclient"), Op::Xclient }
	};
	ushort sts;
	bool vars;			// arg has $() for per message values

	void complete(bool status, ulong diff) {
	    count++;
	    tcount++;
	    if (!status) {
		err++;
		terr++;
	    }
	    usec += diff;
	    tusec += diff;
	    minusec = minusec ? min(minusec, diff) : diff;
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

    static inline bool allfiles = false, needid = false, needpass = false,
	needuser = false, ruser = false;
    static inline vector<BodyFile> bodies;
    static inline vector<unique_ptr<LoadCmd>> cmds;
    static inline atomic<ulong> count = 0, tcount = 0, tusec = 0, usec = 0;
    static inline Lock lock;		// before cv which uses it
    static inline Condvar cv{lock};
    ulong id;
    static inline uint mthread = 0, startfile = 0, threads = 0, to = 0;
    static inline ulong muser = 0;
    static inline atomic<uint> nextfile = 0;
    static inline atomic_long remain = 0;
    static inline SpinLock statlock{SPIN_LIMIT};
    static inline attrmap vars;

    int onStart(void) override;
    static void add(const tchar *file);
    static bool expand(tchar *str, size_t buf_size, const attrmap &amap = vars);
    static tstring format(ulong u);
    static tstring format(float f);
    static const char *load(uint idx, usec_t &iousec, unique_ptr<char[]> &buf);
    static uint next(void);
    static unique_ptr<char[]> read(const BodyFile &body);
};

bool SMTPLoad::expand(tchar *str, size_t buf_size, const attrmap &amap) {
    const tchar *orig = str;
    tchar *p;
    tstring::size_type len;

    while ((p = tstrstr(str, T("$("))) != nullptr) {
	tchar *end = tstrchr(p, ')');

	if (p != str && p[-1] == '$') {	    // $$() -> $()
	    size_t remaining_len = tstrlen(p) + 1;
	    size_t pos = (size_t)(p - orig);
	    if (pos == 0 || pos + remaining_len > buf_size + 1)
		return false;
	    copy(p, p + remaining_len, p - 1);
	} else if (!end) {
	    return false;
	} else {
	    *end++ = '\0';
	    auto it = amap.find(p + 2);
	    if (it == amap.end())
		return false;
	    len = it->second.size();
	    size_t end_len = tstrlen(end) + 1;
	    size_t current_pos = (size_t)(p - orig);
	    if (current_pos + len + end_len > buf_size)
		return false;
	    memmove(p + len, end, end_len);
	    memcpy(p, it->second.c_str(), len);
	}
	str = p + 1;
    }
    return true;
}

bool SMTPLoad::init(const tchar *host, uint maxthread, ulong maxuser,
    bool randuser, uint timeout, long loops, const tchar *file,
    const tchar *bodyfile, ulong cachesz, bool all, int fcnt) {
    Sockaddr addr;
    tchar buf[1024];
    const tchar *cmt, *cmd, *arg = nullptr, *status = nullptr;
    tchar *p;
    tifstream is(file);
    int len;
    uint line = 0;
    Locker lkr(lock);

    mthread = maxthread;
    muser = maxuser;
    remain = loops;
    ruser = randuser;
    to = timeout;
    allfiles = all;
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
    vars[T("host")] = host ? host : default_host;
    if (!addr.set(host ? host : default_host)) {
	tcerr << T("invalid host: ") << vars[T("host")] << endl;
	return false;
    }
    while (is.getline(buf, (streamsize)size(buf))) {
	line++;
	if (!buf[0] || buf[0] == '#' || buf[0] == '/')
	    continue;
	if (!expand(buf, size(buf))) {
	    tcerr << T("variable syntax err on line ") << line << T(": ") <<
		buf << endl;
	    return false;
	}
	len = (int)tstrlen(buf);
	cmt = tstrtok(buf, T(" \t"));
	if (!cmt)
	    continue;
	if (*cmt == '*') {
	    cmt++;
	    if ((cmd = tstrtok(nullptr, T(" \t"))) == nullptr) {
		tcerr << T("invalid syntax: line ") << line << endl;
		return false;
	    }
	} else {
	    cmd = cmt;
	}
	if (istdigit(*cmd)) {
	    status = cmd;
	    if ((cmd = tstrtok(nullptr, T(" \t"))) == nullptr) {
		tcerr << T("invalid syntax: line ") << line << endl;
		return false;
	    }
	}
	if (!tstricmp(cmd, T("var"))) {
	    tchar *attr, *val;

	    attr = tstrtok(nullptr, T("="));
	    if (!attr) {
		tcerr << T("invalid attribute: line ") << line << endl;
		return false;
	    }
	    p = attr + tstrlen(attr) - 1;
	    while (istspace(*p))
		*p-- = '\0';
	    if (host && !tstricmp(attr, T("host")))
		continue;
	    val = tstrtok(nullptr, T(""));
	    if (!val) {
		tcerr << T("invalid value: line ") << line << endl;
		return false;
	    }
	    while (*val && istspace(*val))
		val++;
	    p = val + tstrlen(val) - 1;
	    while (istspace(*p))
		*p-- = '\0';
	    vars[attr] = val;
	    continue;
	}
	arg = cmd + tstrlen(cmd);
	if (arg - buf == len)
	    arg = nullptr;
	else
	    arg++;

	auto lcmd = make_unique<LoadCmd>(cmt, cmd, arg, status);

	if (bodies.empty() && (lcmd->op == Op::Data || (lcmd->op ==
	    Op::Body && !arg))) {
	    tcerr << T("missing body file for ") << cmd << endl;
	    return false;
	}
	// per message values are only formatted when a command uses them
	needid = needid || lcmd->arg.contains(T("$(id)"));
	needpass = needpass || lcmd->arg.contains(T("$(pass)"));
	needuser = needuser || lcmd->arg.contains(T("$(user)"));
	lcmd->addr = addr;
	cmds.push_back(std::move(lcmd));
    }
    return true;
}

unique_ptr<char[]> SMTPLoad::read(const BodyFile &body) {
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
const char *SMTPLoad::load(uint idx, usec_t &iousec, unique_ptr<char[]> &buf) {
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

void SMTPLoad::add(const tchar *file) {
    namespace fs = std::filesystem;
    std::error_code ec;
    auto sz = fs::file_size(fs::path(file), ec);

    if (ec)
	tcerr << T("invalid body file: ") << file << endl;
    else
	bodies.push_back({.cache = {}, .path = tstring(file), .size = (ulong)sz});
}

uint SMTPLoad::next(void) {
    return startfile + nextfile.fetch_add(1, memory_order_relaxed) %
	((uint)bodies.size() - startfile);
}

int SMTPLoad::onStart(void) {
    tchar buf[1024], data[4096];
    attrmap lvars;
    SMTPClient sc;
    thread_local mt19937 rng(random_device {}());
    thread_local uniform_int_distribution<ulong> dist;
    const auto pick = [&] {
	return allfiles ? next() : (uint)(dist(rng) % bodies.size());
    };
    const auto setvar = [&](const tchar *var, const tchar *fmt) {
	if (auto it = vars.find(var); it != vars.end())
	    fmt = it->second.c_str();
	tsprintf(data, fmt, id);			// NOSONAR
	lvars[var] = data;
    };

    sc.chunking(!dflag);
    if (id > Processor::count())
	msleep(dist(rng) % 1000U * ((mthread / 20) + 1));
    while (!qflag && remain.fetch_sub(1, memory_order_relaxed) > 0) {
	ulong cusec = 0, diff, smsec = 0;
	bool ret = false;
	ulong tmpid = ruser ? dist(rng) << 14 ^ dist(rng) : id;
	usec_t start, last, io = 0;

	id = tmpid ? tmpid % (muser ? muser : id) : 0;	// NOLINT
	if (needid)
	    lvars[T("id")] = std::format(T("{}"), id);
	if (needuser)
	    setvar(T("user"), T("user_%06lu"));
	if (needpass)
	    setvar(T("pass"), T("pass_%06lu"));
	start = last = uticks();
	for (const auto &cmd : cmds) {
	    const tchar *arg = cmd->arg.c_str();

	    if (qflag)
		break;
	    if (cmd->op == Op::Sleep) {
		ulong len;

		if (*arg == '%') {
		    len = atoi<ulong>(arg + 1);
		    if (len)
			len = (uint)(dist(rng) % len);
		} else {
		    len = atoi<ulong>(arg);
		}
		smsec += len;
		msleep(len);
		last = uticks();
		io = 0;
		continue;
	    }
	    ret = true;
	    if (cmd->vars) {
		ret = cmd->arg.size() < size(buf);
		if (ret) {
		    tstrcpy(buf, arg);
		    ret = expand(buf, size(buf), lvars);
		    arg = buf;
		}
	    }
	    if (ret) {
		switch (cmd->op) {
		case Op::Auth:
		    if (const tchar *p = tstrchr(arg, ' '); p) {
			tstring user(arg, p);

			while (istspace(*p))
			    p++;
			ret = sc.auth(user.c_str(), p);
		    } else {
			ret = false;
		    }
		    break;
		case Op::Bcc:
		    ret = sc.bcc(arg);
		    break;
		case Op::Body:
		    if (*arg || bodies.empty()) {
			ret = sc.data(false, arg) && sc.enddata();
			break;
		    }
		    [[fallthrough]];
		case Op::Data: {
		    unique_ptr<char[]> rbuf;
		    uint u = pick();
		    const char *d = load(u, io, rbuf);

		    ret = d && (cmd->op == Op::Body ? sc.data(false,
			achartotchar(d)) : sc.data(d, bodies[u].size)) &&
			sc.enddata();
		    break;
		}
		case Op::Cc:
		    ret = sc.cc(arg);
		    break;
		case Op::Cmd:
		    ret = sc.cmd(cmd->cmd.c_str(), *arg ? arg : nullptr);
		    break;
		case Op::Connect:
		    ret = sc.connect(cmd->addr, to);
		    break;
		case Op::Ehlo:
		    ret = sc.ehlo(arg);
		    break;
		case Op::From:
		    if (pflag)
			sc.pipeline();
		    ret = sc.from(arg);
		    break;
		case Op::Header:
		    sc.header(arg);
		    break;
		case Op::Helo:
		    ret = sc.helo(arg);
		    break;
		case Op::Lhlo:
		    ret = sc.lhlo(arg);
		    break;
		case Op::Quit:
		    ret = sc.quit();
		    break;
		case Op::Rcpt:
		    ret = sc.to(arg);
		    break;
		case Op::Rset:
		    ret = sc.rset();
		    break;
		case Op::Sleep:
		    break;
		case Op::Subject:
		    sc.subject(arg);
		    break;
		case Op::Vrfy:
		    ret = sc.vrfy(arg);
		    break;
		case Op::Xclient:
		    ret = sc.xclient(arg);
		    break;
		}
	    }

	    usec_t now = uticks();

	    diff = (ulong)(now - last - io);
	    cusec += diff;
	    last = now;
	    io = 0;
	    statlock.lock();
	    cmd->complete(ret, diff);
	    statlock.unlock();
	    if (ret && pflag && (cmd->op == Op::Body || cmd->op == Op::Data)) {
		for (const auto &r : sc.rejected())
		    dlog << Log::Warn << Log::cmd(T("rcpt")) << Log::kv(T("arg"),
			r.first) << Log::kv(T("result"), r.second) << endlog;
	    }
	    if (!ret) {
		dlog << Log::Err << Log::cmd(cmd->cmd) << Log::kv(T("arg"),
		    arg) << Log::kv(T("status"), sc.code()) <<
		    Log::kv(T("message"), sc.message()) <<
		    Log::kv(T("duration"), (diff / 1000)) <<
		    Log::kv(T("result"), sc.result()) << endlog;
		break;
	    } else if (dlog.level() >= Log::Info) {
		dlog << Log::Info << Log::cmd(cmd->cmd) << Log::kv(T("arg"),
		    arg) << Log::kv(T("status"), sc.code()) <<
		    Log::kv(T("message"), sc.message()) <<
		    Log::kv(T("duration"), (diff / 1000)) << endlog;
	    }
	}
	sc.close();
	diff = (ulong)(uticks() - start);
	usec += cusec;
	tusec += diff - smsec * 1000;
	++count;
	++tcount;
	dlog << Log::Info << T("cmd=all duration=") << (diff / 1000) << endlog;
    }
    lock.lock();
    if (!--threads)
	cv.set();
    lock.unlock();
    return 0;
}

tstring SMTPLoad::format(ulong u) { return std::format(T(" {:7}"), u); }

tstring SMTPLoad::format(float f) {
    if (f < FLT_EPSILON)
	return T("       0");
    else if (f >= 100)
	return std::format(T(" {:7}"), lround(f));
    else
	return std::format(T(" {:7.2g}"), f);
}

static inline float per(ulong count, ulong div) {
    return div ? (float)count / (float)div : 0;
}

void SMTPLoad::print(tostream &os, usec_t last) {
    bufferstream<tchar> bs;
    ulong lusec = (ulong)(uticks() - last);
    ulong minusec = 0, tminusec = 0, maxusec = 0, tmaxusec = 0;
    ulong ops = 0, tops = 0, err = 0, terr = 0;

    bs << T("CMD     ops/sec msec/op maxmsec  errors OPS/SEC MSEC/OP  ERRORS MINMSEC MAXMSEC") << endl;
    statlock.lock();
    for (const auto &cmd : cmds) {
	if (cmd->op == Op::Sleep)
	    continue;
	ops += cmd->count;
	tops += cmd->tcount;
	err += cmd->err;
	terr += cmd->terr;
	if (!minusec || cmd->minusec < minusec)
	    minusec = cmd->minusec;
	if (cmd->maxusec > maxusec)
	    maxusec = cmd->maxusec;
	if (!tminusec || cmd->tminusec < tminusec)
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

void SMTPLoad::reset(bool all) {
    statlock.lock();
    for (const auto &cmd : cmds) {
	cmd->count = 0;
	cmd->err = 0;
	cmd->usec = cmd->minusec = cmd->maxusec = 0;
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

void SMTPLoad::uninit(void) {
    bodies.clear();
    cmds.clear();
}

static void signal_handler(int sig) {
    if (sig == SIGHUP) {
	rflag = true;
    } else if (qflag) {
	_exit(-1);
    } else {
	qflag = true;
    }
    signal(SIGHUP, signal_handler);
}

int tmain(int argc, tchar *argv[]) {
    bool allfiles = false;
    const tchar *bodyfile = nullptr;
    ulong cachesz = 64;
    const tchar *host = default_host;
    int filecnt = 0;
    tofstream fs;
    int i;
    usec_t last;
    long loops = 1;
    ulong maxuser = 0;
    bool ruser = false;
    tstring s;
    ulong stattime = 3000;
    SMTPLoad *thread;
    uint timeout = 30000;
    uint threads = 1;
    bool wflag = false;
    const tchar *wld = nullptr;

    dlog.level(Log::Note);
    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-a"))) {
	    allfiles = true;
	    if (ttoi(argv[i + 1]) != 0)
		filecnt = atoi<int>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-b"))) {
	    bodyfile = argv[++i];
	} else if (!tstricmp(argv[i], T("-c"))) {
	    cachesz = atoi<ulong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-d"))) {
	    dflag = true;
	} else if (!tstricmp(argv[i], T("-h"))) {
	    host = argv[++i];
	} else if (!tstricmp(argv[i], T("-l"))) {
	    loops = atoi<long>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-m"))) {
	    maxuser = atoi<ulong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-p"))) {
	    pflag = true;
	} else if (!tstricmp(argv[i], T("-q"))) {
	    dlog.level(Log::Level(dlog.level() - 1));
	} else if (!tstricmp(argv[i], T("-r"))) {
	    ruser = true;
	} else if (!tstricmp(argv[i], T("-s"))) {
	    stattime = atoi<ulong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-t"))) {
	    threads = (uint)atoi<ulong>(argv[++i]);
	    if (!maxuser)
		maxuser = threads;
	} else if (!tstricmp(argv[i], T("-w"))) {
	    timeout = (uint)atoi<ulong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-v"))) {
	    dlog.level(Log::Level(dlog.level() + 1));
	} else if (!wld && *argv[i] != '-') {
	    wld = argv[i];
	} else {
	    break;
	}
    }
    if (argc == 1 || i < argc) {
	const tchar *program = tstrrchr(argv[0], '/');

	if (!program)
	    program = tstrrchr(argv[0], '\\');
	tcerr << T("usage: ") << (program ? program + 1 : argv[0]) <<
	    T(" [-a [numfiles]] [-b bodyfile|bodydir] [-c cachemb] [-d]\n")
	    T("\t[-h host[:port]] [-l loops] [-m maxuser] [-p] [-q|-v]* [-r]\n")
	    T("\t[-s stattime] [-t threads] [-w timeout] cmdfile") << endl;
	return 1;
    }
    setvbuf(stdout, nullptr, _IOFBF, 4096);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    if (!wld)
	wld = T("smtp.wld");
    if (!SMTPLoad::init(host, threads, maxuser, ruser, timeout,
	loops, wld, bodyfile, cachesz * 1024 * 1024, allfiles, filecnt))
	return -1;
    dlog << Log::Info << T("test ") << host << ' ' << wld << T(" (") <<
	threads << T(" thread") << (threads == 1 ? T("") : T("s")) << T(", ") <<
	loops << T(" loop") << (loops == 1 ? T("") : T("s")) << ')' << endlog;
    for (uint u = 0; u < threads; u++) {
	thread = new SMTPLoad;
	thread->start(32 * 1024);
    }
    do {
	last = uticks();
	SMTPLoad::pause(stattime);
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
	    SMTPLoad::reset(true);
	    tcout << T("*** RESET STATISTICS ***") << endl << endl;
	} else {
	    SMTPLoad::print(tcout, last);
	    if (wflag) {
		wflag = false;
		tcout << T("Comment: ");
		getline(tcin, s);
		if (!fs.is_open())
		    fs.open(T("load.dat"), ios::out | ios::app);
		fs << T("**** ") << s << T(" ****") << endl;
		SMTPLoad::print(fs, last);
		fs << endl << endl;
	    }
	    SMTPLoad::reset(false);
	}
    } while (!qflag && SMTPLoad::working());
    dlog.level(Log::None);
    if (fs.is_open())
	fs.close();
    while ((thread = (SMTPLoad *)ThreadGroup::MainThreadGroup.wait(3000)) !=
	nullptr)
	delete thread;
    SMTPLoad::uninit();
    return 0;
}
