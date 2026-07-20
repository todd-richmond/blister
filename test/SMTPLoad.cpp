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
#include <ctype.h>
#include <fcntl.h>
#include <float.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <random>
#include <unordered_map>
#include "Log.h"
#include "SMTPClient.h"

using attrmap = unordered_map<tstring, tstring, strhash<tchar>, streq>;

static constexpr const tchar *default_host = T("localhost:25");
static atomic_bool qflag = false, rflag = false;

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
    class LoadCmd {
    public:
	LoadCmd(const tchar *comment, const tchar *command, const tchar
	    *argument, const tchar *status = nullptr): cmt(comment), cmd(command),
	    arg(argument ? argument : T("")),
	    sts((ushort)(status ? ttoi(status) : 200)), usec(0), tusec(0),
	    minusec(0), tminusec(0), maxusec(0), tmaxusec(0), count(0),
	    tcount(0), err(0), terr(0) {
	    for (auto &c : cmd)
		c = (char)tolower(c);
	}

	tstring cmt, cmd, arg;
	ushort sts;
	Sockaddr addr;
	ulong usec, tusec, minusec, tminusec, maxusec, tmaxusec;
	ulong count, tcount, err, terr;

	void complete(bool status, ulong diff) {
	    count++;
	    tcount++;
	    if (!status) {
		err++;
		terr++;
	    }
	    usec += diff;
	    tusec += diff;
	    if (!minusec || diff < minusec)
		minusec = diff;
	    if (diff > maxusec)
		maxusec = diff;
	    if (!tminusec || diff < tminusec)
		tminusec = diff;
	    if (diff > tmaxusec)
		tmaxusec = diff;
	}
    };

    ulong id;
    static Lock lock;
    static Condvar cv;
    static tchar format_buf[32];
    static bool ruser;
    static ulong muser;
    static uint mthread;
    static uint to;
    static atomic_long remain;
    static uint threads;
    static attrmap vars;
    struct BodyFile {
	tstring path;
	ulong size = 0;
	char *cache = nullptr;
    };
    static ulong bodycachesz;
    static vector<BodyFile> bodies;
    static bool allfiles;
    static int filecnt;
    static uint nextfile;
    static uint startfile;
    static atomic<ulong> usec, tusec, count, tcount;
    static vector<unique_ptr<LoadCmd>> cmds;

    int onStart(void) override;
    [[nodiscard]] static bool expand(tchar *str, size_t buf_size, const attrmap &amap = vars);
    static const tchar *format(ulong u);
    static const tchar *format(float f);
    [[nodiscard]] static char *load(uint idx, usec_t &iousec);
    static void add(const tchar *file);
    static uint next(void);
};

Lock SMTPLoad::lock;
Condvar SMTPLoad::cv(lock);
tchar SMTPLoad::format_buf[32];
uint SMTPLoad::threads;
ulong SMTPLoad::muser;
uint SMTPLoad::mthread;
bool SMTPLoad::ruser;
atomic_long SMTPLoad::remain;
uint SMTPLoad::to;
attrmap SMTPLoad::vars;
ulong SMTPLoad::bodycachesz;
vector<SMTPLoad::BodyFile> SMTPLoad::bodies;
bool SMTPLoad::allfiles;
int SMTPLoad::filecnt;
uint SMTPLoad::nextfile;
uint SMTPLoad::startfile = 0;
atomic<ulong> SMTPLoad::usec, SMTPLoad::tusec;
atomic<ulong> SMTPLoad::count, SMTPLoad::tcount;
vector<unique_ptr<SMTPLoad::LoadCmd>> SMTPLoad::cmds;

bool SMTPLoad::expand(tchar *str, size_t buf_size, const attrmap &amap) {
    tchar *p;
    tstring::size_type len;

    while ((p = tstrstr(str, T("$("))) != NULL) {
	tchar *end = tstrchr(p, ')');

	if (p != str && p[-1] == '$') {	    // $$() -> $()
	    size_t remaining_len = tstrlen(p) + 1;
	    size_t current_pos = (size_t)(p - str);
	    if (current_pos + remaining_len > buf_size) {
		return false;  // Not enough space
	    }
	    memmove(p - 1, p, remaining_len);
	} else if (!end) {
	    return false;
	} else {
	    *end++ = '\0';
	    auto it = amap.find(p + 2);
	    if (it == amap.end())
		return false;
	    len = it->second.size();
	    size_t end_len = tstrlen(end) + 1;
	    size_t current_pos = (size_t)(p - str);
	    if (current_pos + len + end_len > buf_size) {
		return false;  // Not enough space for expansion
	    }
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
    bodycachesz = (loops == 1) ? 0 : cachesz;
    filecnt = fcnt;
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
	if (filecnt > 0 && (uint)filecnt < (uint)bodies.size())
	    bodies.resize((size_t)filecnt);
	else if (filecnt < 0 && (uint)(-filecnt) < (uint)bodies.size())
	    startfile = (uint)bodies.size() - (uint)(-filecnt);
	nextfile = startfile;
	remain = remain * (long)(bodies.size() - startfile);
    }
    vars[T("host")] = host ? host : default_host;
    if (!addr.set(host ? host : default_host)) {
	tcerr << T("invalid host: ") << vars[T("host")] << endl;
	return false;
    }
    while (is.getline(buf, (streamsize)std::size(buf))) {
	line++;
	if (!buf[0] || buf[0] == '#' || buf[0] == '/')
	    continue;
	if (!expand(buf, sizeof (buf))) {
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
	    if ((cmd = tstrtok(NULL, T(" \t"))) == NULL) {
		tcerr << T("invalid syntax: line ") << line << endl;
		return false;
	    }
	} else {
	    cmd = cmt;
	}
	if (istdigit(*cmd)) {
	    status = cmd;
	    if ((cmd = tstrtok(NULL, T(" \t"))) == NULL) {
		tcerr << T("invalid syntax: line ") << line << endl;
		return false;
	    }
	}
	if (!tstricmp(cmd, T("var"))) {
	    tchar *attr, *val;

	    attr = tstrtok(NULL, T("="));
	    if (!attr) {
		tcerr << T("invalid attribute: line ") << line << endl;
		return false;
	    }
	    p = attr + tstrlen(attr) - 1;
	    while (istspace(*p))
		*p-- = '\0';
	    if (host && !tstricmp(attr, T("host")))
		continue;
	    val = tstrtok(NULL, T(""));
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
	if (!arg && bodies.empty() &&
	    (!tstricmp(cmd, T("body")) || !tstricmp(cmd, T("data")))) {
	    tcerr << T("missing text for ") << cmd << endl;
	    return false;
	}
	auto lcmd = make_unique<LoadCmd>(cmt, cmd, arg, status);
	lcmd->addr = addr;
	cmds.push_back(std::move(lcmd));
    }
    return true;
}

char *SMTPLoad::load(uint idx, usec_t &iousec) {
    int fd;
    char *ret;
    const tchar *file = bodies[idx].path.c_str();
    ulong filelen = bodies[idx].size;

    lock.lock();
    ret = bodies[idx].cache;
    lock.unlock();
    if (ret) {
	iousec = 0;
	return ret;
    }
    ret = nullptr;
    iousec = uticks();
    if ((fd = open(tchartoachar(file), O_RDONLY|O_BINARY|O_SEQUENTIAL)) != -1) {
	ret = new char[(size_t)filelen + 1];
	if (::read(fd, ret, filelen) == (int)filelen) {
	    ret[filelen] = '\0';
	    lock.lock();
	    if (!bodies[idx].cache && filelen <= bodycachesz) {
		bodies[idx].cache = ret;
		bodycachesz -= filelen;
	    }
	    lock.unlock();
	} else {
	    delete [] ret;
	    ret = nullptr;
	}
	close(fd);
    }
    if (!ret)
	tcerr << T("unable to read body file: ") << file << endl;
    iousec = uticks() - iousec;
    return ret;
}

void SMTPLoad::add(const tchar *file) {
    namespace fs = std::filesystem;
    std::error_code ec;
    auto sz = fs::file_size(fs::path(file), ec);
    if (ec)
	tcerr << T("invalid body file: ") << file << endl;
    else
	bodies.push_back({.path = tstring(file), .size = (ulong)sz});
}

uint SMTPLoad::next(void) {
    uint ret;

    lock.lock();
    ret = nextfile++;
    if (nextfile >= (uint)bodies.size())
	nextfile = startfile;
    lock.unlock();
    return ret;
}

int SMTPLoad::onStart(void) {
    tchar buf[1024], data[4096];
    ulong diff;
    attrmap lvars;
    SMTPClient sc;
    usec_t start, end, last, now, io;
    thread_local mt19937 rng(random_device {}());
    thread_local uniform_int_distribution<ulong> dist;
    if (id > Processor::count())
	msleep(dist(rng) % 1000U * ((mthread / 20) + 1));
    while (!qflag) {
	const tchar *p;
	ulong smsec = 0;
	bool ret = false;
	ulong tmpid = ruser ? dist(rng) << 14 ^ dist(rng) : id;
	long tmp;

	tmp = remain.fetch_sub(1, memory_order_relaxed);
	if (tmp <= 0)
	    break;
	id = tmpid ? tmpid % (muser ? muser : id) : 0;	// NOLINT
	tsprintf(data, T("%lu"), id);
	lvars[T("id")] = data;
	if (auto ait = vars.find(T("user")); ait == vars.end())
	    tsprintf(data, T("user_%06lu"), id);
	else
	    tsprintf(data, ait->second.c_str(), id);	// NOSONAR
	lvars[T("user")] = data;
	if (auto ait = vars.find(T("pass")); ait == vars.end())
	    tsprintf(data, T("pass_%06lu"), id);
	else
	    tsprintf(data, ait->second.c_str(), id);	// NOSONAR
	lvars[T("pass")] = data;
	start = last = uticks();
	io = 0;
	for (const auto &cmd : cmds) {
	    if (qflag)
		break;
	    ret = false;
	    if (!tstricmp(cmd->cmd.c_str(), T("sleep"))) {
		ulong len;

		p = cmd->arg.c_str();
		if (*p == '%') {
		    len = atoi<ulong>(p + 1);
		    if (len)
			len = (uint)(dist(rng) % len);
		} else {
		    len = atoi<ulong>(p);
		}
		smsec += len;
		msleep(len);
		last = uticks();
		io = 0;
		continue;
	    } else if (cmd->arg.length() < std::size(buf)) {
		tstrcpy(buf, cmd->arg.c_str());
		ret = expand(buf, sizeof (buf), lvars);
	    }
	    if (!ret) {
		// continue
	    } else if (cmd->cmd == T("connect")) {
		ret = sc.connect(cmd->addr, to);
	    } else if (cmd->cmd == T("auth")) {
		tstring auth;

		p = tstrchr(buf, ' ');
		if (p) {
		    while (istspace(*p))
			p++;
		    auth.assign(buf, (tstring::size_type)(p - buf));
		    ret = sc.auth(auth.c_str(), p + 1);
		} else {
		    ret = false;
		}
	    } else if (cmd->cmd == T("ehlo")) {
		ret = sc.ehlo(buf);
	    } else if (cmd->cmd == T("helo")) {
		ret = sc.helo(buf);
	    } else if (cmd->cmd == T("lhlo")) {
		ret = sc.lhlo(buf);
	    } else if (cmd->cmd == T("xclient")) {
		ret = sc.xclient(buf);
	    } else if (cmd->cmd == T("from")) {
		ret = sc.from(buf);
	    } else if (cmd->cmd == T("rcpt") || cmd->cmd == T("to")) {
		ret = sc.to(buf);
	    } else if (cmd->cmd == T("bcc")) {
		ret = sc.bcc(buf);
	    } else if (cmd->cmd == T("cc")) {
		ret = sc.cc(buf);
	    } else if (cmd->cmd == T("hdr") || cmd->cmd == T("header")) {
		sc.header(buf);
		ret = true;
	    } else if (cmd->cmd == T("rset")) {
		ret = sc.rset();
	    } else if (cmd->cmd == T("subj") || cmd->cmd == T("subject")) {
		sc.subject(buf);
		ret = true;
	    } else if (cmd->cmd == T("body")) {
		if (buf[0] || bodies.empty()) {
		    ret = sc.data(false, buf) && sc.enddata();
		} else {
		    uint u = allfiles ? next() : ((uint)dist(rng) % (uint)bodies.size());
		    char *d = load(u, io);

		    if (d) {
			ret = sc.data(false, achartotchar(d)) &&
			    sc.enddata();
			if (d != bodies[u].cache)
			    delete [] d;
		    }
		}
	    } else if (cmd->cmd == T("data")) {
		uint u = allfiles ? next() : ((uint)dist(rng) % (uint)bodies.size());
		char *d = load(u, io);

		if (d) {
		    ret = sc.data(d, bodies[u].size) && sc.enddata();
		    if (d != bodies[u].cache)
			delete [] d;
		}
	    } else if (cmd->cmd == T("vrfy")) {
		ret = sc.vrfy(buf);
	    } else if (cmd->cmd == T("quit")) {
		ret = sc.quit();
	    } else {
		ret = sc.cmd(cmd->cmd.c_str(), buf[0] ? buf : nullptr);
	    }
	    now = uticks();
	    diff = (ulong)(now - last - io);
	    usec += diff;
	    last = now;
	    io = 0;
	    lock.lock();
	    cmd->complete(ret, diff);
	    lock.unlock();
	    if (!ret) {
		dlog << Log::Err << Log::cmd(cmd->cmd) << Log::kv(T("arg"),
		    buf) << Log::kv(T("status"), sc.code()) <<
		    Log::kv(T("message"), sc.message()) <<
		    Log::kv(T("duration"), (diff / 1000)) <<
		    Log::kv(T("result"), sc.result()) << endlog;
		break;
	    } else if (dlog.level() >= Log::Info) {
		dlog << Log::Info << Log::cmd(cmd->cmd) << Log::kv(T("arg"),
		    buf) << Log::kv(T("status"), sc.code()) <<
		    Log::kv(T("message"), sc.message()) <<
		    Log::kv(T("duration"), (diff / 1000)) << endlog;
	    }
	}
	sc.close();
	end = uticks();
	diff = (ulong)(end - start);
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

const tchar *SMTPLoad::format(ulong u) {
    tsprintf(format_buf, T(" %7lu"), u);
    return format_buf;
}

const tchar *SMTPLoad::format(float f) {
    WARN_DISABLE(26467)
    if (f - 0.0F < FLT_EPSILON)
	tstrcpy(format_buf, T("       0"));
    else if (f >= 100)
	tsprintf(format_buf, T(" %7lu"), (ulong)round(f));
    else
	tsprintf(format_buf, T(" %7.2g"), (double)f);
    return format_buf;
}

static inline float round(ulong count, ulong div) {
    return div ? (float)count / ((float)div * 1.0F) : 0;
}

void SMTPLoad::print(tostream &os, usec_t last) {
    tchar buf[32];
    bufferstream<tchar> bs;
    ulong lusec = (ulong)(uticks() - last);
    ulong minusec = 0, tminusec = 0, maxusec = 0, tmaxusec = 0;
    ulong ops = 0, tops = 0, err = 0, terr = 0;

    bs << T("CMD     ops/sec msec/op maxmsec  errors OPS/SEC MSEC/OP  ERRORS MINMSEC MAXMSEC") << endl;
    lock.lock();
    for (const auto &cmd : cmds) {
	if (!tstricmp(cmd->cmd.c_str(), T("sleep")))
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
	tsprintf(buf, T("%-7s"), cmd->cmd.c_str());
	bs << buf << format(round(cmd->count, lusec) * 1000000) <<
	    format(round(cmd->usec, cmd->count) / 1000) <<
	    format(cmd->maxusec / 1000) << format(cmd->err) <<
	    format(round(cmd->tcount, tusec) * 1000000) <<
	    format(round(cmd->tusec, cmd->tcount) / 1000) <<
	    format(cmd->terr) << format(cmd->tminusec / 1000) <<
	    format(cmd->tmaxusec / 1000) << endl;
    }
    lock.unlock();
    bs << T("ALL    ") << format(round(count, lusec) * 1000000) <<
	format(round(usec, count) / 1000) <<
	format(maxusec / 1000) << format(err) <<
	format(round(tcount, tusec) * 1000000) <<
	format(round(tusec, tcount) / 1000) << format(terr) <<
	format(tminusec / 1000) << format(tmaxusec / 1000) << endl;
    bs << T("AVG/TOT") << format(round(ops, lusec) * 1000000) <<
	format(round(usec, ops) / 1000) << format(maxusec / 1000) <<
	format(err) << format(round(tops, tusec) * 1000000) <<
	format(round(tusec, tops) / 1000) << format(terr) <<
	format(tminusec / 1000) << format(tmaxusec / 1000) << endl << endl;
    os.write(bs.str(), bs.pcount());
    os.flush();
}

void SMTPLoad::reset(bool all) {
    for (auto &cmd : cmds) {
	cmd->count = 0;
	cmd->err = 0;
	cmd->usec = cmd->minusec = cmd->maxusec = 0;
	if (all) {
	    cmd->tcount = 0;
	    cmd->terr = 0;
	    cmd->tusec = cmd->tminusec = cmd->tmaxusec = 0;
	}
    }
    usec =  0;
    count = 0;
    if (all) {
	tusec = 0;
	tcount = 0;
    }
}

void SMTPLoad::uninit(void) {
    for (const auto &b : bodies)
	delete [] b.cache;
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
	} else if (!tstricmp(argv[i], T("-h"))) {
	    host = argv[++i];
	} else if (!tstricmp(argv[i], T("-l"))) {
	    loops = atoi<long>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-m"))) {
	    maxuser = atoi<ulong>(argv[++i]);
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
	    T(" [-a [numfiles]] [-b bodyfile|bodydir] [-c cachemb]\n")
	    T("\t[-h host[:port]] [-l loops] [-m maxuser] [-q|-v]* [-r]\n")
	    T("\t[-s stattime] [-t threads] [-w timeout] cmdfile") << endl;
	return 1;
    }
    setvbuf(stdout, NULL , _IOFBF, 4096);
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
    while ((thread = (SMTPLoad *)(ThreadGroup::MainThreadGroup.wait(
	3000))) != nullptr)
	delete thread;
    SMTPLoad::uninit();
    return 0;
}
