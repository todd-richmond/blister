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
#include "HTTPClient.h"
#include "Log.h"

using attrmap = unordered_map<tstring, tstring, strhash, streq>;

static atomic_bool qflag = false, rflag = false;

class HTTPLoad: public Thread {
public:
    HTTPLoad(): id(threads++) {}

    [[nodiscard]] static bool init(const tchar *host, uint maxthread, ulong maxuser,
	bool randuser, bool debug, bool keepalive, uint timeout, long loops,
	const tchar *file, const tchar *bodyfile, ulong cachesz, bool all, int fcnt);
    static void print(tostream &os, usec_t last);
    static uint working(void) { return threads; }
    static void reset(bool all = false);
    static void uninit(void);
    static void pause(ulong msec) { lock.lock(); cv.wait(msec); lock.unlock(); }

private:
    enum class Op: uchar { Get, Post, Sleep };

    class LoadCmd {
    public:
	LoadCmd(const tchar *c, const tchar *a, const URL &u, const tchar *d =
	    nullptr, const tchar *s = nullptr, const tchar *v = nullptr):
	    arg(a ? a : T("")), cmd(c), data(d ? d : T("")), full(u.fullpath()),
	    path(u.relpath()), value(v ? v : T("")),
	    op(!tstricmp(c, T("get")) ? Op::Get : !tstricmp(c, T("post")) ?
	    Op::Post : Op::Sleep), status((ushort)(s ? ttoi(s) : 0)),
	    vars(path.contains(T("$("))) {}

	Sockaddr addr;
	tstring arg, cmd, data, full, path, value;
	ulong count = 0, err = 0, tcount = 0, terr = 0;
	ulong maxusec = 0, minusec = 0, tmaxusec = 0, tminusec = 0, tusec = 0,
	    usec = 0;
	Op op;
	ushort status;
	bool vars;			// path has $() for per request values

	void error(void) { err++; terr++; }
	void complete(bool sts, ulong diff) {
	    count++;
	    tcount++;
	    if (!sts) {
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

    static inline bool allfiles = false, dbg = false, ka = false,
	needid = false, needpass = false, needuser = false, ruser = false;
    static inline vector<BodyFile> bodies;
    static inline vector<unique_ptr<LoadCmd>> cmds;
    static inline atomic<ulong> count = 0, tcount = 0, tusec = 0, usec = 0;
    static inline Lock lock;		// before cv which uses it
    static inline Condvar cv{lock};
    static inline attrmap hdrs, vars;
    ulong id;
    static inline uint mthread = 0, startfile = 0, threads = 0, to = 0;
    static inline ulong muser = 0;
    static inline atomic<uint> nextfile = 0;
    static inline atomic_long remain = 0;
    static inline SpinLock statlock{SPIN_LIMIT};

    int onStart(void) override;
    static void add(const tchar *file);
    static bool expand(tchar *str, size_t buf_size, const attrmap &amap = vars);
    static tstring format(ulong u);
    static tstring format(float f);
    static const char *load(uint idx, usec_t &iousec, unique_ptr<char[]> &buf);
    static uint next(void);
    static unique_ptr<char[]> read(const BodyFile &body);
};

bool HTTPLoad::expand(tchar *str, size_t buf_size, const attrmap &amap) {
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

bool HTTPLoad::init(const tchar *host, uint maxthread, ulong maxuser,
    bool randuser, bool debug, bool keepalive, uint timeout, long loops,
    const tchar *file, const tchar *bodyfile, ulong cachesz, bool all,
    int fcnt) {
    Sockaddr addr;
    tchar buf[1024];
    const tchar *cmd, *req, *arg, *data = nullptr, *value = nullptr, *status = nullptr;
    tchar *p;
    tifstream is(file);
    int len;
    int line = 0;
    URL url;

    mthread = maxthread;
    muser = maxuser;
    remain = loops;
    ruser = randuser;
    dbg = debug;
    ka = keepalive;
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
    vars[T("host")] = host;
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
	cmd = tstrtok(buf, T(" \t"));
	if (!cmd)
	    continue;
	if (!tstricmp(cmd, T("hdr")) || !tstricmp(cmd, T("var"))) {
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
	    if (!tstricmp(cmd, T("hdr")))
		hdrs[attr] = val;
	    else
		vars[attr] = val;
	    continue;
	}
	if (!tstricmp(cmd, T("get")) || !tstricmp(cmd, T("post"))) {
	    arg = tstrtok(nullptr, T(" \t"));
	    req = tstrtok(nullptr, T(" \t"));
	    if (!tstricmp(cmd, T("post")))
		data = tstrtok(nullptr, T(" \t"));
	    status = tstrtok(nullptr, T(" \t"));
	    if (!status)
		status = T("200");
	    value = tstrtok(nullptr, T(""));
	    if (!url.set(req)) {
		tcerr << T("invalid url: line ") << line << endl;
		return false;
	    }
	} else if (!tstricmp(cmd, T("sleep"))) {
	    arg = tstrtok(nullptr, T(" \t"));
	} else {
	    tcerr << T("invalid cmd: line ") << line << endl;
	    return false;
	}
	if (arg && arg - buf == len)
	    arg = nullptr;
	if (bodies.empty() && !tstricmp(cmd, T("post")) && !data) {
	    tcerr << T("missing body file for ") << cmd << endl;
	    return false;
	}
	if (!addr.set(url.host().c_str(), url.port())) {
	    tcerr << T("invalid host: line ") << line << endl;
	    return false;
	}

	auto lcmd = make_unique<LoadCmd>(cmd, arg, url, data, status, value);

	// per request values are only formatted when a command uses them
	for (const tstring *str : { &lcmd->path, &lcmd->data }) {
	    needid = needid || str->contains(T("$(id)"));
	    needpass = needpass || str->contains(T("$(pass)"));
	    needuser = needuser || str->contains(T("$(user)"));
	}
	lcmd->addr = addr;
	cmds.push_back(std::move(lcmd));
    }
    return true;
}

unique_ptr<char[]> HTTPLoad::read(const BodyFile &body) {
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
const char *HTTPLoad::load(uint idx, usec_t &iousec, unique_ptr<char[]> &buf) {
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

void HTTPLoad::add(const tchar *file) {
    namespace fs = std::filesystem;
    std::error_code ec;
    auto sz = fs::file_size(fs::path(file), ec);

    if (ec)
	tcerr << T("invalid body file: ") << file << endl;
    else
	bodies.push_back({.cache = {}, .path = tstring(file), .size = (ulong)sz});
}

uint HTTPLoad::next(void) {
    return startfile + nextfile.fetch_add(1, memory_order_relaxed) %
	((uint)bodies.size() - startfile);
}

int HTTPLoad::onStart(void) {
    tchar buf[1024], data[4096];
    HTTPClient hc;
    tofstream fs;
    attrmap lvars;
    tstring s;
    vector<tstring> cookies;
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

    if (dbg)
	fs.open("debug.out", ios::trunc | ios::out);
    if (id > Processor::count())
	msleep(dist(rng) % 1000U * ((mthread / 20) + 1));
    while (!qflag && remain.fetch_sub(1, memory_order_relaxed) > 0) {
	ulong cusec = 0, diff, smsec = 0;
	bool ret;
	ulong tmpid = ruser ? dist(rng) << 14 ^ dist(rng) : id;
	usec_t start, last, io = 0;

	id = tmpid ? tmpid % (muser ? muser : id) : 0;	// NOLINT
	if (needid)
	    lvars[T("id")] = std::format(T("{}"), id);
	if (needuser)
	    setvar(T("user"), T("user_%06lu"));
	if (needpass)
	    setvar(T("pass"), T("pass_%06lu"));
	cookies.clear();
	start = last = uticks();
	for (const auto &cmd : cmds) {
	    const tchar *path = cmd->path.c_str();

	    if (qflag)
		break;
	    if (cmd->op == Op::Sleep) {
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
		io = 0;
		continue;
	    }
	    if (dbg)
		fs << T("\n\n******* ") << cmd->cmd << T(" ") << cmd->arg <<
		    T(" ") << cmd->full << T(" *******") << endl;
	    hc.timeout(to, to);
	    if ((ret = hc.connect(cmd->addr, ka, to)) == true) {
		if (!cookies.empty()) {
		    s.erase();
		    for (const auto &c : cookies) {
			if (!s.empty())
			    s += T("; ");
			s += c;
		    }
		    hc.header(T("cookie"), s);
		    if (dbg)
			fs << T("SEND Cookie: ") << s << endl;
		}
		for (const auto &[key, value] : hdrs)
		    hc.header(key, value);
	    } else {
		path = cmd->full.c_str();
	    }
	    if (ret && cmd->vars) {
		ret = cmd->path.size() < size(buf);
		if (ret) {
		    tstrcpy(buf, path);
		    ret = expand(buf, size(buf), lvars);
		    path = buf;
		}
	    }
	    if (!ret) {
		// continue
	    } else if (cmd->op == Op::Get) {
		ret = hc.get(path);
	    } else if (cmd->data.empty()) {
		unique_ptr<char[]> rbuf;
		uint u = pick();
		const char *d = load(u, io, rbuf);

		hc.header(T("content-type"), T("application/octet-stream"));
		ret = d && hc.post(path, d, bodies[u].size);
	    } else if (cmd->data.length() >= size(data)) {
		ret = false;
	    } else {
		tstrcpy(data, cmd->data.c_str());
		ret = expand(data, size(data), lvars);
		if (ret) {
		    hc.header(T("content-type"),
			T("application/x-www-form-urlencoded"));
		    ret = hc.post(path, data, (ulong)(tstrlen(data) *
			sizeof (tchar)));
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
	    if (!ret || (cmd->status && hc.status() != cmd->status) ||
		(!cmd->status && hc.status() != 200 && hc.status() != 302)) {
		if (ret) {
		    statlock.lock();
		    cmd->error();
		    statlock.unlock();
		}
		dlog << Log::Err << T("cmd=") << cmd->cmd << T(" arg=") <<
		    path << T(" status=") << hc.status() << T(" expected=") <<
		    cmd->status << T(" duration=") << (diff / 1000) << endlog;
		break;
	    } else {
		if (dbg)
		    fs << cmd->cmd << T(" status: ") << hc.status() << endl <<
			endl;
		for (const auto &[key, val] : hc.responses()) {
		    if (key == T("set-cookie")) {
			tstring::size_type pos;

			s = val;
			if ((pos = s.find_first_of(T(';'))) != string::npos)
			    s.erase(pos);
			if (s != T("invalid"))
			    cookies.push_back(s);
		    }
		    if (dbg)
			fs << key << ": " << val << endl;
		}
#ifndef UNICODE	// TODO
		if (dbg) {
		    fs << endl;
		    fs.write(hc.data(), (streamsize)hc.size());
		    fs.flush();
		}
		if (!cmd->value.empty() && !tstring_view(hc.data(),
		    hc.size()).contains(cmd->value)) {
		    dlog << Log::Err << T("cmd=") << cmd->cmd << T(" arg=") <<
			path << T(" invalid return data") << endlog;
		    statlock.lock();
		    cmd->error();
		    statlock.unlock();
		    break;
		}
#endif
		if (dlog.level() >= Log::Info)
		    dlog << Log::Info << T("cmd=") << cmd->cmd << T(" arg=") <<
			path << T(" status=") << hc.status() <<
			T(" duration=") << (diff / 1000) << endlog;
	    }
	}
	if (!ka)
	    hc.close();
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

tstring HTTPLoad::format(ulong u) { return std::format(T(" {:7}"), u); }

tstring HTTPLoad::format(float f) {
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

void HTTPLoad::print(tostream &os, usec_t last) {
    ulong lusec = (ulong)(uticks() - last);
    ulong minusec = 0, tminusec = 0, maxusec = 0, tmaxusec = 0;
    ulong ops = 0, tops = 0, err = 0, terr = 0;
    bufferstream<tchar> bs;

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

void HTTPLoad::reset(bool all) {
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

void HTTPLoad::uninit(void) {
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
    bool debug = false;
    int filecnt = 0;
    tofstream fs;
    const tchar *host = T("localhost:80");
    int i;
    bool ka = false;
    usec_t last;
    long loops = 1;
    ulong maxuser = 0;
    bool ruser = false;
    tstring s;
    ulong stattime = 3000;
    HTTPLoad *thread;
    uint threads = 1;
    bool wflag = false;
    const tchar *wld = nullptr;
    uint timeout = 30000;

    dlog.level(Log::Note);
    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-a"))) {
	    allfiles = true;
	    if (atoi<int>(argv[i + 1]) != 0)
		filecnt = atoi<int>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-b"))) {
	    bodyfile = argv[++i];
	} else if (!tstricmp(argv[i], T("-c"))) {
	    cachesz = atoi<ulong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-d"))) {
	    debug = true;
	    unlink("debug.out");
	} else if (!tstricmp(argv[i], T("-h"))) {
	    host = argv[++i];
	} else if (!tstricmp(argv[i], T("-k"))) {
	    ka = true;
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
	    T(" [-a [numfiles]] [-b bodyfile|bodydir] [-c cachemb] [-d]\n")
	    T("\t[-h host[:port]] [-k] [-l loops] [-m maxuser] [-q|-v]* [-r]\n")
	    T("\t[-s stattime] [-t threads] [-w timeout] cmdfile") << endl;
	return 1;
    }
    setvbuf(stdout, nullptr, _IOFBF, 4096);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    if (!wld)
	wld = T("http.wld");
    if (!HTTPLoad::init(host, threads, maxuser, ruser, debug, ka, timeout,
	loops, wld, bodyfile, cachesz * 1024 * 1024, allfiles, filecnt))
	return -1;
    dlog << Log::Info << T("test ") << host << ' ' << wld << T(" (") <<
	threads << T(" thread") << (threads == 1 ? T("") : T("s")) << T(", ") <<
	loops << T(" loop") << (loops == 1 ? T("") : T("s")) << ')' << endlog;
    for (uint u = 0; u < threads; ++u) {
	thread = new HTTPLoad;
	thread->start(32 * 1024);
    }
    do {
	last = uticks();
	HTTPLoad::pause(stattime);
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
	    HTTPLoad::reset(true);
	    tcout << T("*** RESET STATISTICS ***") << endl << endl;
	} else {
	    HTTPLoad::print(tcout, last);
	    if (wflag) {
		wflag = false;
		tcout << T("Comment: ");
		getline(tcin, s);
		if (!fs.is_open())
		    fs.open(T("load.dat"), ios::out | ios::app);
		fs << T("**** ") << s << T(" ****") << endl;
		HTTPLoad::print(fs, last);
		fs << endl << endl;
	    }
	    HTTPLoad::reset(false);
	}
    } while (!qflag && HTTPLoad::working());
    dlog.level(Log::None);
    if (fs.is_open())
	fs.close();
    while ((thread = (HTTPLoad *)ThreadGroup::MainThreadGroup.wait(3000)) !=
	nullptr)
	delete thread;
    HTTPLoad::uninit();
    return 0;
}
