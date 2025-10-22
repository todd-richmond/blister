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
#else
#include <dirent.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <float.h>
#include <math.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include <fstream>
#include <unordered_map>
#include "HTTPClient.h"
#include "Log.h"

typedef unordered_map<tstring, tstring, strhash<tchar>, streq<tchar> > attrmap;

static atomic_bool qflag = false, rflag = false;

class HTTPLoad: public Thread {
public:
    HTTPLoad(): id(threads++) {}

    static bool init(const tchar *host, uint maxthread, ulong maxuser, bool
	randuser, bool debug, bool keepalive, uint timeout, long loops, const
	tchar *file, const tchar *bodyfile, ulong cachesz, bool all, int fcnt);
    static void print(tostream &os, usec_t last);
    static uint working(void) { return threads; }
    static void reset(bool all = false);
    static void uninit(void);
    static void pause(ulong msec) { lock.lock(); cv.wait(msec); lock.unlock(); }

private:
    class LoadCmd {
    public:
	LoadCmd(const tchar *c, const tchar *a, const URL &u, const tchar *d =
	    NULL, const tchar *s = NULL, const tchar *v = NULL): cmd(c), arg(a ?
	    a : T("")), data(d ? d : T("")), value(v ? v : T("")),
	    status((ushort)(s ? ttoi(s) : 0)), url(u), usec(0), tusec(0),
	    minusec(0), tminusec(0), maxusec(0), tmaxusec(0), count(0),
	    tcount(0), err(0), terr(0) {}

	tstring cmd, arg, data, value;
	ushort status;
	URL url;
	Sockaddr addr;
	ulong usec, tusec, minusec, tminusec, maxusec, tmaxusec;
	ulong count, tcount, err, terr;

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
    static bool dbg, ka, ruser;
    static tchar format_buf[32];
    static ulong muser;
    static uint mthread;
    static uint to;
    static atomic_long remain;
    static uint threads;
    static attrmap hdrs, vars;
    static uint bodycnt;
    static ulong *bodysz;
    static ulong bodycachesz;
    static tchar **body;
    static char **bodycache;
    static bool allfiles;
    static int filecnt;
    static uint nextfile;
    static uint startfile;
    static atomic<ulong> usec, tusec,	count, tcount;
    static vector<LoadCmd *> cmds;

    int onStart(void);
    static bool expand(tchar *str, const attrmap &amap = vars);
    static const tchar *format(ulong u);
    static const tchar *format(float f);
    static char *load(uint idx, usec_t &iousec);
    static void add(const tchar *file);
    static uint next(void);
};

Lock HTTPLoad::lock;
Condvar HTTPLoad::cv(lock);
tchar HTTPLoad::format_buf[32];
uint HTTPLoad::threads;
ulong HTTPLoad::muser;
uint HTTPLoad::mthread;
bool HTTPLoad::dbg, HTTPLoad::ka, HTTPLoad::ruser;
atomic_long HTTPLoad::remain;
uint HTTPLoad::to;
attrmap HTTPLoad::hdrs;
attrmap HTTPLoad::vars;
uint HTTPLoad::bodycnt;
ulong *HTTPLoad::bodysz;
tchar **HTTPLoad::body;
char **HTTPLoad::bodycache;
ulong HTTPLoad::bodycachesz;
bool HTTPLoad::allfiles;
int HTTPLoad::filecnt;
uint HTTPLoad::nextfile;
uint HTTPLoad::startfile;
atomic<ulong> HTTPLoad::usec, HTTPLoad::tusec;
atomic<ulong> HTTPLoad::count, HTTPLoad::tcount;
vector<HTTPLoad::LoadCmd *> HTTPLoad::cmds;

bool HTTPLoad::expand(tchar *str, const attrmap &amap) {
    tchar *p;
    attrmap::const_iterator it;
    tstring::size_type len;

    while ((p = tstrstr(str, T("$("))) != NULL) {
	tchar *end = tstrchr(p, ')');

	if (p != str && p[-1] == '$') {	    // $$() -> $()
	    memmove(p - 1, p, tstrlen(p) + 1);
	} else if (!end) {
	    return false;
	} else {
	    *end++ = '\0';
	    if ((it = amap.find(p + 2)) == amap.end())
		return false;
	    len = it->second.size();
	    memmove(p + len, end, tstrlen(end) + 1);
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
    const tchar *cmd, *req, *arg, *data = NULL, *value = NULL, *status = NULL;
    tchar *p;
    tifstream is(file);
    int len;
    LoadCmd *lcmd;
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
    bodycachesz = (loops == 1) ? 0 : cachesz;
    filecnt = fcnt;
    if (!is) {
	tcerr << T("invalid file: ") << file << endl;
	return false;
    }
    if (bodyfile) {
	struct stat sbuf;
	DIR *dir;

	if ((dir = opendir(tchartoachar(bodyfile))) != NULL) {
	    const struct dirent *ent;

	    while (readdir(dir) != NULL)
		bodycnt++;
	    rewinddir(dir);
	    while ((ent = readdir(dir)) != NULL) {
		tstring s(bodyfile);

		if (*ent->d_name == '.')
		    continue;
		s += '/';
		s += achartotstring(ent->d_name);
		add(s.c_str());
	    }
	    closedir(dir);
	} else if (stat(tchartoachar(bodyfile), &sbuf) != -1 && sbuf.st_mode &
	    S_IFREG) {
	    bodycnt = 1;
	    add(bodyfile);
	} else {
	    tcerr << T("invalid body file: ") << bodyfile << endl;
	    return false;
	}
    }
    if (allfiles && bodycnt > 0) {
	lock.lock();
	if (filecnt > 0 && (uint)filecnt < bodycnt)
	    bodycnt = (uint)filecnt;
	else if (filecnt < 0 && uint(-1 * filecnt) < bodycnt)
	    startfile = bodycnt - (uint)(-1 * filecnt);
	nextfile = startfile;
	remain *= (bodycnt - startfile);
	lock.unlock();
    }
    vars[T("host")] = host;
    while (is.getline(buf, (streamsize)(sizeof (buf) / sizeof (tchar)))) {
	line++;
	if (!buf[0] || buf[0] == '#' || buf[0] == '/')
	    continue;
	if (!expand(buf)) {
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
	    if (!tstricmp(cmd, T("hdr")))
		hdrs[attr] = val;
	    else
		vars[attr] = val;
	    continue;
	}
	if (!tstricmp(cmd, T("get")) || !tstricmp(cmd, T("post"))) {
	    arg = tstrtok(NULL, T(" \t"));
	    req = tstrtok(NULL, T(" \t"));
	    if (!tstricmp(cmd, T("post")))
		data = tstrtok(NULL, T(" \t"));
	    status = tstrtok(NULL, T(" \t"));
	    if (!status)
		status = T("200");
	    value = tstrtok(NULL, T(""));
	    if (!url.set(req)) {
		tcerr << T("invalid url: line ") << line << endl;
		return false;
	    }
	} else if (!tstricmp(cmd, T("sleep"))) {
	    arg = tstrtok(NULL, T(" \t"));
	} else {
	    tcerr << T("invalid cmd: line ") << line << endl;
	    return false;
	}
	if (arg && arg - buf == len)
	    arg = NULL;
	if (!arg && !bodycnt &&
	    (!tstricmp(cmd, T("body")) || !tstricmp(cmd, T("data")))) {
	    tcerr << T("missing text for ") << cmd << endl;
	    return false;
	}
	if (!addr.set(url.host.c_str(), url.port)) {
	    tcerr << T("invalid host: line ") << line << endl;
	    return false;
	}
	lcmd = new LoadCmd(cmd, arg, url, data, status, value);
	lcmd->addr = addr;
	cmds.push_back(lcmd);
    }
    return true;
}

char *HTTPLoad::load(uint idx, usec_t &iousec) {
    int fd;
    char *ret = NULL;
    const tchar *file = body[idx];
    ulong filelen = bodysz[idx];

    if (bodycache[idx]) {
	iousec = 0;
	return bodycache[idx];
    }
    iousec = uticks();
    if ((fd = open(tchartoachar(file), O_RDONLY|O_BINARY|O_SEQUENTIAL)) != -1) {
	ret = new char[(size_t)filelen + 1];
	if (::read(fd, ret, filelen) == (int)filelen) {
	    ret[filelen] = '\0';
	    if (filelen <= bodycachesz) {
		bodycache[idx] = ret;
		bodycachesz -= filelen;
	    }
	} else {
	    delete [] ret;
	    ret = NULL;
	}
	close(fd);
    }
    if (!ret)
	tcerr << T("unable to read body file: ") << file << endl;
    iousec = uticks() - iousec;
    return ret;
}

void HTTPLoad::add(const tchar *file) {
    struct stat sbuf;

    if (!body) {
	body = new tchar *[bodycnt];
	bodycache = new char *[bodycnt];
	bodysz = new ulong[bodycnt];
	bodycnt = 0;
    }
    ZERO(sbuf);
    if (access(tchartoachar(file), R_OK) || stat(tchartoachar(file), &sbuf)) {
	tcerr << T("invalid body file: ") << file << endl;
    } else {
	body[bodycnt] = new tchar[tstrlen(file) + 1];
	tstrcpy(body[bodycnt], file);
	bodycache[bodycnt] = NULL;
	bodysz[bodycnt] = (ulong)sbuf.st_size;
	bodycnt++;
    }
}

uint HTTPLoad::next() {
    uint ret;

    lock.lock();
    ret = nextfile++;
    if (nextfile >= bodycnt)
	nextfile = startfile;
    lock.unlock();
    return ret;
}

int HTTPLoad::onStart(void) {
    usec_t start, end, last, now, io;
    tchar buf[1024], data[4096];
    HTTPClient hc;
    tofstream fs;
    attrmap lvars;
    ulong diff;
    tstring s;
    vector<tstring> cookies;
    vector<tstring>::const_iterator cit;
    vector<LoadCmd *>::const_iterator it;
    attrmap::const_iterator ait;

    if (dbg)
	fs.open("debug.out", ios::trunc | ios::out);
    srand((uint)(id ^ ((uticks() >> 32 ^ (msec_t)time(NULL)))));
    if (id > Processor::count())
	msleep((ulong)rand() % 1000U * ((mthread / 20) + 1));
    while (!qflag) {
	const tchar *p;
	ulong smsec = 0;
	bool ret;
	HTTPClient::attrmap rmap;
	HTTPClient::attrmap::const_iterator rit;
	ulong tmpid = ruser ? (ulong)rand() << 14 ^ (ulong)rand() : id;
	long tmp;

	lock.lock();
	tmp = remain;
	if (remain > 0)
	    remain--;
	lock.unlock();
	if (!tmp)
	    break;
	id = tmpid ? tmpid % (muser ? muser : id) : 0;	// NOLINT
	tsprintf(data, T("%lu"), id);
	lvars[T("id")] = data;
	if ((ait = vars.find(T("user"))) == vars.end())
	    tsprintf(data, T("user_%06lu"), id);
	else
	    tsprintf(data, ait->second.c_str(), id);
	lvars[T("user")] = data;
	if ((ait = vars.find(T("pass"))) == vars.end())
	    tsprintf(data, T("pass_%06lu"), id);
	else
	    tsprintf(data, ait->second.c_str(), id);
	lvars[T("pass")] = data;
	cookies.clear();
	start = last = uticks();
	io = 0;
	for (it = cmds.begin(); it != cmds.end() && !qflag; ++it) {
	    LoadCmd *cmd = *it;

	    if (!tstricmp(cmd->cmd.c_str(), T("sleep"))) {
		ulong len;

		p = cmd->arg.c_str();
		if (*p == '%') {
		    len = tstrtoul(p + 1, NULL, 10);
		    if (len)
			len = (ulong)rand() % len;
		} else {
		    len = tstrtoul(p, NULL, 10);
		}
		smsec += len;
		msleep(len);
		last = uticks();
		io = 0;
		continue;
	    }
	    if (dbg)
		fs << T("\n\n******* ") << cmd->cmd << T(" ") << cmd->arg <<
		    T(" ") << cmd->url.fullpath() << T(" *******") << endl;
	    hc.timeout(to, to);
	    if ((ret = hc.connect(cmd->addr, ka, to)) == true) {
		if (!cookies.empty()) {
		    s.erase();
		    for (cit = cookies.begin(); cit != cookies.end(); ++cit) {
			if (!s.empty())
			    s += T("; ");
			s += *cit;
		    }
		    hc.header(T("cookie"), s);
		    if (dbg)
			fs << T("SEND Cookie: ") << s << endl;
		}
		for (ait = hdrs.begin(); ait != hdrs.end(); ++ait)
		    hc.header((*ait).first, (*ait).second);
	    }
	    if (!ret) {
		tstrcpy(buf, cmd->url.fullpath().c_str());
	    } else if (!tstricmp(cmd->cmd.c_str(), T("get"))) {
		tstrcpy(buf, cmd->url.relpath().c_str());
		expand(buf, lvars);
		ret = hc.get(buf);
	    } else if (!tstricmp(cmd->cmd.c_str(), T("post"))) {
		tstrcpy(buf, cmd->url.relpath().c_str());
		expand(buf, lvars);
		if (cmd->data.empty()) {
		    uint u = allfiles ? next() : ((uint)rand() % bodycnt);
		    char *d = load(u, io);

		    hc.header(T("content-type"), T("application/octet-stream"));
		    if (d) {
			ret = hc.post(buf, d, bodysz[u]);
			if (d != bodycache[u])
			    delete [] d;
		    }
		} else if (cmd->data.length() >= sizeof (data)) {
		    ret = false;
		} else {
		    tstrcpy(data, cmd->data.c_str());
		    expand(data, lvars);
		    hc.header(T("content-type"), T("application/x-www-form-urlencoded"));
		    ret = hc.post(buf, data, (ulong)(tstrlen(data) * sizeof (tchar)));
		}
	    }
	    now = uticks();
	    diff = (ulong)(now - last - io);
	    usec += diff;
	    last = now;
	    io = 0;
	    lock.lock();
	    cmd->complete(ret, diff);
	    lock.unlock();
	    if (!ret || (cmd->status && hc.status() != cmd->status) ||
		(!cmd->status && hc.status() != 200 && hc.status() != 302)) {
		if (ret) {
		    lock.lock();
		    cmd->error();
		    lock.unlock();
		}
		dlog << Log::Err << T("cmd=") << cmd->cmd << T(" arg=") <<
		    buf << T(" status=") << hc.status() << T(" expected=") <<
		    cmd->status << T(" duration=") << (diff / 1000) << endlog;
		break;
	    } else {
		if (dbg)
		    fs << cmd->cmd << T(" status: ") << hc.status() << endl <<
			endl;
		rmap = hc.responses();
		for (rit = rmap.begin(); rit != rmap.end(); ++rit) {
		    if (!tstrcmp(rit->first.c_str(), T("set-cookie"))) {
			tstring::size_type pos;

			s = rit->second;
			if ((pos = s.find_first_of(T(';'))) != string::npos)
			    s.erase(pos);
			if (s != T("invalid"))
			    cookies.push_back(s);
		    }
		    if (dbg)
			fs << rit->first << ": " << rit->second << endl;
		}
#ifndef UNICODE	// TODO
		if (dbg) {
		    fs << endl;
		    fs.write(hc.data(), (streamsize)hc.size());
		    fs.flush();
		}
		if (!cmd->value.empty() &&
		    tstrstr(hc.data(), cmd->value.c_str()) == NULL) {
		    dlog << Log::Err << T("cmd=") << cmd->cmd << T(" arg=") <<
			buf << T(" invalid return data") << endlog;
		    lock.lock();
		    cmd->error();
		    lock.unlock();
		    break;
		}
#endif
		if (dlog.level() >= Log::Info)
		    dlog << Log::Info << T("cmd=") << cmd->cmd << T(" arg=") <<
			buf << T(" status=") << hc.status() <<
			T(" duration=") << (diff / 1000) << endlog;
	    }
	}
	if (!ka)
	    hc.close();
	end = uticks();
	diff = (ulong)(end - start);
	lock.lock();
	tusec += diff - smsec * 1000;
	++count;
	++tcount;
	lock.unlock();
	dlog << Log::Info << T("cmd=all duration=") << (diff / 1000) << endlog;
    }
    lock.lock();
    if (!--threads)
	cv.set();
    lock.unlock();
    return 0;
}

const tchar *HTTPLoad::format(ulong u) {
    tsprintf(format_buf, T(" %7lu"), u);
    return format_buf;
}

const tchar *HTTPLoad::format(float f) {
    if (f - 0.0F < FLT_EPSILON)
	tstrcpy(format_buf, T("       0"));
    else if (f >= 100)
	tsprintf(format_buf, T(" %7lu"), (ulong)lround(f));
    else
	tsprintf(format_buf, T(" %7.2g"), (double)f);
    return format_buf;
}

static inline float round(ulong count, ulong div) {
    return div ? (float)count / ((float)div * 1.0F) : 0;
}

void HTTPLoad::print(tostream &os, usec_t last) {
    tchar buf[32];
    LoadCmd *cmd;
    vector<LoadCmd *>::const_iterator it;
    ulong lusec = (ulong)(uticks() - last);
    ulong minusec = 0, tminusec = 0, maxusec = 0, tmaxusec = 0;
    ulong ops = 0, tops = 0, err = 0, terr = 0;
    bufferstream<tchar> bs;

    bs << T("CMD     ops/sec msec/op maxmsec  errors OPS/SEC MSEC/OP  ERRORS MINMSEC MAXMSEC") << endl;
    lock.lock();
    for (it = cmds.begin(); it != cmds.end(); ++it) {
	cmd = *it;
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

void HTTPLoad::reset(bool all) {
    vector<LoadCmd *>::const_iterator it;
    LoadCmd *cmd;

    lock.lock();
    for (it = cmds.begin(); it != cmds.end(); ++it) {
	cmd = *it;
	cmd->count = 0;
	cmd->err = 0;
	cmd->usec = cmd->minusec = cmd->maxusec = 0;
	if (all) {
	    cmd->tcount = 0;
	    cmd->terr = 0;
	    cmd->tusec = cmd->tminusec = cmd->tmaxusec = 0;
	}
    }
    usec = 0;
    count = 0;
    if (all) {
	tusec = 0;
	tcount = 0;
    }
    lock.unlock();
}

void HTTPLoad::uninit(void) {
    for (uint u = 0; u < bodycnt; u++) {
	delete [] body[u];
	delete [] bodycache[u];
    }
    delete [] body;
    delete [] bodycache;
    delete [] bodysz;
    for (vector<LoadCmd *>::const_iterator it = cmds.begin(); it != cmds.end(); ++it)
	delete *it;
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
    const tchar *bodyfile = NULL;
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
    const tchar *wld = NULL;
    uint timeout = 30000;

    dlog.level(Log::Note);
    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-a"))) {
	    allfiles = true;
	    if (ttoi(argv[i + 1]) != 0)
		filecnt = ttoi(argv[++i]);
	} else if (!tstricmp(argv[i], T("-b"))) {
	    bodyfile = argv[++i];
	} else if (!tstricmp(argv[i], T("-c"))) {
	    cachesz = tstrtoul(argv[++i], NULL, 10);
	} else if (!tstricmp(argv[i], T("-d"))) {
	    debug = true;
	    unlink("debug.out");
	} else if (!tstricmp(argv[i], T("-h"))) {
	    host = argv[++i];
	} else if (!tstricmp(argv[i], T("-k"))) {
	    ka = true;
	} else if (!tstricmp(argv[i], T("-l"))) {
	    loops = ttol(argv[++i]);
	} else if (!tstricmp(argv[i], T("-m"))) {
	    maxuser = tstrtoul(argv[++i], NULL, 10);
	} else if (!tstricmp(argv[i], T("-q"))) {
	    dlog.level(Log::Level(dlog.level() - 1));
	} else if (!tstricmp(argv[i], T("-r"))) {
	    ruser = true;
	} else if (!tstricmp(argv[i], T("-s"))) {
	    stattime = tstrtoul(argv[++i], NULL, 10);
	} else if (!tstricmp(argv[i], T("-t"))) {
	    threads = (uint)tstrtoul(argv[++i], NULL, 10);
	    if (!maxuser)
		maxuser = threads;
	} else if (!tstricmp(argv[i], T("-w"))) {
	    timeout = (uint)tstrtoul(argv[++i], NULL, 10);
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
    setvbuf(stdout, NULL , _IOFBF, 4096);
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
    while ((thread = (HTTPLoad *)(ThreadGroup::MainThreadGroup.wait(
	3000))) != NULL)
	delete thread;
    HTTPLoad::uninit();
    return 0;
}
