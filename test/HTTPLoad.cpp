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

#include "stdapi.h"
#ifdef _WIN32
#include <conio.h>
#else
#include <dirent.h>
#endif
#include <ctype.h>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include "HTTPClient.h"
#include "Log.h"

typedef map<string, string> attrmap;

static volatile bool qflag = false, rflag = false;

class HTTPLoad: public Thread {
public:
    HTTPLoad(): id(threads++) {}

    static bool init(const char *host, uint maxthread,
	ulong maxuser, bool randuser, bool debug, bool keepalive, ulong timeout,
	long loops, const char *file, const char *bodyfile, ulong cachesz,
	bool all, int fcnt);
    static void print(ostream &os, usec_t last);
    static long working(void) { return threads; }
    static void reset(bool all = false);
    static void uninit(void);
    static void wait(ulong msec) { lock.lock(); cv.wait(msec); lock.unlock(); }

private:
    class LoadCmd {
    public:
	LoadCmd(const char *c, const char *a, const URL &u,
	    const char *d = NULL, const char *s = NULL, const char *v = NULL):
	    cmd(c), arg(a), data(d ? d : ""), value(v ? v : ""),
	    status(s ? (ushort)atoi(s) : 200), url(u), usec(0), tusec(0),
	    minusec(0), tminusec(0), maxusec(0), tmaxusec(0),
	    count(0), tcount(0), err(0), terr(0) {}

	string cmd, arg, data, value;
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
    static ulong muser;
    static uint mthread;
    static ulong to;
    static volatile long remain;
    static ulong threads;
    static attrmap hdrs, vars;
    static uint bodycnt, *bodysz;
    static ulong bodycachesz;
    static char **body, **bodycache;
    static bool allfiles;
    static int filecnt;
    static uint nextfile;
    static uint startfile;
    static TSNumber<ulong> usec, tusec, minusec, tminusec, maxusec, tmaxusec,
	count, tcount;
    static vector<LoadCmd *> cmds;

    int onStart(void);
    static bool expand(char *str, const attrmap &amap = vars);
    static char *read(uint index, usec_t &iousec);
    static void add(const char *file);
    static uint next(void);
};

Lock HTTPLoad::lock;
Condvar HTTPLoad::cv(lock);
ulong HTTPLoad::threads;
ulong HTTPLoad::muser;
uint HTTPLoad::mthread;
bool HTTPLoad::dbg, HTTPLoad::ka, HTTPLoad::ruser;
volatile long HTTPLoad::remain;
ulong HTTPLoad::to;
attrmap HTTPLoad::hdrs;
attrmap HTTPLoad::vars;
uint HTTPLoad::bodycnt;
uint *HTTPLoad::bodysz;
char **HTTPLoad::body;
char **HTTPLoad::bodycache;
ulong HTTPLoad::bodycachesz;
bool HTTPLoad::allfiles;
int HTTPLoad::filecnt;
uint HTTPLoad::nextfile;
uint HTTPLoad::startfile;
TSNumber<ulong> HTTPLoad::usec, HTTPLoad::tusec;
TSNumber<ulong> HTTPLoad::minusec, HTTPLoad::tminusec;
TSNumber<ulong> HTTPLoad::maxusec, HTTPLoad::tmaxusec;
TSNumber<ulong> HTTPLoad::count, HTTPLoad::tcount;
vector<HTTPLoad::LoadCmd *> HTTPLoad::cmds;

bool HTTPLoad::expand(char *str, const attrmap &amap) {
    char *p;
    attrmap::const_iterator it;
    string::size_type len;

    while ((p = strstr(str, "$(")) != NULL) {
	char *end = strchr(p, ')');

	if (p != str && p[-1] == '$') {	    // $$() -> $()
	    memmove(p - 1, p, strlen(p) + 1);
	} else if (!end) {
	    return false;
	} else {
	    *end++ = '\0';
	    if ((it = amap.find(p + 2)) == amap.end())
		return false;
	    len = (*it).second.size();
	    memmove(p + len, end, strlen(end) + 1);
	    memcpy(p, (*it).second.c_str(), len);
	}
	str = p + 1;

    }
    return true;
}

bool HTTPLoad::init(const char *host, uint maxthread, ulong maxuser,
    bool randuser, bool debug, bool keepalive, ulong timeout, long loops,
    const char *file, const char *bodyfile, ulong cachesz, bool all,
    int fcnt) {
    ifstream is(file);
    URL url;
    char buf[1024];
    char *cmd, *req, *arg, *data = NULL, *value = NULL, *status = NULL, *p;
    int line = 0;
    int len;
    Sockaddr addr;
    LoadCmd *lcmd;

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
	cerr << "invalid file: " << file << endl;
	return false;
    }
    if (bodyfile) {
	struct stat sbuf;
	DIR *dir;
	struct dirent *ent;

	if (stat(bodyfile, &sbuf) != -1 && sbuf.st_mode & S_IFREG) {
	    bodycnt = 1;
	    add(bodyfile);
	} else if ((dir = opendir(bodyfile)) != NULL) {
	    while ((ent = readdir(dir)) != NULL)
		bodycnt++;
	    rewinddir(dir);
	    while ((ent = readdir(dir)) != NULL) {
		string s(bodyfile);

		if (*ent->d_name == '.')
		    continue;
		s += '/';
		s += ent->d_name;
		add(s.c_str());
	    }
	    closedir(dir);
	} else {
	    cerr << "invalid body file: " << bodyfile << endl;
	}
    }
    if (allfiles && bodycnt > 0) {
	if (filecnt > 0 && (uint)filecnt < bodycnt)
	    bodycnt = filecnt;
	else if (filecnt < 0 && uint(-1 * filecnt) < bodycnt)
	    startfile = bodycnt - uint(-1 * filecnt);
	nextfile = startfile;
	remain *= (bodycnt - startfile);
    }
    vars["host"] = host;
    while (is.getline(buf, sizeof (buf))) {
	line++;
	if (!buf[0] || buf[0] == '#' || buf[0] == '/')
	    continue;
	if (!expand(buf)) {
	    cerr << "variable syntax err on line " << line << ": " << buf << endl;
	    return false;
	}
	len = strlen(buf);
	cmd = strtok(buf, " \t");
	if (!stricmp(cmd, "hdr") || !stricmp(cmd, "var")) {
	    char *attr, *val;

	    attr = strtok(NULL, "=");
	    if (!attr) {
		cerr << "invalid attribute: line " << line << endl;
		return false;
	    }
	    p = attr + strlen(attr) - 1;
	    while (isspace(*p))
		*p-- = '\0';
	    if (host && !stricmp(attr, "host"))
		continue;
	    val = strtok(NULL, "");
	    if (!attr || !val) {
		cerr << "invalid value: line " << line << endl;
		return false;
	    }
	    while (*val && isspace(*val))
		val++;
	    p = val + strlen(val) - 1;
	    while (isspace(*p))
		*p-- = '\0';
	    if (!stricmp(cmd, "hdr"))
		hdrs[attr] = val;
	    else
		vars[attr] = val;
	    continue;
	}
	if (!stricmp(cmd, "get") || !stricmp(cmd, "post")) {
	    arg = strtok(NULL, " \t");
	    req = strtok(NULL, " \t");
	    if (!stricmp(cmd, "post"))
		data = strtok(NULL, " \t");
	    status = strtok(NULL, " \t");
	    value = strtok(NULL, "");
	    if (!url.set(req)) {
		cerr << "invalid url: line " << line << endl;
		return false;
	    }
	} else if (!stricmp(cmd, "sleep")) {
	    arg = strtok(NULL, " \t");
	} else {
	    cerr << "invalid sleep: line " << line << endl;
	    return false;
	}
	arg = cmd + strlen(cmd);
	if (arg - buf == len)
	    arg = NULL;
	else
	    arg++;
	if (!arg && !bodycnt &&
	    (!stricmp(cmd, "body") || !stricmp(cmd, "data"))) {
	    cerr << "missing text for " << cmd << endl;
	    return false;
	}
	if (!addr.set(url.host.c_str(), url.port)) {
	    cerr << "invalid host: line " << line << endl;
	    return false;
	}
	lcmd = new LoadCmd(cmd, arg, url, data, status, value);
	lcmd->addr = addr;
	cmds.push_back(lcmd);
    }
    return true;
}

char *HTTPLoad::read(uint idx, usec_t &iousec) {
    int fd;
    char *ret = NULL;
    char *file = body[idx];
    uint filelen = bodysz[idx];

    if (bodycache[idx]) {
	iousec = 0;
	return bodycache[idx];
    }
    iousec = uticks();
    if ((fd = open(file, O_RDONLY|O_BINARY|O_SEQUENTIAL)) != -1) {
	ret = new char [filelen + 1];
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
	cerr << "unable to read body file: " << file << endl;
    iousec = uticks() - iousec;
    return ret;
}

void HTTPLoad::add(const char *file) {
    struct stat sbuf;

    if (!body) {
	body = new char *[bodycnt];
	bodycache = new char *[bodycnt];
	bodysz = new uint[bodycnt];
	bodycnt = 0;
    }
    if (access(file, R_OK) || stat(file, &sbuf)) {
	cerr << "invalid body file: " << file << endl;
    } else {
	body[bodycnt] = new char [strlen(file) + 1];
	strcpy(body[bodycnt], file);
	bodycache[bodycnt] = NULL;
	bodysz[bodycnt] = sbuf.st_size;
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
    char buf[1024], data[1024];
    HTTPClient hc;
    ofstream fs;
    attrmap lvars;
    ulong diff;
    string s;
    vector<string> cookies;
    vector<string>::const_iterator cit;
    vector<LoadCmd *>::const_iterator it;
    attrmap::const_iterator ait;

    if (dbg)
	fs.open("debug.out", ios::trunc | ios::out);
    srand(id ^ ((uint)(uticks() >> 32 ^ time(NULL))));
    if (mthread > 1)
	msleep(rand() % 1000 * ((mthread / 20) + 1));
    while (!qflag) {
	const char *p;
	ulong smsec = 0;
	bool ret = false;
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
	id = tmpid ? tmpid % (muser ? muser : id) : 0;
	sprintf(data, "%lu", id);
	lvars["id"] = data;
	if ((ait = vars.find("user")) == vars.end())
	    sprintf(data, "user_%06lu", id);
	else
	    sprintf(data, (*ait).second.c_str(), id);
	lvars["user"] = data;
	if ((ait = vars.find("pass")) == vars.end())
	    sprintf(data, "pass_%06lu", id);
	else
	    sprintf(data, (*ait).second.c_str(), id);
	lvars["pass"] = data;
	cookies.clear();
	start = last = uticks();
	io = 0;
	for (it = cmds.begin(); it != cmds.end() && !qflag; it++) {
	    LoadCmd *cmd = *it;

	    if (!stricmp(cmd->cmd.c_str(), "sleep")) {
		ulong len;

		p = cmd->arg.c_str();
		if (*p == '%')
		    len = rand() % strtoul(p + 1, NULL, 10);
		else
		    len = strtoul(p, NULL, 10);
		smsec += len;
		msleep(len);
		last = uticks();
		io = 0;
		continue;
	    }
	    if (dbg)
		fs << "\n\n******* " << cmd->cmd << " " << cmd->arg << " " <<
		cmd->url.fullpath() << " *******" << endl;
	    if ((ret = hc.connect(cmd->addr, ka, to)) == true) {
		if (!cookies.empty()) {
		    s.erase();
		    for (cit = cookies.begin(); cit != cookies.end(); cit++) {
			if (!s.empty())
			    s += "; ";
			s += *cit;
		    }
		    hc.header("cookie", s);
		    if (dbg)
			fs << "SEND Cookie: " << s << endl;
		}
		for (ait = hdrs.begin(); ait != hdrs.end(); ait++)
		    hc.header((*ait).first, (*ait).second);
	    }
	    if (!ret) {
	    } else if (!stricmp(cmd->cmd.c_str(), "get")) {
		strcpy(buf, cmd->url.relpath().c_str());
		expand(buf, lvars);
		ret = hc.get(buf);
	    } else if (!stricmp(cmd->cmd.c_str(), "post")) {
		strcpy(buf, cmd->url.relpath().c_str());
		expand(buf, lvars);
		if (cmd->data.empty()) {
		    uint u = allfiles ? next() : (rand() % bodycnt);
		    char *d = read(u, io);

		    hc.header("content-type", "application/octet-stream");
		    if (d) {
			ret = hc.post(buf, d, bodysz[u]);
			if (d != bodycache[u])
			    delete [] d;
		    }
		} else {
		    strcpy(data, cmd->data.c_str());
		    expand(data, lvars);
		    hc.header("content-type", "application/x-www-form-urlencoded");
		    ret = hc.post(buf, data, strlen(data));
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
		dlog << Log::Err << "cmd=" << cmd->cmd << " arg=" << buf <<
		    " status=" << hc.status() << " expected=" << cmd->status <<
		    " duration=" << (diff / 1000) << endlog;
		break;
	    } else {
		if (dbg)
		    fs << cmd->cmd << " status: " << hc.status() << endl << endl;
		rmap = hc.responses();
		for (rit = rmap.begin(); rit != rmap.end(); rit++) {
		    if (!strcmp((*rit).first.c_str(), "set-cookie")) {
			string::size_type pos;

			s = (*rit).second;
			if ((pos = s.find_first_of(";")) != string::npos)
			    s.erase(pos);
			if (s != "invalid")
			    cookies.push_back(s);
		    }
		    if (dbg)
			fs << (*rit).first << ": " << (*rit).second << endl;
		}
		if (dbg) {
		    fs << endl;
		    fs.write(hc.data(), hc.size());
		    fs.flush();
		}
		if (!cmd->value.empty() &&
		    strstr(hc.data(), cmd->value.c_str()) == NULL) {
		    dlog << Log::Err << "cmd=" << cmd->cmd << " arg=" <<
			buf << " invalid return data" << endlog;
		    lock.lock();
		    cmd->error();
		    lock.unlock();
		    break;
		}
		if (dlog.level() >= Log::Info)
		    dlog << Log::Info << "cmd=" << cmd->cmd << " arg=" << buf <<
			" status=" << hc.status() <<
			" duration=" << (diff / 1000) << endlog;
	    }
	}
	if (!ka)
	    hc.close();
	end = uticks();
	diff = (ulong)(end - start);
	lock.lock();
	tusec += diff - smsec * 1000;
	count++;
	tcount++;
	if (!minusec || diff < minusec)
	    minusec = diff;
	if (diff > maxusec)
	    maxusec = diff;
	if (!tminusec || diff < tminusec)
	    tminusec = diff;
	if (diff > tmaxusec)
	    tmaxusec = diff;
	lock.unlock();
	dlog << Log::Info << "cmd=all duration=" << (diff / 1000) << endlog;
    }
    lock.lock();
    if (!--threads)
	cv.set();
    lock.unlock();
    return 0;
}

inline string format(ulong u) {
    char buf[16];

    sprintf(buf, " %7lu", u);
    return buf;
}

inline string format(float f) {
    char buf[16];

    if (f == 0)
	strcpy(buf, "       0");
    else if (f >= 100)
	sprintf(buf, " %7u", (unsigned)(f + .5));
    else
	sprintf(buf, " %7.2f", f);
    return buf;
}

inline float round(ulong count, ulong div) {
    return div ? (float)(count / (div * 1.0)) : 0;
}

void HTTPLoad::print(ostream &out, usec_t last) {
    LoadCmd *cmd;
    vector<LoadCmd *>::const_iterator it;
    ulong lusec = (ulong)(uticks() - last);
    ulong minusec = 0, tminusec = 0, maxusec = 0, tmaxusec = 0;
    ulong ops = 0, tops = 0, err = 0, terr = 0, calls = 0;
    bufferstream os;

    os << "CMD\t ops/sec msec/op maxmsec    errs OPS/SEC MSEC/OP    ERRS MINMSEC MAXMSEC" << endl;
    lock.lock();
    for (it = cmds.begin(); it != cmds.end(); it++) {
	cmd = *it;
	if (!stricmp(cmd->cmd.c_str(), "sleep"))
	    continue;
	calls++;
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
	os << cmd->cmd << "\t" << format(round(cmd->count, lusec) * 1000000) <<
	    format(round(cmd->usec, cmd->count) / 1000) <<
	    format(cmd->maxusec / 1000) << format(cmd->err) <<
	    format(round(cmd->tcount, tusec) * 1000000) <<
	    format(round(cmd->tusec, cmd->tcount) / 1000) <<
	    format(cmd->terr) << format(cmd->tminusec / 1000) <<
	    format(cmd->tmaxusec / 1000) << endl;
    }
    lock.unlock();
    os << "ALL\t" << format(round(count, lusec) * 1000000) <<
	format(round(usec, count) / 1000) <<
	format(maxusec / 1000) << format(err) <<
	format(round(tcount, tusec) * 1000000) <<
	format(round(tusec, tcount) / 1000) << format(terr) <<
	format(tminusec / 1000) << format(tmaxusec / 1000) << endl;
    os << "AVG/TOT\t" << format(round(ops, lusec) * 1000000) <<
	format(round(usec, ops) / 1000) << format(maxusec / 1000) <<
	format(err) << format(round(tops, tusec) * 1000000) <<
	format(round(tusec, tops) / 1000) << format(terr) <<
	format(tminusec / 1000) << format(tmaxusec / 1000) << endl << endl;
    out.write(os.str(), os.pcount());
    out.flush();
}

void HTTPLoad::reset(bool all) {
    vector<LoadCmd *>::const_iterator it;
    LoadCmd *cmd;

    for (it = cmds.begin(); it != cmds.end(); it++) {
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
    usec = minusec = maxusec = 0;
    count = 0;
    if (all) {
	tusec = tminusec = tmaxusec = 0;
	tcount = 0;
    }
}

void HTTPLoad::uninit(void) {
    for (uint u = 0; u < bodycnt; u++) {
	delete [] body[u];
	delete [] bodycache[u];
    }
    delete [] body;
    delete [] bodycache;
    delete [] bodysz;
    for (vector<LoadCmd *>::const_iterator it = cmds.begin(); it != cmds.end(); it++)
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

int main(int argc, char *argv[]) {
    bool allfiles = false;
    const char *bodyfile = NULL;
    ulong cachesz = 64;
    bool debug = false;
    bool first = true;
    int filecnt = 0;
    ofstream fs;
    const char *host = "localhost:80";
    int i;
    bool ka = false;
    usec_t last;
    long loops = 1;
    ulong maxuser = 0;
    bool ruser = false;
    string s;
    ulong stattime = 3000;
    HTTPLoad *thread;
    int threads = 1;
    bool wflag = false;
    const char *wld = NULL;
    ulong timeout = 30000;

    dlog.level(Log::Note);
    for (i = 1; i < argc; i++) {
	if (!stricmp(argv[i], "-a")) {
	    allfiles = true;
	    if (atoi(argv[i + 1]) != 0)
		filecnt = atoi(argv[++i]);
	} else if (!stricmp(argv[i], "-b")) {
	    bodyfile = argv[++i];
	} else if (!stricmp(argv[i], "-c")) {
	    cachesz = strtoul(argv[++i], NULL, 10);
	} else if (!stricmp(argv[i], "-d")) {
	    debug = true;
	    unlink("debug.out");
	} else if (!stricmp(argv[i], "-h")) {
	    host = argv[++i];
	} else if (!stricmp(argv[i], "-k")) {
	    ka = true;
	} else if (!stricmp(argv[i], "-l")) {
	    loops = atol(argv[++i]);
	} else if (!stricmp(argv[i], "-m")) {
	    maxuser = strtoul(argv[++i], NULL, 10);
	} else if (!stricmp(argv[i], "-q")) {
	    dlog.level(Log::Level(dlog.level() - 1));
	} else if (!stricmp(argv[i], "-r")) {
	    ruser = true;
	} else if (!stricmp(argv[i], "-s")) {
	    stattime = strtoul(argv[++i], NULL, 10);
	} else if (!stricmp(argv[i], "-t")) {
	    threads = atoi(argv[++i]);
	    if (!maxuser)
		maxuser = threads;
	} else if (!stricmp(argv[i], "-w")) {
	    timeout = strtoul(argv[++i], NULL, 10);
	} else if (!stricmp(argv[i], "-v")) {
	    dlog.level(Log::Level(dlog.level() + 1));
	 } else if (!wld && *argv[i] != '-') {
	     wld = argv[i];
	 } else {
	     break;
	}
    }
    if (argc == 1 || i < argc) {
	const char *program = strrchr(argv[0], '/');

	if (!program)
	    program = strrchr(argv[0], '\\');
	cerr << "usage: " << (program ? program + 1 : argv[0]) <<
	    " [-a [numfiles]] [-b bodyfile|bodydir] [-c cachemb] [-d]\n"
	    "\t[-h host[:port]] [-k] [-l loops] [-m maxuser] [-q|-v]* [-r]\n"
	    "\t[-s stattime] [-t threads] [-w timeout] cmdfile" << endl;
	return 1;
    }
    setvbuf(stdout, NULL , _IOFBF, 4096);
    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    if (!wld)
	wld = "web.wld";
    if (!HTTPLoad::init(host, threads, maxuser, ruser, debug, ka, timeout,
	loops, wld, bodyfile, cachesz * 1024 * 1024, allfiles, filecnt))
	return -1;
    dlog << Log::Info << "test " << host << " " << wld <<
	" (" << threads << " thread" << (threads == 1 ? "" : "s") << ", " <<
	loops << " loop" << (loops == 1 ? "" : "s") << ")" << endlog;
    for (i = 0; i < threads; i++) {
	thread = new HTTPLoad;
	thread->start(32 * 1024);
    }
    do {
	last = uticks();
	HTTPLoad::wait(stattime);
#ifdef _WIN32
	while (kbhit()) {
	    switch (getch()) {
	    case 'q': qflag = true;
		break;
	    case 'r': rflag = true;
		break;
	    case 'w': wflag = true;
		break;
	    case '?': cout << "(q)uit (r)eset (w)rite" << endl;
		break;
	    }
	}
#endif
	if (qflag) {
	    break;
	} else if (first && threads > 1 && HTTPLoad::working()) {
	    first = false;
	    HTTPLoad::reset(true);
	} else if (rflag) {
	    rflag = false;
	    HTTPLoad::reset(true);
	    cout << "*** RESET STATISTICS ***" << endl << endl;
	} else {
	    HTTPLoad::print(cout, last);
	    if (wflag) {
		wflag = false;
		cout << "Comment: ";
		getline(cin, s);
		if (!fs.is_open())
		    fs.open("load.dat", ios::out | ios::app);
		fs << "**** " << s << " ****" << endl;
		HTTPLoad::print(fs, last);
		fs << endl << endl;
	    }
	    HTTPLoad::reset(false);
	}
    } while (!qflag && HTTPLoad::working());
    dlog.level(Log::None);
    if (fs.is_open())
	fs.close();
    while ((thread = (HTTPLoad *)ThreadGroup::MainThreadGroup.wait(3000)) != NULL)
	delete thread;
    HTTPLoad::uninit();
    return 0;
}
