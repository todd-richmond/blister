#include "stdapi.h"
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>
#ifndef _WIN32
#include <dirent.h>
#include <sys/file.h>
#endif
#ifndef _WIN32_WCE
#include <sys/stat.h>
#endif
#include "Config.h"
#include "Log.h"
#include "SMTPClient.h"

#if defined(_WIN32) && !defined(_WIN32_WCE)
#pragma comment(lib, "user32.lib")
#endif

static const tchar *SSubst = T("\001\001");
static const tchar *ZSubst = T("\002\002");

const tchar * const Log::LevelStr[] = { T("none"), T("emrg"), T("alrt"),
    T("crit"), T("err"), T("warn"), T("rprt"), T("note"), T("info"),
    T("debg"), T("trce"), T("sprs") };
const tchar * const Log::LevelStr2[] = { T("nothing"), T("emergency"),
    T("alert"), T("critical"), T("error"), T("warning"), T("report"),
    T("notice"), T("information"), T("debug"), T("trace"), T("suppress") };


// UNIX loaders may try to construct static objects > 1 time
static Log &_dlog(void) {
    static Log __dlog;

    return __dlog;
}

Log &dlog = _dlog();

const uchar Log::kv::mustquote[256] = {
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // NUL - SI
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // DLE - US
    1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // SPACE - /
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0 - ?
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // @ - O
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,  // P - _
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // ` - o
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  // p - DEL
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // high bits
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // high bits
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // high bits
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // high bits
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // high bits
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // high bits
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // high bits
    1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // high bits
};

void Log::kv::set(const tchar *key, const tchar *val) { 
    const tchar *p;

    s = key;
    s += '=';
    if (!val)
	return;
    for (p = val; *p; p++) {
	if (mustquote[(uchar)*p]) {
	    s += '"';
	    for (p = val; *p; p++) {
		if (*p == '"') {
		    s += T("\\\"");
		} else if (*p == '\\') {
		    s += T("\\\\");
		} else if (*p == '\n') {
		    s += T("\\n");
		} else if (*p == '\r') {
		    s += T("\\r");
		} else if ((uchar)*p < ' ' && *p != '\t') {
		    tchar tmp[5];

		    sprintf(tmp, "\\%03o", *p);
		    s += tmp;
		} else {
		    s += *p;
		}
	    }
	    s += '"';
	    return;
	}
    }
    s += val;
}

int Log::FlushThread::onStart(void) {
    Locker lkr(l.lck);

    while (!qflag) {
	l.cv.wait(l.buftm ? l.buftm : INFINITE);
	l._flush();
    }
    return 0;
}

bool Log::LogFile::close(void) {
    len = 0;
    if (fd < 0)
	return false;
    unlock();
    ::close(fd);
    fd = -1;
    return true;
}

void Log::LogFile::lock() {
    if (fd == -1)
	reopen();
    if (fd >= 0 && !locked) {
	len = lockfd(fd);
	if (len == (ulong)-1) {
	    close();
	    fd = -3;
	    cerr << T("unable to lock log ") << path << endl;
	} else {
	    locked = true;
	}
    }
}

ulong Log::LogFile::lockfd(int fd) {
    ulong len;

    if (fd < 0)
	return 0;
    if (lockfile(fd, F_WRLCK, SEEK_SET, 0, 0, 0) ||
	(len = (ulong)lseek(fd, 0, SEEK_END)) == (ulong)-1)
	return (ulong)-1;
    return len;
}

void Log::LogFile::print(const char *buf, size_t sz) {
    if (fd < 0) {
#ifdef _WIN32_WCE
	OutputDebugString(buf);
#else
	if (fd == -2) {
	    tcout.write(buf, sz);
	    tcout.flush();
	} else if (fd == -3) {
	    tcerr.write(buf, sz);
	    tcerr.flush();
	} else if (fd == -4) {
#ifdef _WIN32
	    MessageBox(NULL, buf, NULL, MB_OK | MB_ICONWARNING |
		MB_SETFOREGROUND);
#endif
	}
#endif
    } else {
	write(fd, buf, sz);
	if (file[0] != '>')
	    len += sz;
    }
}

bool Log::LogFile::reopen(void) {
    bool ret = true;

    close();
    if ((fd = ::open(tstringtoa(path).c_str(),
	O_WRONLY | O_CREAT | O_BINARY | O_SEQUENTIAL, 0640)) == -1) {
	cerr << T("unable to open log ") << path << endl;
	fd = -3;
	ret = false;
    } else {
	lock();
	if (!len && path != file) {
	    char buf[1024];
	    time_t now = ::time(NULL);
	    string s(path);
	    struct tm tmbuf, *tm = gmt ? gmtime_r(&now, &tmbuf) :
		localtime_r(&now, &tmbuf);

	    tstrftime(buf, sizeof (buf), file.c_str(), tm);
	    link(path.c_str(), buf);
	}
    }
    return ret;
}

void Log::LogFile::roll(void) {
    char buf[1024];
    DIR *dir;
    struct dirent *ent;
    uint files = 0;
    time_t now;
    string oldfile;
    string::size_type pos;
    string s1, s2, s3;
    struct stat sbuf;
    char sep;

    close();
    if (!enable)
	return;
    lock();
    now = cnt && !tm && fstat(fd, &sbuf) == 0 ? (time_t)sbuf.st_ctime :
	::time(NULL);
    s1 = path;
    if ((pos = s1.rfind('/')) == s1.npos && (pos = s1.rfind('\\')) == s1.npos) {
	sep = '/';
	s2 = s1;
	s1.erase();
    } else {
	sep = s1[pos];
	s2 = s1.substr(pos + 1);
	s1.erase(pos);
    }
    if ((dir = opendir(s1.empty() ? "." : s1.c_str())) != NULL) {
	for (;;) {
	    ulong oldtime = (ulong)-1;

	    files = 0;
	    while ((ent = readdir(dir)) != NULL) {
		if (strncmp(ent->d_name, s2.c_str(), s2.size()) ||
		    (path == ent->d_name && path != file))
		    continue;
		if (s1.empty()) {
		    s3 = ent->d_name;
		} else {
		    s3 = s1;
		    s3 += sep;
		    s3 += ent->d_name;
		}
		if ((s3 == path && path != file))
		    continue;
		files++;
		if (stat(s3.c_str(), &sbuf) == 0 &&
		    (ulong)sbuf.st_mtime < (ulong)oldtime) {
		    oldfile = s3;
		    oldtime = (time_t)sbuf.st_mtime;
		}
	    }
	    if (oldtime == (ulong)-1) {
		break;
	    } else if ((cnt && files >= cnt &&
		(!tm || oldtime < (ulong)(now - tm))) ||
		(tm && oldtime < (ulong)(now - tm)) && (!cnt || files >= cnt)) {
		unlink(oldfile.c_str());
		files--;
		rewinddir(dir);
	    } else {
		break;
	    }
	}
	closedir(dir);
    }
    if (cnt && path == file) {
	sprintf(buf, ".%u", files);
	s1 = file + buf;
	for (uint u = files; u > 1; u--) {
	    unlink(s1.c_str());
	    sprintf(buf, ".%u", u - 1);
	    s2 = file + buf;
	    rename(s2.c_str(), s1.c_str());
	    s1 = s2;
	}
	rename(file.c_str(), s1.c_str());
    } else if (path != file) {
	unlink(path.c_str());
    }
    close();
    lock();
}

void Log::LogFile::set(const Config &cfg, const tchar *sect,
    const tchar *sub, bool denable, const tchar *dlvl, const tchar *dfile) {
    tstring f, s(sub);

    s += '.';
    cnt = cfg.get((s + T("count")).c_str(), 0, sect);
    f = cfg.get((s + T("name")).c_str(), dfile, sect);
    gmt = cfg.get(T("gmt"), false, sect);
    lvl = str2enum(cfg.get((s + T("level")).c_str(), dlvl, sect).c_str());
    sz = cfg.get((s + T("size")).c_str(), 10 * 1024 * 1024L, sect);
    tm = cfg.get((s + T("time")).c_str(), 0L, sect);
    set(lvl, f.c_str(), cnt, sz, tm);
    if (fd == -1 && !tstrchr(file.c_str(), '/') &&
	!tstrchr(file.c_str(), '\\')) {
	string dir(cfg.get(T("installdir")));

	if (!dir.empty()) {
	    dir += T("/log");
	    if (access(tstringtoa(dir).c_str(), 0))
		dir = cfg.get(T("installdir"));
	    dir += T("/");
	    file = dir + file;
	    path = dir + path;
	}
    }
    enable = cfg.get((s + T("enable")).c_str(), denable, sect);
}

void Log::LogFile::set(Level l, const tchar *f, uint c, ulong s, ulong t) {
    enable = true;
    lvl = l;
    if (!f)
	return;
    cnt = c;
    sz = s;
    tm = t;
    if (file == f)
	return;
    close();
    file = path = f;
    if (file == T("stdout") || file == T("cout")) {
	fd = -2;
    } else if (file == T("stderr") || file == T("cerr")) {
	fd = -3;
    } else if (file == T("console")) {
	fd = -4;
    } else if (file[0] == '>') {
	fd = atoi(file.c_str() + 1);
    } else {
	const char *p;

	fd = -1;
	if ((p = strchr(path.c_str(), '%')) != NULL) {
	    if (p[-1] == '.')
		p--;
	    path.erase(p - path.c_str());
	}
    }
    len = 0;
}

void Log::LogFile::unlockfd(int fd) {
    if (fd >= 0)
	lockfile(fd, F_UNLCK, SEEK_SET, 0, 0, 0);
}

Log::Log(Level level): afd(false, Err, T("stderr"), true),
    ffd(true, Info, T("stdout"), true),
    bufenable(false), mailenable(false), syslogenable(false),
    bufsz(32 * 1024), buftm(1000), gmt(false), mp(true),
    lvl(level), maillvl(None), sysloglvl(None),
    syslogfac(1), syslogsock(SOCK_DGRAM), _type(Simple), cv(lck), ft(*this)  {
    format(T("[%Y-%m-%d %H:%M:%S.%s %z]"));
}

Log::~Log() {
    stop();
    close();
}

void Log::alert(Level l, const tchar *f, uint cnt, ulong sz, ulong tm) {
    Locker lkr(lck);

    afd.set(l, f, cnt, sz, tm);
}

void Log::buffer(bool enable) {
    bufenable = !mp && enable;
    if (bufenable)
	start();
    else
	stop();
}

bool Log::close(void) {
    flush();
    afd.close();
    return ffd.close();
}

void Log::endlog(Tlsdata *tlsd, Level clvl) {
    uint lvllen, tmlen;
    time_t now_sec;
    usec_t now_usec;
    string &strbuf(tlsd->strbuf);
    size_t sz = tlsd->strm.size();
    tchar tmp[8];
    static tstring::size_type spos;
    static tstring::size_type zpos;
    static tchar tbuf[96];
    static time_t last_sec;
    static usec_t last_usec;
    static char gmtoff[8];

    if (tlsd->clvl == Suppress)
	return;
    lck.lock();
    if (ffd.enable && clvl <= ffd.lvl) {
	ffd.lock();
	if (ffd.len + bufstrm.size() >= ffd.sz) {
	    if (!ffd.mp || (ffd.reopen() && ffd.len + bufstrm.size() >= ffd.sz)) {
		_flush();
		ffd.roll();
	    }
	}
    }
    if (afd.enable && clvl <= afd.lvl) {
	afd.lock();
	if (afd.len >= afd.sz)
	    afd.roll();
    }
    now_usec = microtime();
    if (now_usec > last_usec - 1000000 && now_usec <= last_usec)
	now_usec = last_usec + 1;
    last_usec = now_usec;
    now_sec = (uint)(now_usec / 1000000);
    if (now_sec != last_sec) {
	struct tm tmbuf, *tm;

	tm = gmt ? gmtime_r(&now_sec, &tmbuf) : localtime_r(&now_sec, &tmbuf);
	tstrftime(tbuf, sizeof (tbuf), fmt.c_str(), tm);
	strbuf = tbuf;
	spos = strbuf.find(SSubst);
	if ((zpos = strbuf.find(ZSubst)) != strbuf.npos) {
	    struct tm tmbuf2, *tm2;
	    int diff;

	    memcpy(&tmbuf, tm, sizeof (tmbuf));
	    tm = &tmbuf;
	    tm2 = gmt ? localtime_r(&now_sec, &tmbuf2) : tm;
	    tm = gmt ? tm : gmtime_r(&now_sec, &tmbuf2);
	    diff = (tm2->tm_hour - tm->tm_hour) * 100 + tm2->tm_min - tm->tm_min;
	    if (tm->tm_wday != tm2->tm_wday)
		diff -= 2400 * (tm->tm_wday > tm2->tm_wday ||
		    (tm->tm_wday == 0  && tm2->tm_wday == 6) ? 1 : -1);
	    if (diff < 0)
		tsprintf(gmtoff, T("-%04d"), -1 * diff);
	    else
		tsprintf(gmtoff, T("+%04d"), diff);
	}
    }
    last_sec = now_sec;
    strbuf = tbuf;
    if (spos != strbuf.npos) {
	tsprintf(tmp, T("%06u"), (uint)(now_usec % 1000000));
	strbuf.replace(spos, 2, tmp);
    }
    if (zpos != strbuf.npos) {
	if (spos != strbuf.npos && spos < zpos)
	    zpos = strbuf.find(ZSubst);
	strbuf.replace(zpos, 2, gmtoff);
    }
    if (!strbuf.empty())
	strbuf += ' ';
    tmlen = strbuf.size();
    if (_type == KeyVal) {
	strbuf += T("ll=");
	strbuf += LevelStr[clvl];
	strbuf += ' ';
    } else if (_type != NoLevel) {
	strbuf += LevelStr[clvl];
	if (_type == Syslog)
	    strbuf += ':';
	if (clvl == Err)
	    strbuf += ' ';
	strbuf += ' ';
    }
    lvllen = strbuf.size();
    if (!tlsd->prefix.empty()) {
	strbuf += tlsd->prefix;
	if (_type == Syslog)
	    strbuf += ':';
	strbuf += ' ';
    }
    if (_type == KeyVal) {
	tstring txt;

	txt.assign(tlsd->strm.str(), sz);
	strbuf += kv(T("txt"), txt.c_str()).str();
    } else {
	for (const tchar *p = tlsd->strm.str(); sz--; p++) {
	    if (*p < ' ' && *p != '\t') {
		if (*p == '\n') {
		    strbuf += T("\\n");
		} else if (*p == '\r') {
		    strbuf += T("\\r");
		} else {
		    tsprintf(tmp, T("\\%03o"), *p);
		    strbuf += tmp;
		}
	    } else {
		strbuf += *p;
	    }
	}
    }
    tlsd->space = false;
    tlsd->strm.reset();
    strbuf += '\n';
    if (afd.enable && clvl <= afd.lvl) {
	if (src.empty()) {
	    afd.print(strbuf);
	} else {
	    string ss(strbuf.substr(0, lvllen));

	    ss += T("src=");
	    ss += src;
	    ss += ' ';
	    ss += strbuf.substr(lvllen);
	    afd.print(ss);
	}
	afd.unlock();
    }
    if (ffd.enable && clvl <= ffd.lvl) {
	if (ft.getState() == Running) {
	    bufstrm.write(strbuf.c_str(), strbuf.size());
	    if (bufstrm.size() > bufsz)
		_flush();
	} else {
	    ffd.print(strbuf);
	}
	if (mp)
	    ffd.unlock();
    }
    lck.unlock();
    strbuf.erase(strbuf.size() - 1);
    tlsd->clvl = Suppress;
#ifndef _WIN32_WCE
    if (syslogenable && clvl <= sysloglvl) {
	string ss;
	string::size_type pos;
	char buf[40], cbuf[32];
	int i = (syslogfac << 3) | (clvl - (clvl < Note ? 1 : 2));

	ctime_r(&now_sec, cbuf);
	sprintf(buf, "<%d>%.15s", i, cbuf + 4);
	ss = buf;
	if (!mailfrom.empty()) {
	    ss += ' ';
	    if (_type == KeyVal)
		ss += "nm=";
	    if ((pos = mailfrom.find_first_of('@')) == ss.npos)
		ss += tstringtoa(mailfrom);
	    else
		ss += tstringtoa(mailfrom.substr(0, pos));
	}
	if (_type == Syslog)
	    ss += ':';
	ss += ' ';
	ss += tstringtoa(strbuf.substr(tmlen));
	syslogsock.write(ss.c_str(), ss.size(), syslogaddr);
    }
    if (mailenable && clvl <= maillvl && !mailto.empty()) {
	SMTPClient smtp;

	if (smtp.connect(mailhost.c_str())) {
	    string ss(tstringtoa(mailfrom));

	    smtp.helo();
	    if (ss.find_first_of('@') == ss.npos) {
	    	ss += '@';
		ss += tstringtoa(Sockaddr::hostname());
	    }
	    smtp.from(ss.c_str());
	    smtp.to(tstringtoa(mailto).c_str());
	    smtp.subject(tstringtoa(strbuf.substr(tmlen, tmlen + 69)).c_str());
	    smtp.data(false, tstringtoa(strbuf).c_str());
	    smtp.enddata();
	    smtp.quit();
	}
    }
#endif
    tlsd->clvl = None;
}

void Log::file(Level l, const tchar *f, uint cnt, ulong sz, ulong tm) {
    Locker lkr(lck);

    _flush();
    ffd.set(l, f, cnt, sz, tm);
}

void Log::_flush(void) {
    if (bufstrm.size()) {
	ffd.print(bufstrm.str(), bufstrm.size());
	bufstrm.reset();
    }
}

void Log::format(const tchar *s) {
    tstring::size_type pos;

    fmt = s;
    if ((pos = fmt.find(T("%s"))) != fmt.npos)
	fmt.replace(pos, 2, SSubst);
#ifndef __linux__
    if ((pos = fmt.find(T("%z"))) != fmt.npos)
	fmt.replace(pos, 2, ZSubst);
#endif
}

void Log::logv(Level l, ...) {
    bool first;
    const char *p;
    Tlsdata *tlsd;
    va_list vl;

    if (l > lvl)
	return;
    first = true;
    tlsd = tls.get();
    va_start(vl, l);
    while ((p = va_arg(vl, const char *)) != NULL) {
	if (first)
	    first = false;
	else
	    tlsd->strm << ' ';
	tlsd->strm << p;
    }
    va_end(vl);
    endlog(tlsd, l);
}

void Log::mail(Level l, const tchar *to, const tchar *from, const tchar *host) {
    mailenable = true;
    maillvl = l;
    if (to) {
	mailfrom = from;
	mailhost = host;
	mailto = to;
    }
}

void Log::set(const Config &cfg, const tchar *sect) {
    tstring s;

    lck.lock();
    _flush();
    bufsz = cfg.get(T("file.buffer.size"), 32 * 1024, sect);
    buftm = cfg.get(T("file.buffer.msec"), 1000, sect);
    bufenable = cfg.get(T("file.buffer.enable"), false, sect);
    gmt = cfg.get(T("gmt"), false, sect);
    mail(str2enum(cfg.get(T("mail.level"), T("err"), sect).c_str()),
	cfg.get(T("mail.to"), T("logger"), sect).c_str(),
	cfg.get(T("mail.from"), T("<>"), sect).c_str(),
	cfg.get(T("mail.host"), T("mail:25"), sect).c_str());
    mailenable = cfg.get(T("mail.enable"), false, sect);
    if (src.empty()) {
	tstring::size_type pos;

	src = cfg.prefix();
	if ((pos = src.find_last_of(T("."))) != s.npos)
	    src.erase(0, pos + 1);
    }
    syslog(str2enum(cfg.get(T("syslog.level"), T("err"), sect).c_str()),
	cfg.get(T("syslog.host"), T("localhost"), sect).c_str(),
	cfg.get(T("syslog.facility"), 1, sect));
    syslogenable = cfg.get(T("syslog.enable"), false, sect);
    format(cfg.get(T("format"), T("[%Y-%m-%d %H:%M:%S.%s %z]"), sect).c_str());
    s = cfg.get(T("type"), T("simple"), sect);
    _type = s == T("nolevel") ? NoLevel : s == T("syslog") ? Syslog :
	s == T("keyval") ? KeyVal : Simple;
    afd.set(cfg, sect, T("alert"), false, T("err"), T("stderr"));
    ffd.set(cfg, sect, T("file"), true, T("info"), T("stdout"));
    lvl = afd.lvl > ffd.lvl ? afd.lvl : ffd.lvl;
    lck.unlock();
    buffer(bufenable);
}

bool Log::setids(uid_t uid, gid_t gid) const {
    return (!alert() || chown(alertpath(), uid, gid) == -1) &&
	(!file() || chown(filepath(), uid, gid) == -1);
}

void Log::setmp(bool b) {
    flush();
    ffd.close();
    if (b)
	buffer(false);
    mp = ffd.mp = b;
}

void Log::start(void) {
    Locker lkr(lck);

    if (bufenable && ft.getState() != Running)
	ft.start(16 * 1024);
}

void Log::stop(void) {
    Locker lkr(lck);

    if (ft.getState() == Running) {
	ft.quit();
	cv.set();
	lkr.unlock();
	ft.wait();
    }
}

Log::Level Log::str2enum(const tchar *l) {
    for (int i = 0; i < (int)(sizeof (LevelStr) / sizeof (const tchar *)); i++) {
	if (!tstricmp(l, LevelStr[i]) || !tstricmp(l, LevelStr2[i]))
	    return (Level)i;
    }
    return None;
}

void Log::syslog(Level l, const tchar *host, uint fac) {
    sysloglvl = l;
    if (!host) {
	syslogenable = !sysloghost.empty();
	return;
    }
    syslogfac = fac;
    if (sysloghost != host) {
	sysloghost = host;
	syslogsock.close();
    }
    if (sysloghost.empty() ||
	!syslogaddr.set(sysloghost.c_str(), 0, Sockaddr::UDP) ||
	!syslogaddr.port(T("syslog"), Sockaddr::UDP) ||
	!syslogsock.open(AF_INET)) {
	syslogenable = false;
	sysloghost.erase();
	syslogsock.close();
    } else {
	syslogenable = true;
    }
}

