/*
 * Copyright 2001-2016 Todd Richmond
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
#include <fcntl.h>
#include <stdarg.h>
#include <time.h>
#ifndef _WIN32
#include <dirent.h>
#include <sys/file.h>
#endif
#include <sys/stat.h>
#include "Config.h"
#include "Log.h"
#include "SMTPClient.h"

#ifdef _WIN32
#pragma comment(lib, "user32.lib")
#endif

static const tchar *USubst = T("\001\001");
static const tchar *ZSubst = T("\002\002");

const tchar * const Log::LevelStr[] = { T("none"), T("emrg"), T("alrt"),
    T("crit"), T("err"), T("warn"), T("note"), T("info"), T("debg"), T("trce"),
    T("sprs") };
const tchar * const Log::LevelStr2[] = { T("nothing"), T("emergency"),
    T("alert"), T("critical"), T("error"), T("warning"), T("notice"),
    T("information"), T("debug"), T("trace"), T("suppress") };


// UNIX loaders may try to construct static objects > 1 time
static Log &_dlog(void) {
    static Log __dlog;

    return __dlog;
}

Log &dlog = _dlog();

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
	if (!lockfd()) {
	    close();
	    fd = -3;
	    tcerr << T("unable to lock log ") << path << endl;
	} else {
	    locked = true;
	}
    }
}

bool Log::LogFile::lockfd(void) {
    if (fd < 0)
	return 0;
    if (lockfile(fd, F_WRLCK, SEEK_SET, 0, 0, 0) ||
	(len = (ulong)lseek(fd, 0, SEEK_END)) == (ulong)-1)
	return false;
    return true;
}

void Log::LogFile::print(const tchar *buf, uint chars) {
    if (fd < 0) {
	if (fd == -2) {
	    tcout.write(buf, chars);
	    tcout.flush();
	} else if (fd == -3) {
	    tcerr.write(buf, chars);
	    tcerr.flush();
#ifdef _WIN32
	} else if (fd == -4) {
	    MessageBox(NULL, buf, NULL, MB_OK | MB_ICONWARNING |
		MB_SETFOREGROUND);
	} else if (fd == -5) {
	    OutputDebugString(buf);
#endif
	}
    } else {
	write(fd, buf, (int)(chars * sizeof (tchar)));
	if (file[0] != '>')
	    len += chars * sizeof (tchar);
    }
}

bool Log::LogFile::reopen(void) {
    bool ret = true;

    close();
    if ((fd = ::open(tstringtoachar(path), O_WRONLY | O_CREAT | O_BINARY |
	O_SEQUENTIAL, 0640)) == -1) {
	tcerr << T("unable to open log ") << path << endl;
	fd = -3;
	ret = false;
    } else {
	lock();
	if (!len && path != file) {
	    char buf[1024];
	    time_t now = ::time(NULL);
	    struct tm tmbuf, *tm = gmt ? gmtime_r(&now, &tmbuf) :
		localtime_r(&now, &tmbuf);

	    strftime(buf, sizeof (buf) / sizeof (tchar), tstringtoachar(file), tm);
	    link(tstringtoachar(path), buf);
	}
    }
    return ret;
}

void Log::LogFile::roll(void) {
    tDIR *dir;
    struct tdirent *ent;
    uint files = 0;
    time_t now;
    tstring oldfile;
    tstring::size_type pos;
    tstring s1, s2, s3;
    struct stat sbuf;
    tchar sep;

    close();
    if (!enable)
	return;
    lock();
    now = cnt && !sec && fstat(fd, &sbuf) == 0 ? (time_t)sbuf.st_ctime :
	::time(NULL);
    s1 = path;
    if ((pos = s1.rfind('/')) == s1.npos && (pos = s1.rfind('\\')) == s1.npos) {
	sep = '/';
	s2 = s1;
	s1.erase();
    } else {
	sep = s1.at(pos);
	s2 = s1.substr(pos + 1);
	s1.erase(pos);
    }
    if ((dir = topendir(s1.empty() ? T(".") : s1.c_str())) != NULL) {
	for (;;) {
	    uint ext;
	    uint oldext = 0;
	    ulong oldtime = (ulong)-1;

	    files = 0;
	    while ((ent = treaddir(dir)) != NULL) {
		if (tstrncmp(ent->d_name, s2.c_str(), s2.size()) != 0 ||
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
		if (tstat(s3.c_str(), &sbuf) == 0 && (ulong)sbuf.st_mtime <
		    (ulong)oldtime) {
		    if ((pos = s3.rfind('.')) != s3.npos && pos < s3.size() -
			1 && isdigit((int)s3[++pos])) {
			ext = ttoi(s3.c_str() + pos);
			if (ext < oldext)
			    continue;
			else
			    oldext = ext;
		    }
		    oldfile = s3;
		    oldtime = (ulong)sbuf.st_mtime;
		}
	    }
	    if (oldtime == (ulong)-1) {
		break;
	    } else if (((cnt && files >= cnt &&
		(!sec || oldtime < (ulong)(now - sec))) ||
		(sec && oldtime < (ulong)(now - sec))) &&
		(!cnt || files >= cnt)) {
		tunlink(oldfile.c_str());
		files--;
		trewinddir(dir);
	    } else {
		break;
	    }
	}
	tclosedir(dir);
    }
    if (cnt && path == file) {
	tchar buf[32];
	uint u;

	tsprintf(buf, T(".%u"), files);
	s1 = file + buf;
	for (u = files; u > 1; u--) {
	    tsprintf(buf, T(".%u"), u - 1);
	    s2 = file + buf;
	    (void)tunlink(s1.c_str());
	    if (trename(s2.c_str(), s1.c_str()))
		break;
	    s1 = s2;
	}
	if (!u)
	    (void)trename(file.c_str(), s1.c_str());
    } else if (path != file) {
	(void)tunlink(path.c_str());
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
    sec = cfg.get((s + T("time")).c_str(), 0L, sect);
    set(lvl, f.c_str(), cnt, sz, sec);
    if (fd == -1 && !tstrchr(file.c_str(), '/') &&
	!tstrchr(file.c_str(), '\\')) {
	tstring dir(cfg.get(T("installdir")));

	if (!dir.empty()) {
	    dir += T("/log");
	    if (access(tstringtoachar(dir), W_OK))
		dir = cfg.get(T("installdir"));
	    dir += T("/");
	    file = dir + file;
	    path = dir + path;
	}
    }
    enable = cfg.get((s + T("enable")).c_str(), denable, sect);
}

void Log::LogFile::set(Level l, const tchar *f, uint c, ulong s, ulong t) {
    cnt = c;
    enable = true;
    lvl = l;
    sz = s;
    sec = t;
    close();
    if (!f || file == f)
	return;
    file = path = f;
    if (file == T("stdout") || file == T("cout")) {
	fd = -2;
    } else if (file == T("stderr") || file == T("cerr")) {
	fd = -3;
    } else if (file == T("console")) {
	fd = -4;
    } else if (file == T("debug")) {
	fd = -5;
    } else if (file[0] == '>') {
	fd = ttoi(file.c_str() + 1);
    } else {
	const tchar *p;

	fd = -1;
	if ((p = tstrchr(path.c_str(), '%')) != NULL) {
	    if (p[-1] == '.')
		p--;
	    path.erase(p - path.c_str());
	}
    }
    len = 0;
}

bool Log::LogFile::unlockfd(void) {
    return fd >= 0 ? lockfile(fd, F_UNLCK, SEEK_SET, 0, 0, 0) == 0 : true;
}

Log::Log(Level level): cv(lck), afd(false, Err, T("stderr"), true),
    ffd(true, Info, T("stdout"), true),
    bufenable(false), mailenable(false), syslogenable(false),
    bufsz(32 * 1024), buftm(1000), ft(*this), gmt(false), mp(true),
    last_sec(0), lvl(level), maillvl(None),
    sysloglvl(None), syslogfac(1), syslogsock(SOCK_DGRAM), _type(Simple),
    upos(0) {
    format(T("[%Y-%m-%d %H:%M:%S.%# %z]"));
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

void Log::endlog(Tlsdata &tlsd, Level clvl) {
    size_t lvllen, tmlen;
    time_t now_sec;
    usec_t now_usec;
    tstring &strbuf(tlsd.strbuf);
    size_t sz = (size_t)tlsd.strm.size();
    tchar tmp[8];

    if (tlsd.suppress)
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
    now_sec = (uint)(now_usec / 1000000);
    if (now_sec != last_sec) {
	tchar tbuf[128];
	struct tm tmbuf, *tm;
	tstring::size_type zpos;

	tm = gmt ? gmtime_r(&now_sec, &tmbuf) : localtime_r(&now_sec, &tmbuf);
	tstrftime(tbuf, sizeof (tbuf) / sizeof (tchar), fmt.c_str(), tm);
	last_format = tbuf;
	last_sec = now_sec;
	if ((zpos = last_format.find(ZSubst)) != last_format.npos) {
	    int diff;
	    tchar gmtoff[16];
	    struct tm tmbuf2, *tm2;

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
	    last_format.replace(zpos, 2, gmtoff);
	}
	upos = last_format.find(USubst);
    }
    strbuf = last_format;
    if (upos != last_format.npos) {
	tsprintf(tmp, T("%06u"), (uint)(now_usec % 1000000));
	strbuf.replace(upos, 2, tmp);
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
    if (!tlsd.prefix.empty()) {
	strbuf += tlsd.prefix;
	if (_type == Syslog)
	    strbuf += ':';
	strbuf += ' ';
    }
    if (_type == KeyVal) {
	strbuf += T("txt=\"");
	strbuf += tlsd.strm.str();
	strbuf += '"';
    } else {
	for (const tchar *p = tlsd.strm.str(); sz--; p++) {
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
    strbuf += '\n';
    if (afd.enable && clvl <= afd.lvl) {
	if (src.empty()) {
	    afd.print(strbuf);
	} else {
	    tstring ss(strbuf.substr(0, lvllen));

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
	    if ((uint)bufstrm.size() > bufsz)
		_flush();
	} else {
	    ffd.print(strbuf);
	}
	if (mp)
	    ffd.unlock();
    }
    lck.unlock();
    strbuf.erase(strbuf.size() - 1);
    tlsd.clvl = None;
    tlsd.space = false;
    tlsd.strm.reset();
    tlsd.suppress = true;
    if (syslogenable && clvl <= sysloglvl) {
	string ss;
	string::size_type pos;
	char buf[40], cbuf[32];
	int i = (syslogfac << 3) | (clvl - (clvl < Note ? 1 : 2));

	sprintf(buf, "<%d>%.15s", i, ctime_r(&now_sec, cbuf) + 4);
	ss = buf;
	if (!mailfrom.empty()) {
	    ss += ' ';
	    if (_type == KeyVal)
		ss += "nm=";
	    if ((pos = mailfrom.find_first_of('@')) == ss.npos)
		ss += tstringtoastring(mailfrom);
	    else
		ss += tstringtoastring(mailfrom.substr(0, pos));
	}
	if (_type == Syslog)
	    ss += ':';
	ss += ' ';
	ss += tstringtoastring(strbuf.substr(tmlen));
	syslogsock.write(ss.c_str(), (uint)ss.size(), syslogaddr);
    }
    if (mailenable && clvl <= maillvl && !mailto.empty()) {
	SMTPClient smtp;

	if (smtp.connect(mailhost.c_str())) {
	    tstring ss(mailfrom);

	    smtp.helo();
	    if (ss.find_first_of('@') == ss.npos) {
	    	ss += '@';
		ss += Sockaddr::hostname();
	    }
	    smtp.from(ss.c_str());
	    smtp.to(mailto.c_str());
	    smtp.subject(strbuf.substr(tmlen, tmlen + 69).c_str());
	    smtp.data(false, strbuf.c_str());
	    smtp.enddata();
	    smtp.quit();
	}
    }
    tlsd.suppress = false;
}

void Log::file(Level l, const tchar *f, uint cnt, ulong sz, ulong sec) {
    Locker lkr(lck);

    _flush();
    ffd.set(l, f, cnt, sz, sec);
}

void Log::_flush(void) {
    if (bufstrm.size()) {
	ffd.print(bufstrm.str(), (uint)bufstrm.size());
	bufstrm.reset();
    }
}

void Log::format(const tchar *s) {
    tstring::size_type pos;

    fmt = s;
    last_sec = 0;
    if ((pos = fmt.find(T("%#"))) != fmt.npos)
	fmt.replace(pos, 2, USubst);
#if !defined(__APPLE__) && !defined(__linux__)
    if ((pos = fmt.find(T("%z"))) != fmt.npos)
	fmt.replace(pos, 2, ZSubst);
#endif
}

void Log::logv(int il, ...) {
    Level l((Level)il);
    const tchar *p;
    bool space;
    Tlsdata &tlsd(*tls);
    va_list vl;

    if (l > lvl)
	return;
    va_start(vl, il);
    space = tlsd.space;
    tlsd.space = false;
    while ((p = va_arg(vl, const tchar *)) != NULL) {
	if (space)
	    tlsd.strm << ' ';
	else
	    space = true;
	tlsd.strm << p;
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
	if ((pos = src.find_last_of(T("."))) != src.npos)
	    src.erase(0, pos + 1);
    }
    syslog(str2enum(cfg.get(T("syslog.level"), T("err"), sect).c_str()),
	cfg.get(T("syslog.host"), T("localhost"), sect).c_str(),
	cfg.get(T("syslog.facility"), 1, sect));
    syslogenable = cfg.get(T("syslog.enable"), false, sect);
    format(cfg.get(T("format"), T("[%Y-%m-%d %H:%M:%S.%# %z]"), sect).c_str());
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
#ifdef _WIN32
	(void)uid; (void)gid;
	return true;
#else
    return (!alert() || chown(alertpath(), uid, gid) == -1) &&
	(!file() || chown(filepath(), uid, gid) == -1);
#endif
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
	!syslogaddr.set(sysloghost.c_str(), T("syslog"), Sockaddr::UDP) ||
	!syslogsock.open(AF_INET)) {
	syslogenable = false;
	sysloghost.erase();
	syslogsock.close();
    } else {
	syslogenable = true;
    }
}

