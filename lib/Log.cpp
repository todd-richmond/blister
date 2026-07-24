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
#include <algorithm>
#include <vector>
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

static constexpr const tchar *USubst = T("\001\001");
#if !defined(__APPLE__) && !defined(__linux__)
#define NO_PERCENT_Z
static constexpr const tchar *ZSubst = T("\002\002");
#endif

const tstring_view Log::LevelStr[] = {
    T("none"), T("emrg"), T("alrt"), T("crit"), T("err "), T("warn"), T("note"),
    T("info"), T("debg"), T("trce"), T("sprs")
};
const tstring_view Log::LevelStr2[] = {
    T("nothing"), T("emergency"), T("alert"), T("critical"), T("error"),
    T("warning"), T("notice"), T("information"), T("debug"), T("trace"),
    T("suppress")
};

// UNIX loaders may try to construct static objects > 1 time
static Log &_dlog(void) {
    static Log __dlog;

    return __dlog;
}

Log &dlog(_dlog());

Log &Log::log(Tlsdata &tlsd, Log::Escalator &escalator) {
    FastSpinLocker lkr(escalator.lck);
    ulong count;
    msec_t now = mticks() / 1000, start;

    count = escalator.count;
    start = escalator.start;
    tlsd.clvl = escalator.level1;
    if (escalator.period && start + escalator.period < now) {
	count = 0;
	if (escalator.count >= escalator.mincount) {
	    tlsd.clvl = escalator.level2;
	    if (escalator.timeout > escalator.period)
		start = now + escalator.timeout - escalator.period;
	    else
		start = now + 1;
	} else {
	    start = now;
	}
    }
    if (start <= now) {
	if (count == 0)
	    start = now;
	++count;
	if (escalator.period == 0) {
	    if (start + escalator.timeout < now) {
		count = 1;
		start = now;
	    }
	    if (!escalator.mincount)
		escalator.mincount = 1;
	    if (count == escalator.mincount) {
		tlsd.clvl = escalator.level2;
		count = 0;
		start = now + escalator.timeout;
	    }
	}
    }
    escalator.count = count;
    escalator.start = start;
    return *this;
}

int Log::FlushThread::onStart(void) {
    Locker lkr(l.lck);

    while (!qflag) {
	// wake up on 1st buffered write
	l.cv.wait(INFINITE);
	// sleep for buffer time before flush
	// cppcheck-suppress knownConditionTrueFalse
	if (!qflag)
	    l.cv.wait(l.buftm);
	l._flush();
    }
    return 0;
}

bool Log::LogFile::close(void) {
    len = 0;
    if (fd < 0)
	return false;
    ::close(fd);
    fd = -1;
    return true;
}

void Log::LogFile::lock() {
    if (fd == -1)
	reopen();
    if (fd >= 0 && (lockfile(fd, F_WRLCK, SEEK_SET, 0, 0, mp ? 0 : 1) ||
	(mp && (len = (ulong)lseek(fd, 0, SEEK_END)) == (ulong)-1))) {
	tcerr << T("unable to lock log ") << path << T(": ") <<
	    tstrerror(errno) << endl;
	close();
	fd = -3;
    }
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
	uint charsz = (uint)(chars * sizeof (tchar));
	long out = (long)write(fd, buf, charsz);

	if (out == (long)charsz) {
	    if (file[0] != '>')
		len += charsz;
	} else if (out > 0) {
	    // partial write - restore previous file length
	    if (ftruncate(fd, (off_t)len)) {
		;
	    }
	}
    }
}

bool Log::LogFile::reopen(void) {
    bool newfile;
    struct stat sbuf;

    close();
    if ((fd = ::open(tstringtoachar(path), O_WRONLY | O_CREAT | O_BINARY |
	O_SEQUENTIAL | O_CLOEXEC, 0640)) == -1) {
	tcerr << T("unable to open log ") << path << T(": ") <<
	    tstrerror(errno) << endl;
	fd = -3;
	return false;
    }
#ifdef POSIX_FADV_SEQUENTIAL
    posix_fadvise(fd, 0, 0, POSIX_FADV_SEQUENTIAL);
#endif
    lock();
    newfile = fd >= 0 && len == 0;
#ifdef _UNICODE
    if (newfile) {
	static const char bom[] = { '\xFF', '\xFE' };

	if (::write(fd, bom, sizeof(bom)) == sizeof(bom))
	    len = sizeof (bom);
    }
#endif
    if (newfile && path != file && !fstat(fd, &sbuf) && sbuf.st_nlink == 1) {
	tchar buf[PATH_MAX];
	time_t now = ::time(NULL);

	while (true) {
	    struct tm tmbuf;
	    const struct tm *tm = gmt ? gmtime_r(&now, &tmbuf) :
		localtime_r(&now, &tmbuf);

	    tstrftime(buf, sizeof (buf), file.c_str(), tm);
	    if (!tlink(path.c_str(), buf)) {
		break;
	    } else if (errno == EEXIST) {
		++now;
	    } else {
		::close(fd);
		fd = -3;
		return false;
	    }
	}
    }
    return true;
}

void Log::LogFile::roll(void) {
    tDIR *dir;
    const struct tdirent *ent;
    uint files = 0;
    ino_t inode = 0;
    time_t now;
    tstring::size_type pos;
    tstring s1, s2, s3;
    struct stat sbuf;
    tchar sep;

    if (fd < 0)
	return;
    if (!fstat(fd, &sbuf))
	inode = sbuf.st_ino;
    close();
    if (!enable)
	return;
    lock();
    if (fd < 0 || (!fstat(fd, &sbuf) && mp && sbuf.st_ino != inode))
	return;
    now = cnt && !sec ? (time_t)sbuf.st_ctime : ::time(NULL);
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
	vector<pair<ulong, tstring>> entries;

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
	    if (tstat(s3.c_str(), &sbuf) == 0)
		entries.emplace_back((ulong)sbuf.st_mtime, s3);
	}
	tclosedir(dir);
	sort(entries.begin(), entries.end());
	files = (uint)entries.size();
	if (cnt || sec) {
	    for (auto it = entries.begin(); it != entries.end(); ) {
		if ((!sec || it->first < ((ulong)now - sec)) &&
		    (!cnt || files >= cnt)) {
		    if (tunlink(it->second.c_str()))
			break;
		    --files;
		    it = entries.erase(it);
		} else {
		    break;
		}
	    }
	}
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
	if (cnt == 1)
	    (void)tunlink(file.c_str());
	else
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
    cnt = cfg.get((s + T("count")).c_str(), 0U, sect);
    f = cfg.get((s + T("name")).c_str(), dfile, sect);
    gmt = cfg.get(T("gmt"), false, sect);
    lvl = str2enum(cfg.get((s + T("level")).c_str(), dlvl, sect).c_str());
    sz = cfg.get((s + T("size")).c_str(), 10UL * 1024 * 1024, sect);
    sec = cfg.get((s + T("time")).c_str(), 0UL, sect);
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
	fd = atoi<int>(file.c_str() + 1);
    } else {
	tstring::size_type p = path.find('%');

	if (p && p != path.npos && path[p - 1] == '.') {
	    p--;
	    path.erase(p);
	}
	fd = -1;
    }
    len = 0;
}

void Log::LogFile::unlock(void) const {
    if (fd >= 0)
	(void)lockfile(fd, F_UNLCK, SEEK_SET, 0, 0, 0);
}

Log::Log(Level level): cv(lck), afd(false, Err, T("stderr"), true), ffd(true,
    Info, T("stdout"), true), bufenable(false), mailenable(false),
    syslogenable(false), bufsz(32U * 1024), buftm(1000), ft(*this), gmt(false),
    mp(true), last_sec(0), lvl(level), maillvl(None), sysloglvl(None),
    syslogfac(1), syslogsock(SOCK_DGRAM), _type(Simple), upos(0) {
    format(T("[%Y-%m-%d %H:%M:%S.%# %z]"));
}

Log::~Log() {
    stop();
    (void)close();
}

void Log::alertfile(Level l, const tchar *f, uint cnt, ulong sz, ulong tm) {
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

void Log::strm_write_esc(tbufferstream &strm, const tchar *data, streamsize sz) {
    const tchar *q = data;
    const tchar *end = data + sz;

#ifndef _WIN32
#ifdef __AVX2__
    {
	// bias trick: (uchar)c < 0x20 via signed cmpgt after XOR with 0x80
	const __m256i bias = _mm256_set1_epi8((char)0x80);
	const __m256i tab_vec = _mm256_set1_epi8('\t');
	const __m256i thresh = _mm256_set1_epi8((char)(0x20 ^ 0x80));

	for (; q + 32 <= end; q += 32) {
	    __m256i chunk = _mm256_loadu_si256((const __m256i *)q);
	    __m256i lt_space = _mm256_cmpgt_epi8(thresh,
		_mm256_xor_si256(chunk, bias));
	    int mask = _mm256_movemask_epi8(_mm256_andnot_si256(
		_mm256_cmpeq_epi8(chunk, tab_vec), lt_space));

	    if (UNLIKELY(mask)) {
		q += __builtin_ctz((uint)mask);
		goto scan_done;
	    }
	}
    }
#elif defined(__ARM_NEON)
    {
	const uint8x16_t space_vec = vdupq_n_u8(0x20);
	const uint8x16_t tab_vec   = vdupq_n_u8('\t');

	for (; q + 16 <= end; q += 16) {
	    uint8x16_t chunk = vld1q_u8((const uint8_t *)q);
	    uint8x16_t needs_esc = vbicq_u8(vcltq_u8(chunk, space_vec),
		vceqq_u8(chunk, tab_vec));
	    uint64_t lo = vgetq_lane_u64(vreinterpretq_u64_u8(needs_esc), 0);
	    uint64_t hi = vgetq_lane_u64(vreinterpretq_u64_u8(needs_esc), 1);

	    if (UNLIKELY(lo | hi)) {
		q += lo ? __builtin_ctzll(lo) >> 3 :
		    8 + (__builtin_ctzll(hi) >> 3);
		goto scan_done;
	    }
	}
    }
#endif
#endif
    while (q < end && LIKELY(!((uchar)*q < ' ' && *q != '\t')))
	++q;
#if !defined(_WIN32) && (defined(__AVX2__) || defined(__ARM_NEON))
scan_done:
#endif
    if (LIKELY(q == end)) {
	strm.write(data, sz);
	return;
    }
    // slow path: escape control chars into strm
    const tchar *p = q;
    const tchar *start = q;

    strm.write(data, (streamsize)(q - data));
    while (p < end) {
	if (UNLIKELY((uchar)*p < ' ' && *p != '\t')) {
	    if (p > start)
		strm.write(start, (streamsize)(p - start));
	    if (*p == '\n') {
		strm.write(T("\\n"), 2);
	    } else if (*p == '\r') {
		strm.write(T("\\r"), 2);
	    } else {
		tchar oct[4] = { '\\',
		    (tchar)('0' + (((uchar)*p >> 6) & 7)),
		    (tchar)('0' + (((uchar)*p >> 3) & 7)),
		    (tchar)('0' + ((uchar)*p & 7)) };

		strm.write(oct, 4);
	    }
	    ++p;
	    start = p;
	} else {
	    ++p;
	}
    }
    if (p > start)
	strm.write(start, (streamsize)(p - start));
}

void Log::endlog(Tlsdata &tlsd) {
    Level clvl = tlsd.clvl;
    bool aenabled = afd.enable && clvl <= afd.lvl;
    bool fenabled = ffd.enable && clvl <= ffd.lvl;
    size_t lvllen, tmlen;
    time_t now_sec;
    usec_t now_usec;
    tstring &strbuf(tlsd.strbuf);
    size_t sz = (size_t)tlsd.strm.size();

    lck.lock();
    if (fenabled) {
	ffd.lock();
	if (ffd.len + (ulong)bufstrm.size() >= ffd.sz) {
	    _flush();
	    ffd.roll();
	}
    }
    if (aenabled) {
	afd.lock();
	if (afd.len >= afd.sz)
	    afd.roll();
    }
    time(&now_sec);
    now_usec = uticks();
    now_usec %= 1000000;
    if (now_sec != last_sec) {
	tchar tbuf[128];
	struct tm tmbuf;
	const struct tm *tm;

	tm = gmt ? gmtime_r(&now_sec, &tmbuf) : localtime_r(&now_sec, &tmbuf);
	tstrftime(tbuf, sizeof (tbuf) / sizeof (tchar), fmt.c_str(), tm);
	last_format = tbuf;
	last_sec = now_sec;
#ifdef NO_PERCENT_Z
	tstring::size_type zpos;

	if ((zpos = last_format.find(ZSubst)) != last_format.npos) {
	    int diff;
	    tchar gmtoff[16];
	    struct tm tmbuf2{};
	    const struct tm *tm2;

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
#endif
	upos = last_format.find(USubst);
    }
    if (_type == NoTime) {
	strbuf.erase();
    } else {
	if (upos == last_format.npos) {
	    strbuf = last_format;
	} else {
	    tchar cbuf[8];
	    auto [ep, ec] = to_chars(cbuf, cbuf + 6, (uint)now_usec);
	    size_t dlen = (size_t)(ep - cbuf);

	    strbuf.assign(last_format, 0, upos);
	    strbuf.append(6 - dlen, '0');
	    strbuf.append(cbuf, dlen);
	    strbuf.append(last_format, upos + 2, last_format.npos);
	}
	if (!strbuf.empty())
	    strbuf += ' ';
    }
    tmlen = strbuf.size();
    if (_type == KeyVal) {
	strbuf += T("ll=");
	if (clvl >= None && clvl <= Trace)
	    strbuf += LevelStr2[clvl];
	strbuf += ' ';
    } else if (_type != NoLevel && _type != NoTime) {
	if (clvl >= None && clvl <= Trace)
	    strbuf += LevelStr[clvl];
	if (_type == Syslog)
	    strbuf += ':';
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
	strbuf.append(T("txt=\""), 5);
	strbuf.append(tlsd.strm.str(), sz);
	strbuf += '"';
    } else {
	strbuf.append(tlsd.strm.str(), sz);
    }
    strbuf += '\n';
    if (aenabled) {
	if (src.empty()) {
	    afd.print(strbuf);
	} else {
	    tstring ss;

	    ss.reserve(strbuf.size() + src.size() + 5);
	    ss.append(strbuf, 0, lvllen);
	    ss += T("src=");
	    ss += src;
	    ss += ' ';
	    ss.append(strbuf, lvllen, strbuf.npos);
	    afd.print(ss);
	}
	afd.unlock();
    }
    if (fenabled) {
	if (ft.getState() == Running) {
	    bool b = bufstrm.size() == 0;

	    bufstrm.write(strbuf.data(), (streamsize)strbuf.size());
	    if ((uint)bufstrm.size() > bufsz)
		_flush();
	    else if (b)
		cv.set();
	} else {
	    ffd.print(strbuf);
	}
	if (mp)
	    ffd.unlock();
    }

    bool mailit = mailenable && clvl <= maillvl && !mailto.empty();
    tstring mfrom, mhost, mto;

    if (mailit) {
	mfrom = mailfrom;
	mhost = mailhost;
	mto = mailto;
    }
    lck.unlock();
    strbuf.erase(strbuf.size() - 1);
    tlsd.clvl = None;
    tlsd.sep = '\0';
    tlsd.strm.reset();
    tlsd.suppress = true;
    if (syslogenable && clvl <= sysloglvl) {
	string ss;
	string::size_type pos;
	char buf[64], cbuf[32];
	uint u = (syslogfac << 3) | (uint)(clvl - (clvl <= Debug ? 1 : 2));

	sprintf(buf, "<%u>%.15s.%06u ", u, ctime_r(&now_sec, cbuf) + 4,
	    (uint)now_usec);
	ss = buf;
	ss += tstringtoastring(hostname);
	if (!mailfrom.empty() && mailfrom != T("<>")) {
	    ss += ' ';
	    if (_type == KeyVal)
		ss += "nm=";
	    if ((pos = mailfrom.find_first_of('@')) == mailfrom.npos)
		ss += tstringtoastring(mailfrom);
	    else
		ss += tstringtoastring(mailfrom.substr(0, pos));
	}
	sprintf(buf, "[%d]: ", getpid());
	ss += buf;
	ss += tstringtoastring(strbuf.substr(tmlen));
	syslogsock.write(ss.data(), (uint)ss.size(), syslogaddr);
    }
    if (mailit) {
	SMTPClient smtp;

	if (smtp.connect(mhost.c_str())) {
	    tstring ss(mfrom);

	    smtp.helo();
	    if (ss.find_first_of('@') == ss.npos) {
		ss += '@';
		ss += Sockaddr::hostname();
	    }
	    smtp.from(RFC822Addr(ss));
	    smtp.to(RFC822Addr(mto));
	    smtp.subject(strbuf.substr(tmlen, 69).c_str());
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
#ifdef NO_PERCENT_Z
    if ((pos = fmt.find(T("%z"))) != fmt.npos)
	fmt.replace(pos, 2, ZSubst);
#endif
}

void Log::logv(int il, ...) {
    if (UNLIKELY((Level)il > lvl))
	return;

    Tlsdata &tlsd(*tls);
    const tchar *p;
    va_list vl;

    if (UNLIKELY(tlsd.suppress))
	return;
    tlsd.clvl = (Level)il;
    tlsd.sep = ' ';
    va_start(vl, il);
    while ((p = va_arg(vl, const tchar *)) != NULL)
	*this << p;
    va_end(vl);
    endlog(tlsd);
}

void Log::mail(Level l, const tchar *to, const tchar *from, const tchar
    *host) {
    Locker lkr(lck);

    _mail(l, to, from, host);
}

void Log::_mail(Level l, const tchar *to, const tchar *from, const tchar
    *host) {
    maillvl = l;
    if (to) {
	mailfrom = from;
	mailhost = host;
	mailto = to;
    }
}

tbufferstream &Log::quote(tbufferstream &os, const tchar *s) {
    static const uchar needquote[256] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // NUL - SI
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // DLE - US
	1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // SPACE - /
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0 - ?
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // @ - O
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,  // P - _
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // ` - o
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  // p - DEL
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 0x80 - 0x8F
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 0x90 - 0x9F
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 0xA0 - 0xAF
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 0xB0 - 0xBF
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 0xC0 - 0xCF
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 0xD0 - 0xDF
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 0xE0 - 0xEF
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // 0xF0 - 0xFF
    };
    const tuchar *start = (const tuchar *)s;
    const tuchar *p = start;

    while (*p) {
	tuchar c = *p;

	if (UNLIKELY(needquote[c])) {
	    streamsize bsz = 0;
	    tchar buf[128];
	    static const tchar dquote = '"';

	    os.write(dquote);
	    os.write((const tchar *)start, p - start);
	    auto flush = [&]() { if (bsz) { os.write(buf, bsz); bsz = 0; } };
	    auto esc2 = [&](tchar e) {
		if (UNLIKELY(bsz + 2 > (streamsize)sizeof (buf)))
		    flush();
		buf[bsz++] = '\\';
		buf[bsz++] = e;
	    };
	    while (*p) {
		c = *p++;
		switch (c) {
		case '"': esc2('"'); break;
		case '\\': esc2('\\'); break;
		case '\f': esc2('f'); break;
		case '\n': esc2('n'); break;
		case '\r': esc2('r'); break;
		case '\t': esc2('t'); break;
		case '\v': esc2('v'); break;
		default:
		    if (LIKELY(c >= ' ' && c != '\x7f')) {
			buf[bsz++] = (tchar)c;
			if (bsz == (streamsize)sizeof (buf))
			    flush();
		    } else {
			if (UNLIKELY(bsz + 4 > (streamsize)sizeof (buf)))
			    flush();
			buf[bsz++] = '\\';
			buf[bsz++] = (tchar)('0' + ((c >> 6) & 7));
			buf[bsz++] = (tchar)('0' + ((c >> 3) & 7));
			buf[bsz++] = (tchar)('0' + (c & 7));
		    }
		}
	    }
	    flush();
	    os.write(dquote);
	    return os;
	}
	++p;
    }
    os.write((const tchar *)start, p - start);
    return os;
}

void Log::set(const Config &cfg, const tchar *sect) {
    tstring::size_type pos;
    tstring s;

    lck.lock();
    _flush();
    bufsz = cfg.get(T("file.buffer.size"), 32U * 1024, sect);
    buftm = cfg.get(T("file.buffer.msec"), 1000UL, sect);
    bufenable = cfg.get(T("file.buffer.enable"), false, sect);
    gmt = cfg.get(T("gmt"), false, sect);
    s = Sockaddr::hostname();
    if ((pos = s.find_first_of('.')) == s.npos)
	hostname = s;
    else
	hostname = s.substr(0, pos);
    mailenable = cfg.get(T("mail.enable"), false, sect);
    _mail(str2enum(cfg.get(T("mail.level"), T("err"), sect).c_str()),
	cfg.get(T("mail.to"), T("logger"), sect).c_str(),
	cfg.get(T("mail.from"), T("<>"), sect).c_str(),
	cfg.get(T("mail.host"), T("mail:25"), sect).c_str());
    if (src.empty()) {
	src = cfg.prefix();
	if ((pos = src.find_last_of(T('.'))) != src.npos)
	    src.erase(0, pos + 1);
    }
    syslogenable = cfg.get(T("syslog.enable"), false, sect);
    _syslog(str2enum(cfg.get(T("syslog.level"), T("err"), sect).c_str()),
	cfg.get(T("syslog.host"), T("localhost"), sect).c_str(),
	cfg.get(T("syslog.facility"), 1U, sect));
    format(cfg.get(T("format"), T("[%Y-%m-%d %H:%M:%S.%# %z]"), sect).c_str());
    s = cfg.get(T("type"), T("simple"), sect);
    _type = s == T("nolevel") ? NoLevel : s == T("notime") ? NoTime :
	s == T("syslog") ? Syslog : s == T("keyval") ? KeyVal : Simple;
    afd.set(cfg, sect, T("alert"), false, T("warn"), T("stderr"));
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
    return (!alertfile() || chown(alertpath(), uid, gid) == 0) &&
	(!file() || chown(filepath(), uid, gid) == 0);
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
	ft.start(16U * 1024);
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
    for (uint u = 0; u < sizeof (LevelStr) / sizeof (LevelStr[0]); ++u) {
	tstring_view sv = LevelStr[u];

	if (!sv.empty() && sv.back() == ' ')
	    sv.remove_suffix(1);
	if ((!tstrnicmp(l, sv.data(), sv.size()) && l[sv.size()] == '\0') ||
	    (!tstrnicmp(l, LevelStr2[u].data(), LevelStr2[u].size()) &&
	    l[LevelStr2[u].size()] == '\0'))
	    return (Level)u;
    }
    return None;
}

void Log::syslog(Level l, const tchar *host, uint fac) {
    Locker lkr(lck);

    _syslog(l, host, fac);
}

void Log::_syslog(Level l, const tchar *host, uint fac) {
    sysloglvl = l;
    if (!host)
	return;
    syslogfac = fac;
    if (sysloghost != host) {
	sysloghost = host;
	syslogsock.close();
    }
    if (!syslogenable || sysloghost.empty() ||
	!syslogaddr.set(sysloghost.c_str(), T("syslog"), Sockaddr::UDP) ||
	!syslogsock.open(AF_INET)) {
	syslogenable = false;
	syslogsock.close();
    }
}

