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
#include <format>
#include <vector>
#include <fcntl.h>
#include <stdarg.h>
#ifndef _WIN32
#include <dirent.h>
#include <sys/file.h>
#endif
#include <sys/stat.h>
#if defined(__SSE2__) && !defined(_WIN32)
#include <emmintrin.h>
#endif
#include "Config.h"
#include "Log.h"
#include "SMTPClient.h"

#ifdef _WIN32
#pragma comment(lib, "user32.lib")
#endif

#ifndef _WIN32
static constexpr ulong LockPos = LONG_MAX - 1;
#endif
static constexpr const tchar *USubst = T("\001\001");
#if !defined(__APPLE__) && !defined(__linux__)
#define NO_PERCENT_Z
static constexpr const tchar *ZSubst = T("\002\002");
#endif

// UNIX loaders may try to construct static objects > 1 time
static Log &_dlog(void) {
    static Log __dlog;

    return __dlog;
}

Log &dlog(_dlog());

Log &Log::log(Tlsdata &tlsd, const Log::Escalator &escalator) {
    FastSpinLocker lkr(escalator.lck);
    ulong count;
    ulong now = (ulong)(mticks() / 1000), start;

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

    for (;;) {
	if (!qflag) {
	    // drainbuffers() unlocks for I/O so recheck for data added meanwhile
	    if (l.bufpending.empty() && l.bufcur->size() == 0) {
		l.cv.wait(INFINITE);
		continue;
	    }
	    // sleep for buffer time before flush
	    l.cv.wait(l.buftm);
	}
	l.flushing = true;
	l.drainbuffers(true);
	l.flushing = false;
	l.cv.broadcast();
	// cppcheck-suppress knownConditionTrueFalse
	if (qflag)
	    return 0;
    }
}

bool Log::LogFile::close(void) {
    len = 0;
    if (fd < 0 || file[0] == '>')
	return false;
    ::close(fd);
    fd = -1;
    return true;
}

void Log::LogFile::lock() {
    bool reopened = fd == -1;

    if (reopened)
	reopen();
    // fcntl locks arbitrate with other processes sharing the file: mp mode
    // locks around every write, single process mode only once at open
    if (mp && fd >= 0 && !reopened && file[0] != '>')
	(void)lockend();
}

// lock and seek to the end, logging to stderr on failure
bool Log::LogFile::lockend(void) {
    llong end;

    if (!lockrange(F_WRLCK) && (end = lseek(fd, 0, SEEK_END)) >= 0) {
	len = (ullong)end;
	return true;
    }
    tcerr << T("unable to lock log ") << path << T(": ") << tstrerror(errno) <<
	endl;
    close();
    fd = -3;
    return false;
}

void Log::LogFile::print(tstring_view s) {
    if (fd < 0) {
	if (fd == -2) {
	    tcout.write(s.data(), (streamsize)s.size());
	    tcout.flush();
	} else if (fd == -3) {
	    tcerr.write(s.data(), (streamsize)s.size());
	    tcerr.flush();
#ifdef _WIN32
	} else if (fd == -4 || fd == -5) {
	    const tstring z(s);	// views need not be NUL terminated

	    if (fd == -4)
		MessageBox(NULL, z.c_str(), NULL, MB_OK | MB_ICONWARNING |
		    MB_SETFOREGROUND);
	    else
		OutputDebugString(z.c_str());
#endif
	}
    } else {
	uint charsz = (uint)(s.size() * sizeof (tchar));
	long out = (long)write(fd, s.data(), charsz);

	if (out == (long)charsz) {
	    if (file[0] != '>')
		len += charsz;
	} else if (out > 0 && file[0] != '>' && !ftruncate(fd, (llong)len)) {
	    // rollback partial write; never touch a caller-owned descriptor
	    lseek(fd, (llong)len, SEEK_SET);
	}
    }
}

bool Log::LogFile::reopen(void) {
    bool newfile;
    struct stat sbuf;

    if (file[0] == '>')
	return fd >= 0;
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
    if (!lockend())
	return false;
    newfile = len == 0;
#ifdef _UNICODE
    if (newfile) {
	static const char bom[] = { '\xFF', '\xFE' };

	if (::write(fd, bom, sizeof (bom)) == sizeof (bom))
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

	    if (!tm) {
		close();
		fd = -3;
		return false;
	    }
	    if (!tstrftime(buf, std::size(buf), file.c_str(), tm)) {
		close();
		fd = -3;
		return false;
	    }
	    if (!tlink(path.c_str(), buf)) {
		break;
	    } else if (errno == EEXIST) {
		++now;
	    } else {
		close();
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
    ino_t inode = 0;
    time_t now;
    const bool numbered = path == file;
    tstring::size_type pos;
    struct stat sbuf;

    if (fd < 0 || file[0] == '>')
	return;
    if (!fstat(fd, &sbuf))
	inode = sbuf.st_ino;
    close();
    if (!enable)
	return;
    lock();
    if (fd < 0 || (!fstat(fd, &sbuf) && mp && sbuf.st_ino != inode))
	return;
    now = ::time(NULL);
    pos = path.find_last_of(T("/\\"));
    const size_t base = pos == path.npos ? 0 : pos + 1;
    const tstring directory = path.substr(0, base);
    const tstring prefix = path.substr(base) + '.';

    if (!(dir = topendir(directory.empty() ? T(".") : directory.c_str())))
	return;

    vector<tuple<ullong, time_t, tstring>> entries;

    while ((ent = treaddir(dir)) != nullptr) {
	const tstring_view name(ent->d_name);
	ullong n = 0;

	if (!name.starts_with(prefix) || name.size() == prefix.size())
	    continue;
	const tstring_view suffix = name.substr(prefix.size());

	if (numbered) {
	    tchar *end;

	    if (suffix.front() < '1' || suffix.front() > '9')
		continue;
	    errno = 0;
	    n = (ullong)tstrtoll(suffix.data(), &end, 10);
	    if (*end || errno == ERANGE || n >= (ullong)LLONG_MAX)
		continue;
	} else if (!istdigit(suffix.front()) ||
	    suffix.find_first_not_of(T("0123456789-_.:+ TZ")) != suffix.npos) {
	    continue;
	}
	tstring archive = directory + ent->d_name;

	if (tlstat(archive.c_str(), &sbuf) || !S_ISREG(sbuf.st_mode))
	    continue;
	entries.emplace_back(numbered ? ULLONG_MAX - n : (ullong)sbuf.st_mtime,
	    sbuf.st_mtime, std::move(archive));
    }
    tclosedir(dir);
    ranges::sort(entries);
    size_t files = entries.size() + (numbered ? 1U : 0U);

    for (auto &[order, age, name] : entries) {
	const bool old = sec && now > age && (ullong)(now - age) > sec;

	if ((cnt || sec) && (!cnt || files >= cnt) && (!sec || old) &&
	    !tunlink(name.c_str())) {
	    --files;
	    name.clear();
	}
    }
    if (!numbered || cnt == 1) {
	(void)tunlink(path.c_str());
    } else {
	auto shift = [&](const tstring &from, ullong n) {
	    const tstring to = std::format(T("{}.{}"), file, n);

	    return tlstat(to.c_str(), &sbuf) && errno == ENOENT &&
		!trename(from.c_str(), to.c_str());
	};

	for (const auto &[order, age, name] : entries) {
	    if (!name.empty() && !shift(name, ULLONG_MAX - order + 1))
		return;
	}
	if (!shift(file, 1))
	    return;
    }
    close();
    lock();
}

void Log::LogFile::set(const Config &cfg, const tchar *sect,
    const tchar *sub, bool denable, const tchar *dlvl, const tchar *dfile) {
    tstring s(sub);

    s += '.';
    gmt = cfg.get(T("gmt"), false, sect);
    set(str2enum(cfg.get((s + T("level")).c_str(), dlvl, sect).c_str()),
	cfg.get((s + T("name")).c_str(), dfile, sect).c_str(),
	cfg.get((s + T("count")).c_str(), 0U, sect),
	cfg.get((s + T("size")).c_str(), 10UL * 1024 * 1024, sect),
	cfg.get((s + T("time")).c_str(), 0UL, sect));
    if (fd == -1 && !file.contains('/') && !file.contains('\\')) {
	tstring dir(cfg.get(T("installdir")));

	if (!dir.empty()) {
	    dir += T("/log");
	    if (access(tstringtoachar(dir), W_OK))
		dir = cfg.get(T("installdir"));
	    dir += (tchar)'/';
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

int Log::LogFile::lockrange(short type) const {
#ifdef _WIN32
    // Windows range locks are mandatory; keep this byte past the log data.
    struct flock fl{type, SEEK_SET, LLONG_MAX - 1, 1, 0};

    return fcntl(fd, F_SETLKW, &fl);
#else
    return lockfile(fd, type, SEEK_SET, LockPos, 1, 0);
#endif
}

void Log::LogFile::unlock(void) const {
    if (mp && fd >= 0 && file[0] != '>')
	(void)lockrange(F_UNLCK);
}

WARN_PUSH_DISABLE(-Wstrict-overflow)
Log::Log(Level l): lvl(l) {
    ffd.lvl = l;
    _format(T("[%Y-%m-%d %H:%M:%S.%# %z]"));
}
WARN_POP()

Log::~Log() {
    stop();
    (void)close();
}

void Log::alertfile(Level l, const tchar *f, uint cnt, ulong sz, ulong tm) {
    Locker lkr(lck);

    afd.set(l, f, cnt, sz, tm);
    updatelvl();
}

void Log::buffer(bool enable) {
    if (enable) {
	if (mp)
	    setmp(false);

	Locker lkr(lck);

	bufenable = true;
	lkr.unlock();
	start();
    } else {
	// stop before disabling so unbuffered writes cannot race the flusher
	stop();

	Locker lkr(lck);

	bufenable = false;
	drainbuffers(false);
    }
}

void Log::file(Level l, const tchar *f, uint cnt, ulong sz, ulong sec) {
    PauseFlush pf(*this);

    drainbuffers(false);
    ffd.set(l, f, cnt, sz, sec);
    updatelvl();
}

void Log::format(const tchar *s) {
    FastLocker lkr(lck);

    _format(s);
}

void Log::_format(const tchar *s) {
    tstring::size_type pos;

    fmt = s;
    last_sec = -1;
    if ((pos = fmt.find(T("%#"))) != fmt.npos)
	fmt.replace(pos, 2, USubst);
#ifdef NO_PERCENT_Z
    if ((pos = fmt.find(T("%z"))) != fmt.npos)
	fmt.replace(pos, 2, ZSubst);
#endif
}

void Log::gmttime(bool b) {
    PauseFlush pf(*this);

    gmt = afd.gmt = ffd.gmt = b;
}

void Log::mail(Level l, const tchar *to, const tchar *from, const tchar
    *host) {
    Locker lkr(lck);

    _mail(l, to, from, host);
    updatelvl();
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

void Log::syslog(bool b) {
    Locker lkr(lck);

    syslogenable = b;
    if (b && !sysloghost.empty() && !syslogsock.open())
	_syslog(sysloglvl, sysloghost.c_str(), syslogfac);
    updatelvl();
}

void Log::syslog(Level l, const tchar *host, uint fac) {
    Locker lkr(lck);

    _syslog(l, host, fac);
    updatelvl();
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
	!syslogsock.open(syslogaddr.family())) {
	syslogenable = false;
	syslogsock.close();
    }
}

bool Log::close(void) {
    PauseFlush pf(*this);

    drainbuffers(false);
    afd.close();
    return ffd.close();
}

// 16 byte SIMD scans; strings under 16 bytes use the scalar loops
#if !defined(_WIN32) && (defined(__SSE2__) || defined(__ARM_NEON))
#define SIMD16
#ifdef __SSE2__
using simd16 = __m128i;

static __forceinline simd16 load16(const char *p) {
    return _mm_loadu_si128((const __m128i *)p);
}

// offset of the first flagged byte or 16 if none
static __forceinline uint first16(simd16 m) {
    return (uint)countr_zero((uint)_mm_movemask_epi8(m) | 0x10000U);
}

// control chars other than tab
static __forceinline simd16 esc16(simd16 c) {
    return _mm_andnot_si128(_mm_cmpeq_epi8(c, _mm_set1_epi8('\t')),
	_mm_cmpeq_epi8(_mm_min_epu8(c, _mm_set1_epi8(0x1f)), c));
}

// signed < '!' also flags bytes >= 0x80
static __forceinline simd16 quote16(simd16 c) {
    return _mm_or_si128(_mm_or_si128(_mm_cmplt_epi8(c, _mm_set1_epi8('!')),
	_mm_cmpeq_epi8(c, _mm_set1_epi8('"'))), _mm_or_si128(
	_mm_cmpeq_epi8(c, _mm_set1_epi8('\\')),
	_mm_cmpeq_epi8(c, _mm_set1_epi8(0x7f))));
}

static __forceinline simd16 dq16(simd16 c) {
    return _mm_or_si128(_mm_cmpeq_epi8(c, _mm_set1_epi8('"')),
	_mm_cmpeq_epi8(c, _mm_set1_epi8('\\')));
}

// control chars, '"', '\\' and DEL
static __forceinline simd16 qesc16(simd16 c) {
    return _mm_or_si128(_mm_or_si128(_mm_cmpeq_epi8(_mm_min_epu8(c,
	_mm_set1_epi8(0x1f)), c), _mm_cmpeq_epi8(c, _mm_set1_epi8(0x7f))),
	dq16(c));
}
#else
using simd16 = uint8x16_t;

static __forceinline simd16 load16(const char *p) {
    return vld1q_u8((const uint8_t *)p);
}

static __forceinline uint first16(simd16 m) {
    // narrow to 4 bits per byte
    const uint64_t bits = vget_lane_u64(vreinterpret_u64_u8(
	vshrn_n_u16(vreinterpretq_u16_u8(m), 4)), 0);

    return (uint)countr_zero(bits) >> 2;
}

static __forceinline simd16 esc16(simd16 c) {
    return vbicq_u8(vcltq_u8(c, vdupq_n_u8(' ')), vceqq_u8(c,
	vdupq_n_u8('\t')));
}

static __forceinline simd16 quote16(simd16 c) {
    return vorrq_u8(vorrq_u8(vcltq_s8(vreinterpretq_s8_u8(c),
	vdupq_n_s8('!')), vceqq_u8(c, vdupq_n_u8('"'))), vorrq_u8(
	vceqq_u8(c, vdupq_n_u8('\\')), vceqq_u8(c, vdupq_n_u8(0x7f))));
}

static __forceinline simd16 dq16(simd16 c) {
    return vorrq_u8(vceqq_u8(c, vdupq_n_u8('"')), vceqq_u8(c,
	vdupq_n_u8('\\')));
}

static __forceinline simd16 qesc16(simd16 c) {
    return vorrq_u8(vorrq_u8(vcltq_u8(c, vdupq_n_u8(' ')), vceqq_u8(c,
	vdupq_n_u8(0x7f))), dq16(c));
}
#endif

// first byte in [p, end) flagged by match, or p if under 16 bytes
template<class F>
static __forceinline const char *scan16(const char *p, const char *end,
    F match) {
    if (end - p < 16)
	return p;
    for (; end - p > 16; p += 16) {
	if (uint u = first16(match(load16(p))); u < 16)
	    return p + u;
    }
    p = end - 16;		// may overlap the previous block
    return p + first16(match(load16(p)));
}
#endif

void Log::strm_write_esc(tbufferstream &strm, const tchar *data, streamsize sz) {
    const tchar *q = data;
    const tchar *end = data + sz;

#ifdef SIMD16
    q = scan16(q, end, esc16);
#endif
    while (q < end && LIKELY(!((tuchar)*q < ' ' && *q != '\t')))
	++q;
    if (LIKELY(q == end)) {
	strm.write(data, sz);
	return;
    }
    // slow path: escape control chars into strm
    const tchar *p = q;
    const tchar *start = q;

    strm.write(data, (streamsize)(q - data));
    while (p < end) {
	if (UNLIKELY((tuchar)*p < ' ' && *p != '\t')) {
	    if (p > start)
		strm.write(start, (streamsize)(p - start));
	    if (*p == '\n') {
		strm.write(T("\\n"), 2);
	    } else if (*p == '\r') {
		strm.write(T("\\r"), 2);
	    } else {
		tchar oct[4] = {
		    '\\',
		    (tchar)('0' + (((uchar)*p >> 6) & 7)),
		    (tchar)('0' + (((uchar)*p >> 3) & 7)),
		    (tchar)('0' + ((uchar)*p & 7))
		};

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

    if (clvl == None || clvl > level()) {
	tlsd.clvl = None;
	tlsd.sep = '\0';
	tlsd.strm.reset();
	return;
    }

    const Type tp = _type.load(memory_order_relaxed);
    size_t tmlen, taillvllen;
    time_t now_sec;
    tstring &strbuf(tlsd.strbuf);
    tstring &tailbuf(tlsd.tailbuf);
    size_t sz = (size_t)tlsd.strm.size();

    // build text without timestamp outside of lock
    tailbuf.erase();
    if (tp == KeyVal) {
	tailbuf += T("ll=");
	tailbuf += LevelStr2[clvl];
	tailbuf += ' ';
    } else if (tp != NoLevel) {
	tailbuf += LevelStr[clvl];
	if (tp == Syslog)
	    tailbuf += ':';
	tailbuf += ' ';
    }
    taillvllen = tailbuf.size();
    if (!tlsd.prefix.empty()) {
	tailbuf += tlsd.prefix;
	if (tp == Syslog)
	    tailbuf += ':';
	tailbuf += ' ';
    }
    if (tp == KeyVal) {
	const tchar *p = tlsd.strm.view().data();
	const tchar *end = p + sz;

	tailbuf.append(T("txt=\""), 5);
	for (;;) {
	    const tchar *q = p;

#ifdef SIMD16
	    q = scan16(q, end, dq16);
#endif
	    while (q < end && *q != '"' && *q != '\\')
		++q;
	    tailbuf.append(p, (size_t)(q - p));
	    if (q == end)
		break;
	    tailbuf += '\\';
	    tailbuf += *q;
	    p = q + 1;
	}
	tailbuf += '"';
    } else {
	tailbuf.append(tlsd.strm.view());
    }
    tailbuf += '\n';

    lck.lock();
    bool aenabled = afd.enable && clvl <= afd.lvl;
    bool fenabled = ffd.enable && clvl <= ffd.lvl;

    if (fenabled && !bufenable) {
	// unbuffered logs must check size and roll inline
	ffd.lock();
	if (ffd.sz && ffd.len >= ffd.sz)
	    ffd.roll();
    }
    if (aenabled) {
	afd.lock();
	if (afd.sz && afd.len >= afd.sz)
	    afd.roll();
    }
    const bool syslogit = syslogenable && clvl <= sysloglvl;

    if (tp == NoTime) {
	strbuf.erase();
	// only the syslog timestamp needs the clock
	now_sec = syslogit ? ::time(NULL) : 0;
    } else {
	struct timeval now_tv;

	gettimeofday(&now_tv, NULL);
	now_sec = now_tv.tv_sec;
	if (now_sec != last_sec) {
	    tchar tbuf[128];
	    struct tm tmbuf;
	    const struct tm *tm;

	    tm = gmt ? gmtime_r(&now_sec, &tmbuf) :
		localtime_r(&now_sec, &tmbuf);
	    tstrftime(tbuf, std::size(tbuf), fmt.c_str(), tm);
	    last_format = tbuf;
	    last_sec = now_sec;
#ifdef NO_PERCENT_Z
	    tstring::size_type zpos;

	    if ((zpos = last_format.find(ZSubst)) != last_format.npos) {
		int diff;
		tchar gmtoff[5];
		struct tm tmbuf2 {};
		const struct tm *tm2;

		tm2 = gmt ? localtime_r(&now_sec, &tmbuf2) : tm;
		tm = gmt ? tm : gmtime_r(&now_sec, &tmbuf2);
		diff = (tm2->tm_hour - tm->tm_hour) * 100 + tm2->tm_min -
		    tm->tm_min;
		if (tm->tm_wday != tm2->tm_wday)
		    diff -= 2400 * (tm->tm_wday > tm2->tm_wday ||
			(tm->tm_wday == 0 && tm2->tm_wday == 6) ? 1 : -1);
		// leading 1 zero pads to 4 digits, then becomes the sign
		(void)to_chars(gmtoff, gmtoff + 5, 10000U + (uint)abs(diff));
		gmtoff[0] = diff < 0 ? '-' : '+';
		last_format.replace(zpos, 2, gmtoff, 5);
	    }
#endif
	    upos = last_format.find(USubst);
	}
	if (upos == last_format.npos) {
	    strbuf = last_format;
	} else {
	    tchar cbuf[7];

	    // leading 1 zero pads to 6 digits
	    (void)to_chars(cbuf, cbuf + 7, 1000000U + (uint)now_tv.tv_usec);
	    strbuf.assign(last_format, 0, upos);
	    strbuf.append(cbuf + 1, 6);
	    strbuf.append(last_format, upos + 2, last_format.npos);
	}
	if (!strbuf.empty())
	    strbuf += ' ';
    }
    tmlen = strbuf.size();
    if ((fenabled && !bufenable) || (aenabled && src.empty()))
	strbuf += tailbuf;
    if (aenabled) {
	if (src.empty()) {
	    afd.print(strbuf);
	} else {
	    tstring ss;

	    ss.reserve(tmlen + tailbuf.size() + src.size() + 5);
	    ss.append(strbuf, 0, tmlen);
	    ss.append(tailbuf, 0, taillvllen);
	    ss += T("src=");
	    ss += src;
	    ss += ' ';
	    ss.append(tailbuf, taillvllen, tailbuf.npos);
	    afd.print(ss);
	}
	afd.unlock();
    }
    if (fenabled) {
	if (bufenable) {
	    bool b = bufcur->size() == 0;

	    bufcur->write(strbuf.data(), (streamsize)tmlen);
	    bufcur->write(tailbuf.data(), (streamsize)tailbuf.size());
	    if ((uint)bufcur->size() > bufsz) {
		rotatebuf();
		cv.broadcast();
	    } else if (b) {
		cv.broadcast();
	    }
	} else {
	    ffd.print(strbuf);
	    ffd.unlock();
	}
    }

    bool mailit = mailenable && clvl <= maillvl && !mailto.empty();
    tstring mfrom, mhost, mto;

    if (mailit) {
	mfrom = mailfrom;
	mhost = mailhost;
	mto = mailto;
    }
    tailbuf.pop_back();
    tlsd.clvl = None;
    tlsd.sep = '\0';
    tlsd.strm.reset();
    tlsd.suppress = true;
    if (syslogit) {
	static constexpr const char mon[][4] = { "Jan", "Feb", "Mar", "Apr",
	    "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec" };
	struct tm tmbuf {};
	localtime_r(&now_sec, &tmbuf);
	uint u = (syslogfac << 3) | (uint)(clvl - (clvl <= Debug ? 1 : 2));
	// RFC 3164 timestamp: C locale, no fraction
	string ss = std::format("<{}>{} {:2} {:02}:{:02}:{:02} {}", u,
	    mon[tmbuf.tm_mon], tmbuf.tm_mday, tmbuf.tm_hour, tmbuf.tm_min,
	    tmbuf.tm_sec, tstringtoastring(hostname));

	if (!mailfrom.empty() && mailfrom != T("<>")) {
	    ss += tp == KeyVal ? " nm=" : " ";
	    ss += tstringtoastring(mailfrom.substr(0, mailfrom.find('@')));
	}
	format_to(back_inserter(ss), "[{}]: {}", getpid(),
	    tstringtoastring(tailbuf));
	syslogsock.write(ss.data(), (uint)ss.size(), syslogaddr);
    }
    // syslog state is only stable under the lock; SMTP is slow so unlock first
    lck.unlock();
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
	    strbuf.resize(tmlen);
	    strbuf += tailbuf;
	    smtp.subject(tailbuf.substr(0, 69).c_str());
	    smtp.data(false, strbuf.c_str());
	    smtp.enddata();
	    smtp.quit();
	}
    }
    tlsd.suppress = false;
}

// queue the current buffer and continue writing into a free one
void Log::rotatebuf(void) {
    bufpending.push_back(std::move(bufcur));
    if (buffree.empty()) {
	bufcur = make_unique<tbufferstream>();
    } else {
	bufcur = std::move(buffree.back());
	buffree.pop_back();
    }
}

// drain all pending buffers and allow other threads to continue writing
void Log::drainbuffers(bool unlockedio) {
    if (bufcur->size())
	rotatebuf();
    while (!bufpending.empty()) {
	unique_ptr<tbufferstream> buf = std::move(bufpending.front());

	bufpending.pop_front();
	if (unlockedio)
	    lck.unlock();
	ffd.lock();
	ffd.print(buf->view());
	if (ffd.sz && ffd.len >= ffd.sz)
	    ffd.roll();
	ffd.unlock();
	(*buf).reset();
	if (unlockedio)
	    lck.lock();
	buffree.push_back(std::move(buf));
    }
}

void Log::logv(int il, ...) {
    if (UNLIKELY((Level)il <= None || (Level)il > level()))
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
	log(tlsd, p);
    va_end(vl);
    endlog(tlsd);
}

tbufferstream &Log::quote(tbufferstream &os, tstring_view s) {
    // chars >= 0x80 always need quoting
    static const uchar needquote[128] = {
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // NUL - SI
	1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,  // DLE - US
	1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // SPACE - /
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // 0 - ?
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // @ - O
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0,  // P - _
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,  // ` - o
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,  // p - DEL
    };
    const tchar *p = s.data();
    const tchar *end = p + s.size();

#ifdef SIMD16
    p = scan16(p, end, quote16);
#endif
    while (p < end && !((tuchar)*p >= 0x80 || needquote[(tuchar)*p]))
	++p;
    if (LIKELY(p == end)) {
	os.write(s.data(), (streamsize)s.size());
	return os;
    }

    const tchar *start = s.data();

    os.write(T('"'));
    for (;; ++p) {
#ifdef SIMD16
	p = scan16(p, end, qesc16);
#endif
	while (p < end && (tuchar)*p >= ' ' && *p != '"' && *p != '\\' &&
	    *p != 0x7f)
	    ++p;
	if (p == end)
	    break;

	const tuchar c = (tuchar)*p;
	tchar esc[4] = { '\\' };
	streamsize n = 2;

	switch (c) {
	case '"': case '\\': esc[1] = (tchar)c; break;
	case '\f': esc[1] = 'f'; break;
	case '\n': esc[1] = 'n'; break;
	case '\r': esc[1] = 'r'; break;
	case '\t': esc[1] = 't'; break;
	case '\v': esc[1] = 'v'; break;
	default:
	    esc[1] = (tchar)('0' + ((c >> 6) & 7));
	    esc[2] = (tchar)('0' + ((c >> 3) & 7));
	    esc[3] = (tchar)('0' + (c & 7));
	    n = 4;
	}
	os.write(start, p - start);
	os.write(esc, n);
	start = p + 1;
    }
    os.write(start, end - start);
    os.write(T('"'));
    return os;
}

void Log::set(const Config &cfg, const tchar *sect) {
    tstring::size_type pos;
    tstring s;

    stop();

    Locker lkr(lck);

    drainbuffers(false);
    bufsz = cfg.get(T("file.buffer.size"), 32U * 1024, sect);
    buftm = cfg.get(T("file.buffer.msec"), 1000UL, sect);
    bufenable = cfg.get(T("file.buffer.enable"), false, sect);
    gmt = cfg.get(T("gmt"), false, sect);
    s = Sockaddr::hostname();
    hostname = s.substr(0, s.find('.'));
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
    _format(cfg.get(T("format"), T("[%Y-%m-%d %H:%M:%S.%# %z]"), sect).c_str());
    s = cfg.get(T("type"), T("simple"), sect);
    _type.store(s == T("nolevel") ? NoLevel : s == T("notime") ? NoTime :
	s == T("syslog") ? Syslog : s == T("keyval") ? KeyVal : Simple,
	memory_order_relaxed);
    afd.set(cfg, sect, T("alert"), false, T("warn"), T("stderr"));
    ffd.set(cfg, sect, T("file"), true, T("info"), T("stdout"));
    updatelvl();
    lkr.unlock();
    buffer(bufenable);
}

bool Log::setids(uid_t uid, gid_t gid) {
#ifdef _WIN32
    (void)uid; (void)gid;
    return true;
#else
    PauseFlush pf(*this);
    // files open lazily: create them before the privilege drop
    auto own = [&](LogFile &f) {
	if (f.enable && f.fd == -1)
	    (void)f.reopen();
	return !f.enable || f.fd < 0 || f.file[0] == '>' ||
	    fchown(f.fd, uid, gid) == 0;
    };
    const bool alert = own(afd);

    return own(ffd) && alert;
#endif
}

void Log::setmp(bool b) {
    if (b)
	buffer(false);

    PauseFlush pf(*this);

    drainbuffers(false);
    ffd.close();
    mp = ffd.mp = b;
}

void Log::start(void) {
    Locker lkr(lck);

    if (bufenable && ft.getState() != Running) {
	ft.rearm();
	// own group so neither the caller's nor MainThreadGroup's destructor
	// can block on it before ~Log stops it
	ft.start(16U * 1024, &ftg);
    }
}

void Log::stop(void) {
    Locker lkr(lck);

    if (ft.getState() == Running) {
	ft.quit();
	cv.broadcast();
	lkr.unlock();
	ft.wait();
    }
}

void Log::flush(void) {
    PauseFlush pf(*this);

    drainbuffers(false);
}

bool Log::reopen(void) {
    PauseFlush pf(*this);

    return ffd.reopen();
}

void Log::roll(void) {
    PauseFlush pf(*this);

    ffd.roll();
}

Log::Level Log::str2enum(const tchar *l) {
    for (uint u = 0; u < std::size(LevelStr); ++u) {
	tstring_view sv = LevelStr[u];

	if (!sv.empty() && sv.back() == ' ')
	    sv.remove_suffix(1);
	if (stringieq(l, sv) || stringieq(l, LevelStr2[u]))
	    return (Level)u;
    }
    return None;
}

