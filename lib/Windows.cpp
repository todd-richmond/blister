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
#include <bcrypt.h>
#include <ctype.h>
#include <errno.h>
#include <mmsystem.h>
#include <fcntl.h>
#include <Psapi.h>
#include <share.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <winioctl.h>
#include <map>
#include <mutex>
#include <unordered_map>
#include <vector>

//-V::303
#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "winmm.lib")
#pragma warning(disable: 4305)
#pragma warning(disable: 4306)

#define to_fd(hdl)	    ((int)(ullong)hdl)

// 0-2 are the std streams: real handles are multiples of 4
static inline HANDLE to_handle(int fd) {
    return (uint)fd <= 2 ? GetStdHandle(STD_INPUT_HANDLE - (DWORD)fd) :
	(HANDLE)(llong)fd;
}

// UTF-16 never needs more code units than the UTF-8 input has bytes
wstring _achartowstring(string_view s) {
    wstring ret;

    ret.resize_and_overwrite(s.size(), [&s](wchar *buf, size_t n) {
	return (size_t)MultiByteToWideChar(CP_UTF8, 0, s.data(),
	    (int)s.size(), buf, (int)n);
    });
    return ret;
}

// each UTF-16 code unit expands to at most 3 UTF-8 bytes: convert short
// strings on the stack and size long ones first so ret is allocated exactly
string _wchartoastring(wstring_view s) {
    char sbuf[1024];
    int len = (int)s.size();
    string ret;

    if (s.size() <= sizeof (sbuf) / 3)
	return {sbuf, (size_t)WideCharToMultiByte(CP_UTF8, 0, s.data(), len,
	    sbuf, (int)sizeof (sbuf), NULL, NULL)};
    ret.resize_and_overwrite((size_t)WideCharToMultiByte(CP_UTF8, 0, s.data(),
	len, NULL, 0, NULL, NULL), [&s, len](char *buf, size_t n) {
	return (size_t)WideCharToMultiByte(CP_UTF8, 0, s.data(), len, buf,
	    (int)n, NULL, NULL);
    });
    return ret;
}

/*
 * POSIX fcntl lock emulation: one process never conflicts with itself and
 * any subrange can be unlocked or converted. Each entry is one Windows lock,
 * which only an unlock of the identical range releases
 */
// POSIX len 0 locks to EOF and beyond, stopping below the flock() byte
#define LOCK_EOF	0xFFFFFFFE00000000ULL

struct FileLock {
    ullong end;
    bool excl;
};

struct FileLocks {
    map<ullong, FileLock> locks;
    mutex mtx;
};

static unordered_map<int, FileLocks> locktbl;
static mutex locktblmtx;

static bool winlock(HANDLE hdl, ullong start, ullong end, bool excl,
    bool test) {
    ullong n = end - start;
    OVERLAPPED ov{};

    ov.Offset = (DWORD)start;
    ov.OffsetHigh = (DWORD)(start >> 32);
    return LockFileEx(hdl, (excl ? LOCKFILE_EXCLUSIVE_LOCK : 0) | (test ?
	LOCKFILE_FAIL_IMMEDIATELY : 0), 0, (DWORD)n, (DWORD)(n >> 32), &ov) !=
	0;
}

static void winunlock(HANDLE hdl, ullong start, ullong end) {
    ullong n = end - start;
    OVERLAPPED ov{};

    ov.Offset = (DWORD)start;
    ov.OffsetHigh = (DWORD)(start >> 32);
    UnlockFileEx(hdl, 0, (DWORD)n, (DWORD)(n >> 32), &ov);
}

// conversions and splits of exclusive locks briefly drop the range: Windows
// can neither convert a lock nor lock exclusively over a held range
static DWORD setlock(int fd, ullong start, ullong end, bool unlock,
    bool excl, bool test) {
    vector<pair<ullong, ullong>> added, conv;
    DWORD err = 0;
    HANDLE hdl = to_handle(fd);
    FileLocks *fl;
    map<ullong, FileLock>::iterator it;
    ullong pos = start;

    {
	lock_guard lk(locktblmtx);

	fl = &locktbl[fd];
    }

    lock_guard lk(fl->mtx);
    auto &locks = fl->locks;
    auto first = [&]() {
	auto i = locks.lower_bound(start);

	return i != locks.begin() && prev(i)->second.end > start ? prev(i) : i;
    };

    // lock the gaps between held ranges first so a conflict changes nothing
    for (it = first(); !unlock && pos < end; ++it) {
	ullong next = it == locks.end() || it->first >= end ? end : it->first;

	if (pos < next) {
	    if (!winlock(hdl, pos, next, excl, test)) {
		err = GetLastError();
		break;
	    }
	    added.emplace_back(pos, next);
	}
	if (next == end)
	    break;
	pos = (max)(pos, it->second.end);
    }
    for (it = first(); !err && it != locks.end() && it->first < end;) {
	ullong a = it->first, b = it->second.end;
	ullong is = (max)(a, start), ie = (min)(b, end);
	bool left, old = it->second.excl, right;

	if (!unlock && old == excl) {
	    ++it;
	    continue;
	}
	// our own shared locks may overlap so keep the outer pieces gap free
	if (old)
	    winunlock(hdl, a, b);
	left = a < is && winlock(hdl, a, is, old, true);
	right = ie < b && winlock(hdl, ie, b, old, true);
	if (!old)
	    winunlock(hdl, a, b);
	it = locks.erase(it);
	if (left)
	    locks.try_emplace(a, FileLock{is, old});
	if (right)
	    it = locks.try_emplace(ie, FileLock{b, old}).first;
	if (unlock)
	    continue;
	if (winlock(hdl, is, ie, excl, test)) {
	    locks.try_emplace(is, FileLock{ie, excl});
	    conv.emplace_back(is, ie);
	} else {
	    err = GetLastError();
	    if (winlock(hdl, is, ie, old, true))
		locks.try_emplace(is, FileLock{ie, old});
	}
    }
    if (!err) {
	for (const auto &[a, b] : added)
	    locks.try_emplace(a, FileLock{b, excl});
	return 0;
    }
    for (const auto &[a, b] : added)
	winunlock(hdl, a, b);
    // requests only convert the other lock type
    for (const auto &[a, b] : conv) {
	winunlock(hdl, a, b);
	if (winlock(hdl, a, b, !excl, true))
	    locks[a].excl = !excl;
	else
	    locks.erase(a);
    }
    return err;
}

// POSIX emulation and CRT replacements keep C linkage
extern "C" {

static void dosmaperr(ulong oserrno);

static int A_TO_W(const char *path, wchar *buf) {
    if (MultiByteToWideChar(CP_UTF8, 0, path, -1, buf, MAX_PATH) > 0)
	return 1;
    errno = GetLastError() == ERROR_INSUFFICIENT_BUFFER ? ENAMETOOLONG :
	EINVAL;
    return 0;
}

static int oserr(void) {
    dosmaperr(GetLastError());
    return -1;
}

#define EPOCH_BIAS  116444736000000000i64

int gettimeofday(struct timeval *tv, struct timezone *tz) {
    FILETIME ft;
    usec_t usec;

    GetSystemTimeAsFileTime(&ft);
    usec = (bit_cast<uint64_t>(ft) - EPOCH_BIAS) / 10;
    tv->tv_sec = (long)(usec / 1000000I64);
    tv->tv_usec = (long)(usec % 1000000I64);
    if (tz) {
	static int tzsetup;

	if (!tzsetup) {
	    TIME_ZONE_INFORMATION tzi;

	    tzset();
	    tzsetup = 1;
	    _daylight = GetTimeZoneInformation(&tzi) == TIME_ZONE_ID_DAYLIGHT;
	}
	tz->tz_minuteswest = _timezone / 60;
	tz->tz_dsttime = _daylight;
    }
    return 0;
}

static LARGE_INTEGER tps;

static inline void tps_init(void) {
    if (!tps.QuadPart)
	QueryPerformanceFrequency(&tps);
}

msec_t mticks(void) {
    LARGE_INTEGER now;

    tps_init();
    QueryPerformanceCounter(&now);
    return (ULONGLONG)now.QuadPart * 1000 / (ULONGLONG)tps.QuadPart;
}

usec_t uticks(void) {
    LARGE_INTEGER now;
    ULONGLONG freq, ticks;

    tps_init();
    QueryPerformanceCounter(&now);
    freq = (ULONGLONG)tps.QuadPart;
    ticks = (ULONGLONG)now.QuadPart;
    // split so ticks * 1000000 cannot overflow after ~21 days at 10MHz
    return ticks / freq * 1000000 + ticks % freq * 1000000 / freq;
}

int access(const char *path, int mode) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? waccess(pbuf, mode) : -1;
}

// ACLs aren't checked: only the read-only attribute denies W_OK on files
int waccess(const wchar *path, int mode) {
    DWORD attr = GetFileAttributesW(path);

    if (attr == INVALID_FILE_ATTRIBUTES) {
	dosmaperr(GetLastError());
	return -1;
    } else if (mode & W_OK && (attr & (FILE_ATTRIBUTE_DIRECTORY |
	FILE_ATTRIBUTE_READONLY)) == FILE_ATTRIBUTE_READONLY) {
	errno = EACCES;
	return -1;
    }
    return 0;
}

int chmod(const char *path, int mode) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wchmod(pbuf, mode) : -1;
}

// owner write permission maps to the read-only attribute
int wchmod(const wchar *path, int mode) {
    DWORD attr = GetFileAttributesW(path);

    if (attr != INVALID_FILE_ATTRIBUTES) {
	attr = ((mode & S_IWUSR) ? attr & ~FILE_ATTRIBUTE_READONLY : attr |
	    FILE_ATTRIBUTE_READONLY) & ~FILE_ATTRIBUTE_NORMAL;
	if (SetFileAttributesW(path, attr ? attr : FILE_ATTRIBUTE_NORMAL))
	    return 0;
    }
    dosmaperr(GetLastError());
    return -1;
}

int chsize(int fd, long len) {
    return ftruncate(fd, len);
}

int close(int fd) {
    if (fd == -1) {
	errno = EINVAL;
	return -1;
    }
    {
	lock_guard lk(locktblmtx);

	locktbl.erase(fd);
    }
    if (CloseHandle(to_handle(fd)))
	return 0;
    dosmaperr(GetLastError());
    return -1;
}

int creat(const char *path, int flag) {
    return open(path, O_CREAT | O_TRUNC | O_WRONLY, flag);
}

int wcreat(const wchar *path, int flag) {
    return wopen(path, O_CREAT | O_TRUNC | O_WRONLY, flag);
}

int copy_file(const char *from, const char *to, int check) {
    wchar fbuf[MAX_PATH], tbuf[MAX_PATH];

    return A_TO_W(from, fbuf) && A_TO_W(to, tbuf) ? wcopy_file(fbuf, tbuf,
	check) : -1;
}

int wcopy_file(const wchar *from, const wchar *to, int check) {
    if (CopyFileW(from, to, check))
	return 0;
    dosmaperr(GetLastError());
    return -1;
}

int dup(int fd) {
    HANDLE hdl;

    if (!DuplicateHandle(GetCurrentProcess(), to_handle(fd),
	GetCurrentProcess(), &hdl, 0L, TRUE, DUPLICATE_SAME_ACCESS)) {
	dosmaperr(GetLastError());
	return -1;
    }
    return to_fd(hdl);
}

// fds are handles so only the std streams can be targets
int dup2(int from, int to) {
    HANDLE hdl, old = to_handle(to);

    if (to < 0 || to > 2) {
	errno = EBADF;
	return -1;
    } else if (!DuplicateHandle(GetCurrentProcess(), to_handle(from),
	GetCurrentProcess(), &hdl, 0L, TRUE, DUPLICATE_SAME_ACCESS)) {
	dosmaperr(GetLastError());
	return -1;
    } else if (!SetStdHandle(STD_INPUT_HANDLE - (DWORD)to, hdl)) {
	dosmaperr(GetLastError());
	CloseHandle(hdl);
	return -1;
    }
    if (old && old != INVALID_HANDLE_VALUE)
	CloseHandle(old);
    return to;
}

int eof(int fd) {
    LARGE_INTEGER pos = {.QuadPart = 0}, sz = {.QuadPart = 0};

    if (!SetFilePointerEx(to_handle(fd), pos, &pos, FILE_CURRENT) ||
	!GetFileSizeEx(to_handle(fd), &sz)) {
	dosmaperr(GetLastError());
	return -1;
    }
    return pos.QuadPart >= sz.QuadPart;
}

FILE *fdopen(int fd, const char *how) {
    int flags = 0;

    if (*how == 'a')
	flags |= O_APPEND;
    else if (!strcmp(how, "r"))
	flags |= O_RDONLY;
    return _fdopen(_open_osfhandle(fd, flags), how);
}

int flock(int fd, int op) {
    if (op == LOCK_UN) {
	if (!UnlockFile(to_handle(fd), 0, (uint)-2, 1, 0)) {
	    dosmaperr(GetLastError());
	    return -1;
	}
    } else {
	OVERLAPPED ov;
	int flag = 0;

	ZERO(ov);
	ov.OffsetHigh = (UINT)-2;
	if (op & LOCK_EX)
	    flag |= LOCKFILE_EXCLUSIVE_LOCK;
	if (op & LOCK_NB)
	    flag |= LOCKFILE_FAIL_IMMEDIATELY;
	if (!LockFileEx(to_handle(fd), flag, 0, 1, 0, &ov)) {
	    dosmaperr(GetLastError());
	    return -1;
	}
    }
    return 0;
}

/* fsync emulation - don't fail on console output */
int fsync(int fd) {
    if (!FlushFileBuffers(to_handle(fd)) && GetFileType(to_handle(fd)) !=
	FILE_TYPE_CHAR) {
	dosmaperr(GetLastError());
	return -1;
    }
    return 0;
}

// SetEndOfFile would move the file pointer: POSIX leaves it alone
long filelength(int fd) {
    LARGE_INTEGER sz;

    if (!GetFileSizeEx(to_handle(fd), &sz)) {
	dosmaperr(GetLastError());
	return -1;
    } else if (sz.QuadPart > LONG_MAX) {
	errno = EOVERFLOW;
	return -1;
    }
    return (long)sz.QuadPart;
}

int isatty(int fd) {
    DWORD mode;

    if (GetConsoleMode(to_handle(fd), &mode))
	return 1;
    errno = ENOTTY;
    return 0;
}

int ftruncate(int fd, llong len) {
    FILE_END_OF_FILE_INFO eof;

    eof.EndOfFile.QuadPart = len;
    if (SetFileInformationByHandle(to_handle(fd), FileEndOfFileInfo, &eof,
	sizeof (eof)))
	return 0;
    dosmaperr(GetLastError());
    return -1;
}

// resolve a POSIX lock range: len 0 runs to EOF and negative len ends at start
static int lockrange(int fd, short whence, llong start, llong len,
    ullong *s, ullong *e) {
    LARGE_INTEGER li = {.QuadPart = 0};

    if (whence == SEEK_CUR) {
	if (!SetFilePointerEx(to_handle(fd), li, &li, FILE_CURRENT))
	    return oserr();
	start += li.QuadPart;
    } else if (whence == SEEK_END) {
	if (!GetFileSizeEx(to_handle(fd), &li))
	    return oserr();
	start += li.QuadPart;
    }
    if (len < 0) {
	start += len;
	len = -len;
    }
    if (start < 0) {
	errno = EINVAL;
	return -1;
    }
    *s = (ullong)start;
    *e = len ? *s + (ullong)len : LOCK_EOF;
    if (*e <= *s) {
	errno = EINVAL;
	return -1;
    }
    return 0;
}

/*
 * conflicting lock type or F_UNLCK, ignoring our own locks like POSIX. Ranges
 * we hold shared can't reveal other shared holders, so a write query passes
 */
static short getlock(int fd, ullong start, ullong end, bool excl) {
    vector<pair<ullong, ullong>> gaps;
    HANDLE hdl = to_handle(fd);
    FileLocks *fl = NULL;
    ullong pos = start;

    {
	lock_guard lk(locktblmtx);

	if (auto it = locktbl.find(fd); it != locktbl.end())
	    fl = &it->second;
    }
    if (fl) {
	lock_guard lk(fl->mtx);

	for (const auto &[a, l] : fl->locks) {
	    if (l.end <= pos)
		continue;
	    if (a >= end)
		break;
	    if (pos < a)
		gaps.emplace_back(pos, a);
	    pos = l.end;
	}
    }
    if (pos < end)
	gaps.emplace_back(pos, end);
    for (const auto &[a, b] : gaps) {
	if (winlock(hdl, a, b, excl, true)) {
	    winunlock(hdl, a, b);
	} else if (excl && winlock(hdl, a, b, false, true)) {
	    winunlock(hdl, a, b);
	    return F_RDLCK;
	} else {
	    return F_WRLCK;
	}
    }
    return F_UNLCK;
}

static int setlockrange(int fd, short type, short whence, llong start,
    llong len, bool test) {
    DWORD err;
    ullong e, s;

    if (lockrange(fd, whence, start, len, &s, &e))
	return -1;
    if (type != F_RDLCK && type != F_WRLCK && type != F_UNLCK) {
	errno = EINVAL;
	return -1;
    }
    if ((err = setlock(fd, s, e, type == F_UNLCK, type == F_WRLCK, test)) ==
	0)
	return 0;
    if (err == ERROR_LOCK_VIOLATION)
	errno = EAGAIN;
    else
	dosmaperr(err);
    return -1;
}

int lockf(int fd, int op, llong len) {
    ullong e, s;

    if (op != F_TEST)
	return setlockrange(fd, op == F_ULOCK ? F_UNLCK : F_WRLCK, SEEK_CUR,
	    0, len, op == F_TLOCK);
    if (lockrange(fd, SEEK_CUR, 0, len, &s, &e))
	return -1;
    if (getlock(fd, s, e, true) == F_UNLCK)
	return 0;
    errno = EACCES;
    return -1;
}

int lockfile(int fd, short op, short whence, ulong start, ulong len,
    short test) {
    return setlockrange(fd, op, whence, (llong)start, (llong)len, test != 0);
}

long lseek(int fd, long pos, int from) {
    LARGE_INTEGER li;

    li.QuadPart = pos;
    if (!SetFilePointerEx(to_handle(fd), li, &li, (DWORD)from)) {
	dosmaperr(GetLastError());
	return -1;
    } else if (li.QuadPart > LONG_MAX) {
	errno = EOVERFLOW;
	return -1;
    }
    return (long)li.QuadPart;
}

/* read emulation - does not work if fd was opened O_TEXT */
int read(int fd, void *buf, uint len) {
    DWORD in;

    // short count so the int return can't go negative
    if (ReadFile(to_handle(fd), buf, (min)(len, (uint)INT_MAX), &in, NULL))
	return (int)in;
    // a closed pipe writer is EOF
    return GetLastError() == ERROR_BROKEN_PIPE ? 0 : oserr();
}

/*
 * readv emulation: ReadFileScatter has the same limits as WriteFileGather so
 * read into one buffer and scatter it which keeps the read atomic
 */
ssize_t readv(int fd, iovec *io, int num) {
    char sbuf[4096];
    char *buf;
    ullong total = 0;
    ssize_t in = 0;

    if (num == 1)
	return read(fd, io->iov_base, io->iov_len);
    for (int i = 0; i < num; i++)
	total += io[i].iov_len;
    if (total > 64 * 1024) {
	/* too large to copy: a short read means no more data is ready */
	for (int i = 0; i < num; i++) {
	    int n = read(fd, io[i].iov_base, io[i].iov_len);

	    if (n == -1)
		return in ? in : -1;
	    in += n;
	    if ((ulong)n < io[i].iov_len)
		break;
	}
	return in;
    }
    buf = total > sizeof (sbuf) ? (char *)malloc((size_t)total) : sbuf;
    if (buf == NULL) {
	errno = ENOMEM;
	return -1;
    }
    if ((in = read(fd, buf, (uint)total)) > 0) {
	ulong left = (ulong)in;
	const char *p = buf;

	for (int i = 0; left; i++) {
	    ulong n = io[i].iov_len < left ? io[i].iov_len : left;

	    memcpy(io[i].iov_base, p, n);
	    p += n;
	    left -= n;
	}
    }
    if (buf != sbuf)
	free(buf);
    return in;
}

/* write emulation - does not work if fd was opened O_TEXT */
int write(int fd, const void *buf, uint len) {
    DWORD out = 0;

    if (len && (!WriteFile(to_handle(fd), buf, (min)(len, (uint)INT_MAX),
	&out, NULL) || out == 0)) {
	dosmaperr(GetLastError());
	return -1;
    }
    return out;
}

/*
 * writev emulation: WriteFileGather needs unbuffered overlapped handles and
 * page aligned buffers so coalesce into a single WriteFile which keeps the
 * write atomic like POSIX writev
 */
ssize_t writev(int fd, const iovec *io, int num) {
    char sbuf[4096];
    char *buf, *p;
    ullong total = 0;
    ssize_t out = 0;

    if (num == 1)
	return write(fd, io->iov_base, io->iov_len);
    for (int i = 0; i < num; i++)
	total += io[i].iov_len;
    if (total > 64 * 1024) {
	/* too large to copy: stop at a short write so no data is skipped */
	for (int i = 0; i < num; i++) {
	    int n = write(fd, io[i].iov_base, io[i].iov_len);

	    if (n == -1)
		return out ? out : -1;
	    out += n;
	    if ((ulong)n < io[i].iov_len)
		break;
	}
	return out;
    }
    buf = total > sizeof (sbuf) ? (char *)malloc((size_t)total) : sbuf;
    if (!buf) {
	errno = ENOMEM;
	return -1;
    }
    p = buf;
    for (int i = 0; i < num; i++) {
	memcpy(p, io[i].iov_base, io[i].iov_len);
	p += io[i].iov_len;
    }
    out = write(fd, buf, (uint)total);
    if (buf != sbuf)
	free(buf);
    return out;
}

long tell(int fd) {
    return lseek(fd, 0, SEEK_CUR);
}

// the XXXXXX suffix is ASCII so it maps back to the same UTF-8 bytes
char *mktemp(char *path) {
    wchar pbuf[MAX_PATH];
    size_t len = strlen(path), wlen;

    if (len < 6 || !A_TO_W(path, pbuf) || !*wmktemp(pbuf) ||
	(wlen = wcslen(pbuf)) < 6) {
	if (len < 6)
	    errno = EINVAL;
	*path = '\0';
	return path;
    }
    for (size_t i = 1; i <= 6; i++)
	path[len - i] = (char)pbuf[wlen - i];
    return path;
}

wchar *wmktemp(wchar *path) {
    if (_wmktemp_s(path, wcslen(path) + 1))
	*path = L'\0';
    return path;
}

// handle fds never translate text
int setmode(int fd, int mode) {
    (void)fd;
    (void)mode;
    return O_BINARY;
}

static int fmask;

int umask(int mode) {
    int old = fmask;

    fmask = mode;
    return old;
}

WDIR *wopendir(const wchar *name) {
    WDIR *dirp;
    DWORD attr;
    const wchar *p;
    const wchar *wild = NULL;
    size_t len, wlen;

    if ((len = wcslen(name)) == 0) {
	errno = ENOENT;
	return NULL;
    }
    p = name + len - 1;
    if (*p != '\\' && *p != '/') {
	while (p >= name) {
	    if (*p == '?' || *p == '*')
		wild = p;
	    else if (*p == '\\' || *p == '/')
		break;
	    p--;
	}
	if (wild) {
	    wild = p + 1;
	    if (p < name)
		p = name;
	} else {
	    p = name + len;
	}
    }
    len = p - name;
    if (!wild)
	wild = L"*.*";
    wlen = wcslen(wild);
    if ((dirp = (WDIR *)malloc(sizeof (struct WDIR) + (len + 1 + wlen) *
	sizeof (wchar))) == NULL)
	return dirp;
    memcpy(dirp->path, name, len * sizeof (wchar));
    dirp->path[len] = '\0';
    if ((attr = GetFileAttributesW(dirp->path)) == (DWORD)-1 ||
	!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
	errno = ENOTDIR;
	free(dirp);
	return NULL;
    }
    dirp->path[len] = '/';
    memcpy(dirp->path + len + 1, wild, (wlen + 1) * sizeof (wchar)); // NOSONAR
    dirp->hdl = 0;
    dirp->dir.d_ino = NULL;
    dirp->dir.d_off = 0;
    dirp->dir.d_name = dirp->wfd.cFileName;
    return dirp;
}

DIR *opendir(const char *name) {
    DIR *dirp;
    wchar pbuf[MAX_PATH];
    WDIR *wdir;

    if (!A_TO_W(name, pbuf) || (wdir = wopendir(pbuf)) == NULL)
	return NULL;
    if ((dirp = (DIR *)malloc(sizeof (DIR))) == NULL) {
	wclosedir(wdir);
	errno = ENOMEM;
	return NULL;
    }
    dirp->wdir = wdir;
    dirp->dir.d_ino = NULL;
    dirp->dir.d_off = 0;
    dirp->dir.d_name = dirp->name;
    return dirp;
}

// d_off counts entries returned so telldir() is the next entry's position
struct wdirent *wreaddir(WDIR *dirp) {
    if (!dirp->hdl) {
	if ((dirp->hdl = FindFirstFileW(dirp->path, &dirp->wfd)) ==
	    INVALID_HANDLE_VALUE)
	    return NULL;
    } else if (dirp->hdl == INVALID_HANDLE_VALUE ||
	!FindNextFileW(dirp->hdl, &dirp->wfd)) {
	return NULL;
    }
    dirp->dir.d_off++;
    return &dirp->dir;
}

// each UTF-16 code unit expands to at most 3 UTF-8 bytes so name always fits
struct dirent *readdir(DIR *dirp) {
    const wdirent *wd;

    if ((wd = wreaddir(dirp->wdir)) == NULL)
	return NULL;
    WideCharToMultiByte(CP_UTF8, 0, wd->d_name, -1, dirp->name,
	(int)sizeof (dirp->name), NULL, NULL);
    dirp->dir.d_off = wd->d_off;
    return &dirp->dir;
}

void wseekdir(WDIR *dirp, long pos) {
    if (pos < dirp->dir.d_off) {
	if (dirp->hdl && dirp->hdl != INVALID_HANDLE_VALUE)
	    FindClose(dirp->hdl);
	dirp->hdl = 0;
	dirp->dir.d_off = 0;
    }
    while (dirp->dir.d_off < pos && wreaddir(dirp))
	continue;
}

void seekdir(DIR *dirp, long pos) {
    wseekdir(dirp->wdir, pos);
    dirp->dir.d_off = dirp->wdir->dir.d_off;
}

void wclosedir(WDIR *dirp) {
    if (dirp->hdl && dirp->hdl != INVALID_HANDLE_VALUE)
	FindClose(dirp->hdl);
    free(dirp);
}

void closedir(DIR *dirp) {
    wclosedir(dirp->wdir);
    free(dirp);
}

int link(const char *from, const char *to) {
    wchar fbuf[MAX_PATH], tbuf[MAX_PATH];

    return A_TO_W(from, fbuf) && A_TO_W(to, tbuf) ? wlink(fbuf, tbuf) : -1;
}

int wlink(const wchar *from, const wchar *to) {
    if (CreateHardLinkW(to, from, NULL))
	return 0;
    dosmaperr(GetLastError());
    return -1;
}

int open(const char *path, int oflag, ...) {
    int mode = 0;
    wchar pbuf[MAX_PATH];

    if (oflag & O_CREAT) {
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, int);
	va_end(ap);
    }
    return A_TO_W(path, pbuf) ? wopen(pbuf, oflag, mode) : -1;
}

int wopen(const wchar *path, int oflag, ...) {	// NOSONAR
    HANDLE hdl;
    DWORD fileaccess;
    DWORD fileshare;
    DWORD filecreate;
    DWORD fileattrib;
    SECURITY_ATTRIBUTES sa;
    int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

    if (oflag & O_CREAT) {
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, int);
	va_end(ap);
    }
    ZERO(sa);
    sa.nLength = sizeof (sa);
    sa.bInheritHandle = (oflag & O_NOINHERIT) ? FALSE : TRUE;
    switch (oflag & (O_RDONLY | O_WRONLY | O_RDWR)) {
    case O_RDONLY:
	fileaccess = GENERIC_READ;
	break;
    case O_WRONLY:
	fileaccess = GENERIC_WRITE;
	break;
    case O_RDWR:
	fileaccess = GENERIC_READ | GENERIC_WRITE;
	break;
    default:
	errno = EINVAL;
	_doserrno = 0L;		    /* not an OS error */
	return -1;
    }
    // append-only access makes every write atomically append; truncation
    // needs FILE_WRITE_DATA but leaves the file empty so writes start at EOF
    if (oflag & O_APPEND && !(oflag & O_TRUNC) && fileaccess & GENERIC_WRITE)
	fileaccess = (fileaccess & ~GENERIC_WRITE) | (FILE_GENERIC_WRITE &
	    ~FILE_WRITE_DATA);
    fileshare = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    switch (oflag & (O_CREAT | O_EXCL | O_TRUNC)) {
    case 0:
    case O_EXCL:		    /* ignore EXCL w/o CREAT */
	filecreate = OPEN_EXISTING;
	break;
    case O_CREAT:
	filecreate = OPEN_ALWAYS;
	break;
    case O_CREAT | O_EXCL:
    case O_CREAT | O_TRUNC | O_EXCL:
	filecreate = CREATE_NEW;
	break;
    case O_TRUNC:
    case O_TRUNC | O_EXCL:	    /* ignore EXCL w/o CREAT */
	filecreate = TRUNCATE_EXISTING;
	break;
    case O_CREAT | O_TRUNC:
	filecreate = CREATE_ALWAYS;
	break;
    default:
	/* this can't happen ... all cases are covered */
	errno = EINVAL;
	_doserrno = 0L;
	return -1;
    }
    fileattrib = FILE_ATTRIBUTE_NORMAL;
    if (oflag & O_CREAT && !(mode & ~fmask & S_IWUSR))
	fileattrib = FILE_ATTRIBUTE_READONLY;
    if (oflag & O_BACKUP)
	fileattrib |= FILE_FLAG_BACKUP_SEMANTICS;
    if (oflag & O_COMPRESSED)
	fileattrib |= FILE_ATTRIBUTE_COMPRESSED;
    if (oflag & O_DIRECT)
	fileattrib |= FILE_FLAG_NO_BUFFERING;
    if (oflag & O_OVERLAPPED)
	fileattrib |= FILE_FLAG_OVERLAPPED;
    if (oflag & O_POSIX)
	fileattrib |= FILE_FLAG_POSIX_SEMANTICS;
    if (oflag & O_SHORT_LIVED)
	fileattrib |= FILE_ATTRIBUTE_TEMPORARY;
    if (oflag & O_SYNC)
	fileattrib |= FILE_FLAG_WRITE_THROUGH;
    if (oflag & O_TEMPORARY)
	fileattrib |= FILE_FLAG_DELETE_ON_CLOSE;
    if (oflag & O_SEQUENTIAL)
	fileattrib |= FILE_FLAG_SEQUENTIAL_SCAN;
    else if (oflag & O_RANDOM)
	fileattrib |= FILE_FLAG_RANDOM_ACCESS;
    hdl = CreateFileW(path, fileaccess, fileshare, &sa,
	filecreate, fileattrib, NULL);
    if (hdl == INVALID_HANDLE_VALUE) {
	dosmaperr(GetLastError());
	return -1;
    }
    return to_fd(hdl);
}

// FAT, exFAT and SMB reject the POSIX semantics info classes
static bool no_posix_info(DWORD err) {
    return err == ERROR_INVALID_PARAMETER || err == ERROR_NOT_SUPPORTED ||
	err == ERROR_INVALID_FUNCTION;
}

int rename(const char *from, const char *to) {
    wchar fbuf[MAX_PATH], tbuf[MAX_PATH];

    return A_TO_W(from, fbuf) && A_TO_W(to, tbuf) ? wrename(fbuf, tbuf) : -1;
}

/* only ntifs.h defines this but FileRenameInfoEx accepts it since 1809 */
#ifndef FILE_RENAME_FLAG_IGNORE_READONLY_ATTRIBUTE
#define FILE_RENAME_FLAG_IGNORE_READONLY_ATTRIBUTE	0x00000040
#endif

/* atomically replace an existing target even if it is open, like POSIX */
int wrename(const wchar *from, const wchar *to) {
    alignas(FILE_RENAME_INFO) char buf[sizeof (FILE_RENAME_INFO) +
	MAX_PATH * sizeof (wchar)];
    auto *fri = (FILE_RENAME_INFO *)buf;
    wchar path[MAX_PATH];
    HANDLE hdl;
    DWORD err, len, sz;

    if ((len = GetFullPathNameW(to, MAX_PATH, path, NULL)) == 0 ||
	len >= MAX_PATH) {
	if (len)
	    errno = ENAMETOOLONG;
	else
	    dosmaperr(GetLastError());
	return -1;
    }
    if ((hdl = CreateFileW(from, DELETE, FILE_SHARE_READ | FILE_SHARE_WRITE |
	FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
	FILE_FLAG_OPEN_REPARSE_POINT, NULL)) == INVALID_HANDLE_VALUE) {
	dosmaperr(GetLastError());
	return -1;
    }
    fri->Flags = FILE_RENAME_FLAG_REPLACE_IF_EXISTS |
	FILE_RENAME_FLAG_POSIX_SEMANTICS |
	FILE_RENAME_FLAG_IGNORE_READONLY_ATTRIBUTE;
    fri->RootDirectory = NULL;
    fri->FileNameLength = len * sizeof (wchar);
    sz = (DWORD)(offsetof(FILE_RENAME_INFO, FileName) + ((size_t)len + 1) *
	sizeof (wchar));
    memcpy(buf + offsetof(FILE_RENAME_INFO, FileName), path,
	((size_t)len + 1) * sizeof (wchar));
    err = SetFileInformationByHandle(hdl, FileRenameInfoEx, fri, sz) ? 0 :
	GetLastError();
    CloseHandle(hdl);
    if (!err)
	return 0;
    if (no_posix_info(err)) {
	if (MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING))
	    return 0;
	err = GetLastError();
    }
    dosmaperr(err);
    return -1;
}

int unlink(const char *path) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wunlink(pbuf) : -1;
}

// symlinks and junctions to directories carry the directory attribute
static bool islink(const FILE_ATTRIBUTE_TAG_INFO *fati) {
    return fati->FileAttributes & FILE_ATTRIBUTE_REPARSE_POINT &&
	(fati->ReparseTag == IO_REPARSE_TAG_SYMLINK || fati->ReparseTag ==
	IO_REPARSE_TAG_MOUNT_POINT);
}

// remove the name immediately even if the file is open, like POSIX
static int posix_delete(const wchar *path, bool dir) {
    FILE_ATTRIBUTE_TAG_INFO fati = {};
    DWORD err;
    FILE_DISPOSITION_INFO_EX fdi;
    HANDLE hdl;

    // directories only open with FILE_FLAG_BACKUP_SEMANTICS
    if ((hdl = CreateFileW(path, DELETE | FILE_READ_ATTRIBUTES,
	FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
	OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS |
	FILE_FLAG_OPEN_REPARSE_POINT, NULL)) == INVALID_HANDLE_VALUE)
	return oserr();
    if (!GetFileInformationByHandleEx(hdl, FileAttributeTagInfo, &fati,
	sizeof (fati))) {
	err = GetLastError();
    } else if (islink(&fati) || !(fati.FileAttributes &
	FILE_ATTRIBUTE_DIRECTORY) ? dir : !dir) {
	CloseHandle(hdl);
	errno = dir ? ENOTDIR : EISDIR;
	return -1;
    } else {
	fdi.Flags = FILE_DISPOSITION_FLAG_DELETE |
	    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS |
	    FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE;
	err = SetFileInformationByHandle(hdl, FileDispositionInfoEx, &fdi,
	    sizeof (fdi)) ? 0 : GetLastError();
    }
    CloseHandle(hdl);
    if (!err)
	return 0;
    if (no_posix_info(err)) {
	if ((fati.FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ?
	    RemoveDirectoryW(path) : DeleteFileW(path))
	    return 0;
	err = GetLastError();
    }
    dosmaperr(err);
    return -1;
}

int wunlink(const wchar *path) {
    return posix_delete(path, false);
}

int rmdir(const char *path) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wrmdir(pbuf) : -1;
}

int wrmdir(const wchar *path) {
    return posix_delete(path, true);
}

/* stat that opens the file so that inodes are set properly */
int stat(const char *path, struct stat *buf) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wstat(pbuf, buf) : -1;
}

static ulong filetime_to_time(const FILETIME *ft) {
    ullong t = bit_cast<ullong>(*ft);

    return t > (ullong)EPOCH_BIAS ? (ulong)((t - (ullong)EPOCH_BIAS) /
	10000000) : 0;
}

static int file_stat(HANDLE hdl, struct stat *buf) {
    BY_HANDLE_FILE_INFORMATION bhfi;
    int perm;

    if (!GetFileInformationByHandle(hdl, &bhfi)) {
	dosmaperr(GetLastError());
	return -1;
    }
    perm = (bhfi.dwFileAttributes & FILE_ATTRIBUTE_READONLY) ? S_IREAD :
	S_IREAD | S_IWRITE;
    buf->st_mode = (ushort)(((bhfi.dwFileAttributes &
	FILE_ATTRIBUTE_DIRECTORY) ? S_IFDIR : S_IFREG) | perm | perm >> 3 |
	perm >> 6);
    buf->st_uid = buf->st_gid = 0;
    buf->st_nlink = (nlink_t)bhfi.nNumberOfLinks;
    buf->st_rdev = buf->st_dev = bhfi.dwVolumeSerialNumber;
    buf->st_atime = filetime_to_time(&bhfi.ftLastAccessTime);
    buf->st_mtime = filetime_to_time(&bhfi.ftLastWriteTime);
    buf->st_ctime = filetime_to_time(&bhfi.ftCreationTime);
    if (!buf->st_ctime)
	buf->st_ctime = buf->st_mtime;
    buf->st_size = (size_t)((ullong)bhfi.nFileSizeHigh << 32 |
	bhfi.nFileSizeLow);
    buf->st_ino = (ino_t)((ullong)bhfi.nFileIndexHigh << 32 |
	bhfi.nFileIndexLow);
    return 0;
}

// FILE_FLAG_BACKUP_SEMANTICS lets directories open
int wstat(const wchar *path, struct stat *buf) {
    HANDLE hdl;
    int ret;

    if ((hdl = CreateFileW(path, 0, FILE_SHARE_DELETE | FILE_SHARE_READ |
	FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
	NULL)) == INVALID_HANDLE_VALUE) {
	dosmaperr(GetLastError());
	return -1;
    }
    ret = file_stat(hdl, buf);
    CloseHandle(hdl);
    return ret;
}

int fstat(int fd, struct stat *buf) {
    return file_stat(to_handle(fd), buf);
}

int lstat(const char *path, struct stat *buf) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wlstat(pbuf, buf) : -1;
}

int wlstat(const wchar *path, struct stat *buf) {
    FILE_ATTRIBUTE_TAG_INFO fati;
    HANDLE hdl;
    int ret;

    if ((hdl = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE |
	FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
	FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL)) ==
	INVALID_HANDLE_VALUE)
	return oserr();
    if ((ret = file_stat(hdl, buf)) == 0 && GetFileInformationByHandleEx(hdl,
	FileAttributeTagInfo, &fati, sizeof (fati)) && islink(&fati))
	buf->st_mode = (ushort)((buf->st_mode & ~S_IFMT) | S_IFLNK);
    CloseHandle(hdl);
    return ret;
}

int fchmod(int fd, int mode) {
    FILE_BASIC_INFO fbi;
    DWORD attr;

    if (!GetFileInformationByHandleEx(to_handle(fd), FileBasicInfo, &fbi,
	sizeof (fbi)))
	return oserr();
    attr = ((mode & S_IWUSR) ? fbi.FileAttributes & ~FILE_ATTRIBUTE_READONLY :
	fbi.FileAttributes | FILE_ATTRIBUTE_READONLY) & ~FILE_ATTRIBUTE_NORMAL;
    // zero times and attributes mean unchanged
    ZERO(fbi);
    fbi.FileAttributes = attr ? attr : FILE_ATTRIBUTE_NORMAL;
    return SetFileInformationByHandle(to_handle(fd), FileBasicInfo, &fbi,
	sizeof (fbi)) ? 0 : oserr();
}

int fdatasync(int fd) {
    return fsync(fd);
}

static llong timeval_to_filetime(const struct timeval *tv) {
    return (llong)tv->tv_sec * 10000000 + (llong)tv->tv_usec * 10 +
	EPOCH_BIAS;
}

// NULL tv sets both times to now
int futimes(int fd, const struct timeval tv[2]) {
    FILE_BASIC_INFO fbi;

    ZERO(fbi);
    if (tv) {
	fbi.LastAccessTime.QuadPart = timeval_to_filetime(&tv[0]);
	fbi.LastWriteTime.QuadPart = timeval_to_filetime(&tv[1]);
    } else {
	GetSystemTimePreciseAsFileTime((FILETIME *)&fbi.LastWriteTime);
	fbi.LastAccessTime = fbi.LastWriteTime;
    }
    return SetFileInformationByHandle(to_handle(fd), FileBasicInfo, &fbi,
	sizeof (fbi)) ? 0 : oserr();
}

int utimes(const char *path, const struct timeval tv[2]) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wutimes(pbuf, tv) : -1;
}

int wutimes(const wchar *path, const struct timeval tv[2]) {
    HANDLE hdl;
    int ret;

    if ((hdl = CreateFileW(path, FILE_WRITE_ATTRIBUTES, FILE_SHARE_DELETE |
	FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
	FILE_FLAG_BACKUP_SEMANTICS, NULL)) == INVALID_HANDLE_VALUE)
	return oserr();
    ret = futimes(to_fd(hdl), tv);
    CloseHandle(hdl);
    return ret;
}

int truncate(const char *path, llong len) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wtruncate(pbuf, len) : -1;
}

int wtruncate(const wchar *path, llong len) {
    HANDLE hdl;
    int ret;

    if ((hdl = CreateFileW(path, GENERIC_WRITE, FILE_SHARE_DELETE |
	FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
	FILE_ATTRIBUTE_NORMAL, NULL)) == INVALID_HANDLE_VALUE)
	return oserr();
    ret = ftruncate(to_fd(hdl), len);
    CloseHandle(hdl);
    return ret;
}

int mkdir(const char *path, int mode) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wmkdir(pbuf, mode) : -1;
}

// directory permissions have no Windows equivalent
int wmkdir(const wchar *path, int mode) {
    (void)mode;
    return CreateDirectoryW(path, NULL) ? 0 : oserr();
}

// replace a trailing XXXXXX with random letters and digits
static bool tmpname(wchar *path) {
    static const char chars[] =
	"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    uchar rnd[6];
    size_t len = wcslen(path);

    if (len < 6 || wcscmp(path + len - 6, L"XXXXXX")) {
	errno = EINVAL;
	return false;
    }
    (void)BCryptGenRandom(NULL, rnd, sizeof (rnd),
	BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    for (size_t i = 0; i < 6; i++)
	path[len - 6 + i] = (wchar)chars[rnd[i] % (sizeof (chars) - 1)];
    return true;
}

// the suffix is ASCII so it maps back to the same UTF-8 bytes
static void tmpcopy(char *path, const wchar *wpath) {
    size_t len = strlen(path), wlen = wcslen(wpath);

    for (size_t i = 1; i <= 6; i++)
	path[len - i] = (char)wpath[wlen - i];
}

int mkstemp(char *path) {
    int fd;
    wchar pbuf[MAX_PATH];

    if (!A_TO_W(path, pbuf) || (fd = wmkstemp(pbuf)) == -1)
	return -1;
    tmpcopy(path, pbuf);
    return fd;
}

int wmkstemp(wchar *path) {
    for (int i = 0; i < 100; i++) {
	int fd;

	if (!tmpname(path))
	    return -1;
	if ((fd = wopen(path, O_CREAT | O_EXCL | O_RDWR | O_BINARY,
	    S_IRUSR | S_IWUSR)) != -1 || errno != EEXIST)
	    return fd;
	wcscpy(path + wcslen(path) - 6, L"XXXXXX");
    }
    return -1;
}

char *mkdtemp(char *path) {
    wchar pbuf[MAX_PATH];

    if (!A_TO_W(path, pbuf) || !wmkdtemp(pbuf))
	return NULL;
    tmpcopy(path, pbuf);
    return path;
}

wchar *wmkdtemp(wchar *path) {
    for (int i = 0; i < 100; i++) {
	if (!tmpname(path))
	    return NULL;
	if (CreateDirectoryW(path, NULL))
	    return path;
	if (GetLastError() != ERROR_ALREADY_EXISTS) {
	    oserr();
	    return NULL;
	}
	wcscpy(path + wcslen(path) - 6, L"XXXXXX");
    }
    errno = EEXIST;
    return NULL;
}

/*
 * reparse data layout from ntifs.h: mount points have no Flags so their
 * path starts there
 */
struct ReparseBuf {
    ULONG tag;
    USHORT datalen;
    USHORT reserved;
    USHORT subofs;
    USHORT sublen;
    USHORT printofs;
    USHORT printlen;
    ULONG flags;
    wchar path[MAXIMUM_REPARSE_DATA_BUFFER_SIZE / sizeof (wchar)];
};

ssize_t readlink(const char *path, char *buf, size_t sz) {
    wchar pbuf[MAX_PATH], wbuf[MAX_PATH];
    ssize_t len;
    string s;

    if (!A_TO_W(path, pbuf) || (len = wreadlink(pbuf, wbuf, MAX_PATH)) == -1)
	return -1;
    s = _wchartoastring(wstring_view(wbuf, (size_t)len));
    len = (ssize_t)(min)(s.size(), sz);
    memcpy(buf, s.data(), (size_t)len);
    return len;
}

// like POSIX the result is truncated to sz and not NUL terminated
ssize_t wreadlink(const wchar *path, wchar *buf, size_t sz) {
    DWORD err = 0, out;
    HANDLE hdl;
    size_t len;
    const wchar *p;
    auto *rb = (ReparseBuf *)calloc(1, sizeof (ReparseBuf));

    if (!rb) {
	errno = ENOMEM;
	return -1;
    }
    if ((hdl = CreateFileW(path, FILE_READ_ATTRIBUTES, FILE_SHARE_DELETE |
	FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING,
	FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT, NULL)) ==
	INVALID_HANDLE_VALUE) {
	err = GetLastError();
    } else {
	if (!DeviceIoControl(hdl, FSCTL_GET_REPARSE_POINT, NULL, 0, rb,
	    sizeof (*rb), &out, NULL))
	    err = GetLastError();
	CloseHandle(hdl);
    }
    if (err || (rb->tag != IO_REPARSE_TAG_SYMLINK && rb->tag !=
	IO_REPARSE_TAG_MOUNT_POINT)) {
	free(rb);
	if (err)
	    dosmaperr(err);	// NOT_A_REPARSE_POINT is EINVAL
	else
	    errno = EINVAL;
	return -1;
    }
    p = rb->tag == IO_REPARSE_TAG_SYMLINK ? rb->path : (const wchar *)
	&rb->flags;
    if (rb->printlen) {
	p += rb->printofs / sizeof (wchar);
	len = rb->printlen / sizeof (wchar);
    } else {
	p += rb->subofs / sizeof (wchar);
	len = rb->sublen / sizeof (wchar);
	if (len >= 4 && !wcsncmp(p, L"\\??\\", 4)) {
	    p += 4;
	    len -= 4;
	}
    }
    len = (min)(len, sz);
    wmemcpy(buf, p, len);
    free(rb);
    return (ssize_t)len;
}

int symlink(const char *target, const char *path) {
    wchar pbuf[MAX_PATH], tbuf[MAX_PATH];

    return A_TO_W(target, tbuf) && A_TO_W(path, pbuf) ? wsymlink(tbuf, pbuf) :
	-1;
}

// needs developer mode or SeCreateSymbolicLinkPrivilege
int wsymlink(const wchar *target, const wchar *path) {
    DWORD attr, flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    size_t tlen = wcslen(target);
    wchar full[MAX_PATH], tbuf[MAX_PATH];

    if (!tlen || tlen >= MAX_PATH) {
	errno = tlen ? ENAMETOOLONG : ENOENT;
	return -1;
    }
    // relative targets resolve against the link's directory and need '\\'
    for (size_t i = 0; i <= tlen; i++)
	tbuf[i] = target[i] == '/' ? '\\' : target[i];
    if (tbuf[0] != '\\' && tbuf[1] != ':') {
	size_t dlen = 0;

	for (const wchar *p = path; *p; p++) {
	    if (*p == '\\' || *p == '/')
		dlen = (size_t)(p - path) + 1;
	}
	if (dlen + tlen >= MAX_PATH) {
	    errno = ENAMETOOLONG;
	    return -1;
	}
	wmemcpy(full, path, dlen);
	wmemcpy(full + dlen, tbuf, tlen + 1);
    } else {
	wmemcpy(full, tbuf, tlen + 1);
    }
    if ((attr = GetFileAttributesW(full)) != INVALID_FILE_ATTRIBUTES &&
	attr & FILE_ATTRIBUTE_DIRECTORY)
	flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;
    return CreateSymbolicLinkW(path, tbuf, flags) ? 0 : oserr();
}

// result must hold PATH_MAX bytes; NULL mallocs it
char *realpath(const char *path, char *resolved) {
    wchar pbuf[MAX_PATH], wbuf[MAX_PATH];
    char buf[PATH_MAX * 3];
    int len;

    if (!A_TO_W(path, pbuf) || !wrealpath(pbuf, wbuf))
	return NULL;
    len = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, buf, (int)sizeof (buf),
	NULL, NULL);
    if (len > PATH_MAX) {
	errno = ENAMETOOLONG;
	return NULL;
    } else if (!resolved && (resolved = (char *)malloc((size_t)len)) ==
	NULL) {
	errno = ENOMEM;
	return NULL;
    }
    memcpy(resolved, buf, (size_t)len);
    return resolved;
}

// result must hold PATH_MAX wchars; NULL mallocs it
wchar *wrealpath(const wchar *path, wchar *resolved) {
    wchar buf[MAX_PATH + 8];
    HANDLE hdl;
    DWORD len;
    wchar *p = buf;

    if ((hdl = CreateFileW(path, 0, FILE_SHARE_DELETE | FILE_SHARE_READ |
	FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS,
	NULL)) == INVALID_HANDLE_VALUE) {
	oserr();
	return NULL;
    }
    len = GetFinalPathNameByHandleW(hdl, buf, MAX_PATH + 8, FILE_NAME_NORMALIZED
	| VOLUME_NAME_DOS);
    CloseHandle(hdl);
    if (!len) {
	oserr();
	return NULL;
    }
    // drop the \\?\ prefix: \\?\UNC\host becomes \\host
    if (len < MAX_PATH + 8 && !wcsncmp(buf, LR"(\\?\UNC\)", 8)) {
	p = buf + 6;
	*p = '\\';
    } else if (len < MAX_PATH + 8 && !wcsncmp(buf, LR"(\\?\)", 4)) {
	p = buf + 4;
    }
    if ((len -= (DWORD)(p - buf)) >= MAX_PATH) {
	errno = ENAMETOOLONG;
	return NULL;
    } else if (!resolved && (resolved = (wchar *)malloc((len + 1) *
	sizeof (wchar))) == NULL) {
	errno = ENOMEM;
	return NULL;
    }
    wmemcpy(resolved, p, len + 1);
    return resolved;
}

// F_GETFL/F_SETFL are no-ops: access modes aren't tracked or changeable
int fcntl(int fd, int cmd, ...) {
    va_list ap;
    DWORD flags;
    struct flock *fl = NULL;
    int arg = 0;
    ullong e, s;

    va_start(ap, cmd);
    if (cmd == F_GETLK || cmd == F_SETLK || cmd == F_SETLKW)
	fl = va_arg(ap, struct flock *);
    else if (cmd == F_DUPFD || cmd == F_SETFD || cmd == F_SETFL)
	arg = va_arg(ap, int);
    va_end(ap);
    switch (cmd) {
    case F_DUPFD:		    // handles can't be renumbered above arg
	return dup(fd);
    case F_GETFD:
	if (!GetHandleInformation(to_handle(fd), &flags))
	    return oserr();
	return (flags & HANDLE_FLAG_INHERIT) ? 0 : FD_CLOEXEC;
    case F_SETFD:
	return SetHandleInformation(to_handle(fd), HANDLE_FLAG_INHERIT, arg &
	    FD_CLOEXEC ? 0 : HANDLE_FLAG_INHERIT) ? 0 : oserr();
    case F_GETFL:
    case F_SETFL:
	return 0;
    case F_GETLK:
	if (lockrange(fd, fl->l_whence, fl->l_start, fl->l_len, &s, &e))
	    return -1;
	if ((fl->l_type = getlock(fd, s, e, fl->l_type == F_WRLCK)) !=
	    F_UNLCK) {
	    fl->l_whence = SEEK_SET;
	    fl->l_start = (llong)s;
	    fl->l_len = e == LOCK_EOF ? 0 : (llong)(e - s);
	    fl->l_pid = 0;		    // owner is unknown
	}
	return 0;
    case F_SETLK:
    case F_SETLKW:
	return setlockrange(fd, fl->l_type, fl->l_whence, fl->l_start,
	    fl->l_len, cmd == F_SETLK);
    default:
	errno = EINVAL;
	return -1;
    }
}

int pipe(int fds[2]) {
    HANDLE rd, wr;
    SECURITY_ATTRIBUTES sa = { sizeof (sa), NULL, TRUE };

    if (!CreatePipe(&rd, &wr, &sa, 0))
	return oserr();
    fds[0] = to_fd(rd);
    fds[1] = to_fd(wr);
    return 0;
}

// synchronous handles move the file pointer: POSIX leaves it alone
ssize_t pread(int fd, void *buf, size_t len, llong off) {
    DWORD err = 0, in;
    HANDLE hdl = to_handle(fd);
    OVERLAPPED ov{};
    LARGE_INTEGER pos = {};

    if (!SetFilePointerEx(hdl, pos, &pos, FILE_CURRENT))
	return oserr();
    ov.Offset = (DWORD)off;
    ov.OffsetHigh = (DWORD)((ullong)off >> 32);
    if (!ReadFile(hdl, buf, (DWORD)(min)(len, (size_t)MAXDWORD), &in, &ov))
	err = GetLastError();
    SetFilePointerEx(hdl, pos, NULL, FILE_BEGIN);
    if (!err)
	return (ssize_t)in;
    else if (err == ERROR_HANDLE_EOF)
	return 0;
    dosmaperr(err);
    return -1;
}

ssize_t pwrite(int fd, const void *buf, size_t len, llong off) {
    DWORD err = 0, out;
    HANDLE hdl = to_handle(fd);
    OVERLAPPED ov{};
    LARGE_INTEGER pos = {};

    if (!SetFilePointerEx(hdl, pos, &pos, FILE_CURRENT))
	return oserr();
    ov.Offset = (DWORD)off;
    ov.OffsetHigh = (DWORD)((ullong)off >> 32);
    if (!WriteFile(hdl, buf, (DWORD)(min)(len, (size_t)MAXDWORD), &out, &ov))
	err = GetLastError();
    SetFilePointerEx(hdl, pos, NULL, FILE_BEGIN);
    if (!err)
	return (ssize_t)out;
    dosmaperr(err);
    return -1;
}

int usleep(useconds_t usec) {
    struct timespec ts = { (time_t)(usec / 1000000), (long)(usec % 1000000) *
	1000 };

    return nanosleep(&ts, NULL);
}

int getpagesize(void) {
    SYSTEM_INFO si;

    GetSystemInfo(&si);
    return (int)si.dwPageSize;
}

long sysconf(int name) {
    switch (name) {
    case _SC_CLK_TCK:
	return 1000;
    case _SC_NPROCESSORS_CONF:
	return (long)GetMaximumProcessorCount(ALL_PROCESSOR_GROUPS);
    case _SC_NPROCESSORS_ONLN:
	return (long)GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    case _SC_OPEN_MAX:
	return 16 * 1024 * 1024;	    // per process handle limit
    case _SC_PAGESIZE:
	return getpagesize();
    default:
	errno = EINVAL;
	return -1;
    }
}

int clock_gettime(clockid_t id, struct timespec *ts) {
    FILETIME ct, et, kt, ut;
    ullong t;

    switch (id) {
    case CLOCK_REALTIME:
	GetSystemTimePreciseAsFileTime(&ct);
	t = (bit_cast<ullong>(ct) - (ullong)EPOCH_BIAS) * 100;
	break;
    case CLOCK_MONOTONIC: {
	LARGE_INTEGER now;
	ullong ticks;

	tps_init();
	QueryPerformanceCounter(&now);
	ticks = (ullong)now.QuadPart;
	ts->tv_sec = (time_t)(ticks / (ullong)tps.QuadPart);
	ts->tv_nsec = (long)(ticks % (ullong)tps.QuadPart * 1000000000 /
	    (ullong)tps.QuadPart);
	return 0;
    }
    case CLOCK_PROCESS_CPUTIME_ID:
	if (!GetProcessTimes(GetCurrentProcess(), &ct, &et, &kt, &ut))
	    return oserr();
	t = (bit_cast<ullong>(kt) + bit_cast<ullong>(ut)) * 100;
	break;
    case CLOCK_THREAD_CPUTIME_ID:
	if (!GetThreadTimes(GetCurrentThread(), &ct, &et, &kt, &ut))
	    return oserr();
	t = (bit_cast<ullong>(kt) + bit_cast<ullong>(ut)) * 100;
	break;
    default:
	errno = EINVAL;
	return -1;
    }
    ts->tv_sec = (time_t)(t / 1000000000);
    ts->tv_nsec = (long)(t % 1000000000);
    return 0;
}

// high resolution timers sleep below the 1 msec Sleep() granularity
int nanosleep(const struct timespec *req, struct timespec *rem) {
    HANDLE hdl;
    LARGE_INTEGER due;

    if (req->tv_nsec < 0 || req->tv_nsec >= 1000000000 || req->tv_sec < 0) {
	errno = EINVAL;
	return -1;
    }
    due.QuadPart = -((llong)req->tv_sec * 10000000 + (req->tv_nsec + 99) /
	100);
    if ((hdl = CreateWaitableTimerExW(NULL, NULL,
	CREATE_WAITABLE_TIMER_HIGH_RESOLUTION, TIMER_ALL_ACCESS)) == NULL)
	return oserr();
    if (SetWaitableTimer(hdl, &due, 0, NULL, NULL, FALSE))
	WaitForSingleObject(hdl, INFINITE);
    else
	Sleep((DWORD)(req->tv_sec * 1000 + (req->tv_nsec + 999999) / 1000000));
    CloseHandle(hdl);
    if (rem)
	rem->tv_sec = rem->tv_nsec = 0;
    return 0;
}

int statvfs(const char *path, struct statvfs *buf) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wstatvfs(pbuf, buf) : -1;
}

int wstatvfs(const wchar *path, struct statvfs *buf) {
    ulong bytesPerSector, freeClusters, sectorsPerCluster, totalClusters;
    const wchar *cp;
    int rc;

    /* try root directory. This doesn't handle filesystems not mapped
     * to drive a letter or a path without a drive letter
     */
    cp = wcschr(path, ':');
    if (cp) {
	wchar rootdir[4];
	size_t size = cp - path + 1;

	if (size >= std::size(rootdir))
	    size = std::size(rootdir) - 1;
	memcpy(rootdir, path, size * sizeof (wchar));
	rootdir[size] = '\0';
	rc = GetDiskFreeSpaceW(rootdir, &sectorsPerCluster, &bytesPerSector,
	    &freeClusters, &totalClusters);
    } else {
	rc = GetDiskFreeSpaceW(path, &sectorsPerCluster, &bytesPerSector,
	    &freeClusters, &totalClusters);
    }
    if (!rc) {
	dosmaperr(GetLastError());
	return -1;
    }
    memset(buf, 0, sizeof (*buf));
    buf->f_bsize = buf->f_frsize = sectorsPerCluster * bytesPerSector;
    buf->f_blocks = totalClusters;
    buf->f_bfree = buf->f_bavail = freeClusters;
    return 0;
}

int sigsend(idtype_t type, id_t id, int sig) {
    int ret;

    if (type != P_PID && type != P_PPID && type != P_SID && type != P_ALL)
	return -1;
    if (id < 0)
	id *= -1;
    if (sig == SIGINT || sig == SIGTERM)
	ret = GenerateConsoleCtrlEvent(CTRL_C_EVENT, id);
    else if (sig == SIGBREAK)
	ret = GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, id);
    else
	ret = 0;
    return ret ? 0 : -1;
}

int pidstat(pid_t pid, struct pidstat *psbuf) {
    FILETIME ct, et, kt, ut;
    HANDLE hdl;
    PROCESS_MEMORY_COUNTERS_EX pmc;
    int ret = 0;

    memset(psbuf, 0, sizeof (*psbuf));
    if (!pid || pid == (pid_t)GetCurrentProcessId())
	hdl = GetCurrentProcess();
    else if ((hdl = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE,
	(DWORD)pid)) == NULL)
	return -1;
    ZERO(pmc);
    if (GetProcessMemoryInfo(hdl, (PROCESS_MEMORY_COUNTERS *)&pmc,
	sizeof (pmc))) {
	psbuf->pss = psbuf->rss = pmc.WorkingSetSize / 1024;
	psbuf->sz = pmc.PrivateUsage / 1024;	// commit, not virtual size
    } else {
	ret = -1;
    }
    if (GetProcessTimes(hdl, &ct, &et, &kt, &ut)) {
	psbuf->stime = bit_cast<uint64_t>(kt) / 10000;	// 100ns -> msec
	psbuf->utime = bit_cast<uint64_t>(ut) / 10000;
    }
    if (hdl != GetCurrentProcess())
	CloseHandle(hdl);
    return ret;
}

/*
 * the UCRT keeps its Win32 to errno map internal: this matches it except for
 * POSIX codes it lacks and DOS / OS/2 era errors NT never returns
 */
static void dosmaperr(ulong oserrno) {
    int err;

    _doserrno = oserrno;
    switch (oserrno) {
    case ERROR_FILE_NOT_FOUND:
    case ERROR_PATH_NOT_FOUND:
    case ERROR_INVALID_DRIVE:
    case ERROR_NO_MORE_FILES:
    case ERROR_BAD_NETPATH:
    case ERROR_BAD_NET_NAME:
    case ERROR_BAD_PATHNAME:
	err = ENOENT;
	break;
    case ERROR_ACCESS_DENIED:
    case ERROR_CURRENT_DIRECTORY:
    case ERROR_NETWORK_ACCESS_DENIED:
    case ERROR_CANNOT_MAKE:
    case ERROR_DRIVE_LOCKED:
    case ERROR_SEEK_ON_DEVICE:
    case ERROR_NOT_LOCKED:
    case ERROR_LOCK_FAILED:
	err = EACCES;
	break;
    case ERROR_FILE_EXISTS:
    case ERROR_ALREADY_EXISTS:
	err = EEXIST;
	break;
    case ERROR_INVALID_HANDLE:
    case ERROR_INVALID_TARGET_HANDLE:
	err = EBADF;
	break;
    case ERROR_NOT_ENOUGH_MEMORY:
    case ERROR_NOT_ENOUGH_QUOTA:
	err = ENOMEM;
	break;
    case ERROR_BROKEN_PIPE:
    case ERROR_NO_DATA:
	err = EPIPE;
	break;
    case ERROR_DISK_FULL:
    case ERROR_HANDLE_DISK_FULL:
	err = ENOSPC;
	break;
    case ERROR_BAD_ENVIRONMENT:
	err = E2BIG;
	break;
    case ERROR_BAD_FORMAT:
	err = ENOEXEC;
	break;
    case ERROR_CANT_RESOLVE_FILENAME:
	err = ELOOP;
	break;
    case ERROR_DIR_NOT_EMPTY:
	err = ENOTEMPTY;
	break;
    case ERROR_DIRECTORY:
	err = ENOTDIR;
	break;
    case ERROR_FILENAME_EXCED_RANGE:
	err = ENAMETOOLONG;
	break;
    case ERROR_MAX_THRDS_REACHED:
	err = EAGAIN;
	break;
    case ERROR_NOT_SAME_DEVICE:
	err = EXDEV;
	break;
    case ERROR_NOT_SUPPORTED:
	err = ENOTSUP;
	break;
    case ERROR_PRIVILEGE_NOT_HELD:
	err = EPERM;
	break;
    case ERROR_TOO_MANY_OPEN_FILES:
	err = EMFILE;
	break;
    case ERROR_WAIT_NO_CHILDREN:
	err = ECHILD;
	break;
    default:
	if (oserrno >= ERROR_WRITE_PROTECT && oserrno <=
	    ERROR_SHARING_BUFFER_EXCEEDED)
	    err = EACCES;
	else if (oserrno >= ERROR_INVALID_STARTING_CODESEG && oserrno <=
	    ERROR_INFLOOP_IN_RELOC_CHAIN)
	    err = ENOEXEC;
	else
	    err = EINVAL;
    }
    errno = err;
}

}
#endif
