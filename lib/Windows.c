/*
 * Copyright 2001-2010 Todd Richmond
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
#include <ctype.h>
#include <errno.h>
#include <mmsystem.h>
#include <fcntl.h>
#include <share.h>
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <windows.h>

#pragma comment(lib, "winmm.lib")
#pragma warning(disable: 4305)
#pragma warning(disable: 4306)

#define HASH_SIZE	    769
#define rename_unlock(lck)  if (locks) InterlockedExchange(locks + lck, 0)

static HANDLE lockhdl;
static long *locks;

#ifdef _DLL
#define _dosmaperr	__dosmaperr
static void _dosmaperr(ulong oserrno);
#endif

static ulong local_to_time_t(SYSTEMTIME *stm);

static int A_TO_W(const char *path, wchar *buf) {
    DWORD len;

    if ((len = MultiByteToWideChar(CP_ACP, 0, path, (int)strlen(path) + 1, buf,
	MAX_PATH)) > 0 && len <= MAX_PATH)
	return 1;
    errno = EINVAL;
    return 0;
}

static void __cdecl stdapi_cleanup(void) {
    UnmapViewOfFile(locks);
    locks = NULL;
    CloseHandle(lockhdl);
}

#define EPOCH_BIAS  116444736000000000i64

int gettimeofday(struct timeval *tv, struct timezone *tz) {
    union {
	uint64 u64;
	FILETIME ft;
    } ft;
    usec_t usec;

    GetSystemTimeAsFileTime(&ft.ft);
    usec = (ft.u64 - EPOCH_BIAS) / 10;
    tv->tv_sec = (long)(usec / 1000000i64);
    tv->tv_usec = (long)(usec % 1000000i64);
    if (tz) {
	static int tzsetup;

	if (!tzsetup) {
	    TIME_ZONE_INFORMATION tzinfo;

	    tzset();
	    tzsetup = 1;
	    _daylight = GetTimeZoneInformation(&tzinfo) == TIME_ZONE_ID_DAYLIGHT;
	}
	tz->tz_minuteswest = _timezone / 60;
	tz->tz_dsttime = _daylight;
    }
    return 0;
}

msec_t milliticks(void) {
    ulong now;
    msec_t ret;
    static ulong cnt = (ulong)-1, last = (ulong)-1;
    static volatile long lck;

    while (InterlockedExchange(&lck, 1))
	YieldProcessor();
    now = timeGetTime();	    /* GetTickCount() only has 16ms accuracy */
    if (now < last) {
	if (++cnt) {
	    ulong tmp = now;

	    now += now - last;
	    last = tmp;
	} else {
	    last = now;
	}
    }
    ret = (msec_t)cnt * (ulong)-1 + now - last;
    InterlockedExchange(&lck, 0);
    return ret;
}

usec_t microticks(void) {
    static uint64 tps;

    if (tps) {
	uint64 now;

	if (QueryPerformanceCounter((LARGE_INTEGER *)&now))
	    return now * 1000000 / tps;
    } else {
	static int lck;

	if (!lck) {
	    QueryPerformanceFrequency((LARGE_INTEGER *)&tps);
	    lck = 1;
	}
	if (tps)
	    return microticks();
    }
    return milliticks() * 1000;
}

static uint rename_lock(const wchar *path) {
    uint hash = 0;
    static volatile int init, init1;

    if (!init) {
	if (init1) {
	    while (!init)
		usleep(1);
	} else {
	    init1 = TRUE;
	    if ((lockhdl = CreateFileMappingA(INVALID_HANDLE_VALUE, NULL,
		PAGE_READWRITE, 0, HASH_SIZE * sizeof (long),
		"rename_locks")) != NULL) {
		if ((locks = MapViewOfFile(lockhdl, FILE_MAP_WRITE, 0, 0,
		    HASH_SIZE * sizeof (long))) == NULL) {
		    CloseHandle(lockhdl);
		} else {
		    atexit(stdapi_cleanup);
		}
	    }
	    init = TRUE;
	}
    }
    while (*path) {
	hash = hash * *path + *path;
	path++;
    }
    hash = hash % HASH_SIZE;
    if (locks) {
	while (InterlockedExchange(locks + hash, 1))
	    Sleep(0);
    }
    return hash;
}

#if _MSC_VER < 1500
void *bsearch(const void *key, const void *base, size_t nmemb, size_t size,
    int (*cfunc)(const void *, const void *)) {
    const char *cbase = (char *)base;
    int cmp;
    size_t lim;
    const char *p;

    for (lim = nmemb; lim != 0; lim >>= 1) {
	p = cbase + (lim >> 1) * size;
	cmp = (*cfunc)(key, p);
	if (cmp == 0)
	    return (void *)p;
	if (cmp > 0) {
	    cbase = p + size;
	    lim--;
	}
    }
    return NULL;
}
#endif

int close(int fd) {
    if (fd == -1)
	errno = EINVAL;
    else if (CloseHandle((HANDLE)fd))
	return 0;
    else
	_dosmaperr(GetLastError());
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
    _dosmaperr(GetLastError());
    return -1;
}

int dup(int fd) {
    HANDLE hdl;

    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)fd,
	GetCurrentProcess(), &hdl, 0L, TRUE, DUPLICATE_SAME_ACCESS)) {
	_dosmaperr(GetLastError());
	return -1;
    }
    return (int)hdl;
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
	if (!UnlockFile((HANDLE)fd, 0, (uint)-2, 1, 0)) {
	    _dosmaperr(GetLastError());
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
	if (!LockFileEx((HANDLE)fd, flag, 0, 1, 0, &ov)) {
	    _dosmaperr(GetLastError());
	    return -1;
	}
    }
    return 0;
}

/* fsync emulation - don't fail on console output */
int fsync(int fd) {
    if (!FlushFileBuffers((HANDLE)fd)) {
	if (GetFileType((HANDLE)fd) != FILE_TYPE_CHAR) {
	    _dosmaperr(GetLastError());
	    return -1;
	}
    }
    return 0;
}

int ftruncate(int fd, long len) {
    if (SetFilePointer((HANDLE)fd, len, 0, SEEK_SET) == -1 ||
	!SetEndOfFile((HANDLE)fd)) {
	_dosmaperr(GetLastError());
	return -1;
    }
    return 0;
}

int lockf(int fd, int op, long len) {
    return lockfile(fd, op == F_ULOCK ? F_UNLCK : F_WRLCK, SEEK_CUR, 0, len,
	op == F_TLOCK);
}

int lockfile(int fd, short op, short whence, ulong start, ulong len,
    short test) {
    OVERLAPPED ov;

    ZERO(ov);
    if (whence == SEEK_SET) {
	ov.Offset = start;
    } else if (whence == SEEK_CUR) {
	ov.Offset = SetFilePointer((HANDLE)fd, 0, 0, FILE_CURRENT) + start;
    } else if (whence == SEEK_END) {
	LARGE_INTEGER li;

	GetFileSizeEx((HANDLE)fd, &li);
	li.QuadPart -= start;
	ov.Offset = li.LowPart;
	ov.OffsetHigh = li.HighPart;
    }
    if (op == F_UNLCK) {
	if (!UnlockFileEx((HANDLE)fd, 0, len, 0, &ov)) {
	    _dosmaperr(GetLastError());
	    return -1;
	}
    } else {
	int flag = 0;

	if (op & F_WRLCK)
	    flag |= LOCKFILE_EXCLUSIVE_LOCK;
	if (test)
	    flag |= LOCKFILE_FAIL_IMMEDIATELY;
	if (!LockFileEx((HANDLE)fd, flag, 0, len, 0, &ov)) {
	    _dosmaperr(GetLastError());
	    return -1;
	}
    }
    return 0;
}

long lseek(int fd, long pos, int from) {
    DWORD newpos;

    if ((newpos = SetFilePointer((HANDLE)fd, pos, 0, from)) == -1) {
	_dosmaperr(GetLastError());
	return -1;
    }
    return (long)newpos;
}

/* read emulation - does not work if fd was opened O_TEXT */
int read(int fd, void *buf, uint len) {
    DWORD in;

    if (!ReadFile((HANDLE)fd, buf, len, &in, NULL)) {
	_dosmaperr(GetLastError());
	return -1;
    }
    return in;
}

/* write emulation - does not work if fd was opened O_APPEND or O_TEXT */
int write(int fd, const void *buf, uint len) {
    DWORD out = 0;

    if (len && (!WriteFile((HANDLE)fd, buf, len, &out, NULL) || out == 0)) {
	_dosmaperr(GetLastError());
	return -1;
    }
    return out;
}

long writev(int fd, const struct iovec *io , int num) {
    ulong len = 0;
    char buf[1024];
    char *p = buf;
    int i;
    int out;

    if (num == 1)
	return write(fd, io->iov_base, (int)io->iov_len);
    for (i = 0; i < num; i++, io++) {
	if (p - buf + io->iov_len > sizeof (buf)) {
	    if (p != buf) {
		if ((out = write(fd, buf, (uint)(p - buf))) == -1)
		    return len;
		len += out;
		p = buf;
	    }
	    if (io->iov_len > sizeof (buf) || i == num - 1) {
		if ((out = write(fd, io->iov_base, (int)io->iov_len)) == -1)
		    return len;
		len += out;
		continue;
	    }
	}
	memcpy(p, io->iov_base, io->iov_len);
	p += io->iov_len;
    }
    if (p != buf) {
	if ((out = write(fd, buf, (int)(p - buf))) == -1)
	    return len;
	len += out;
    }
    return (long)len;
}

long tell(int fd) {
    DWORD newpos;

    if ((newpos = SetFilePointer((HANDLE)fd, 0, 0, FILE_CURRENT)) == -1) {
	_dosmaperr(GetLastError());
	return -1;
    }
    return (long)newpos;
}

DIR *opendir(const char *name) {
    DIR *dirp;
    DWORD attr;
    const char *p;
    const char *wild = NULL;
    size_t len;

    len = strlen(name);
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
    if ((dirp = malloc(sizeof (struct DIR) + (len + 1 +
	(wild ? strlen(wild) : sizeof ("/*.*"))) * sizeof (char))) == NULL)
	return dirp;
    memcpy(&dirp->path, name, len);
    dirp->path[len] = '\0';
    if ((attr = GetFileAttributesA(dirp->path)) == (DWORD)-1 ||
	!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
	errno = ENOTDIR;
	free(dirp);
	return NULL;
    }
    strcpy(dirp->path + len, "/");
    strcpy(dirp->path + len + 1, wild ? wild : "*.*");
    dirp->hdl = 0;
    dirp->dir.d_off = 0;
    dirp->dir.d_name = dirp->wfd.cFileName;
    return dirp;
}

WDIR *wopendir(const wchar *name) {
    WDIR *dirp;
    DWORD attr;
    const wchar *p;
    const wchar *wild = NULL;
    size_t len;

    len = wcslen(name);
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
    if ((dirp = malloc(sizeof (struct WDIR) + (len + 1 +
	(wild ? wcslen(wild) : sizeof (L"/*.*"))) * sizeof (wchar))) == NULL)
	return dirp;
    memcpy(&dirp->path, name, len);
    dirp->path[len] = '\0';
    if ((attr = GetFileAttributesW(dirp->path)) == (DWORD)-1 ||
	!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
	errno = ENOTDIR;
	free(dirp);
	return NULL;
    }
    wcscpy(dirp->path + len, L"/");
    wcscpy(dirp->path + len + 1, wild ? wild : L"*.*");
    dirp->hdl = 0;
    dirp->dir.d_off = 0;
    dirp->dir.d_name = dirp->wfd.cFileName;
    return dirp;
}

struct dirent *readdir(DIR *dirp) {
    if (!dirp->hdl) {
	dirp->hdl = FindFirstFileA(dirp->path, &dirp->wfd);
	if (dirp->hdl == INVALID_HANDLE_VALUE)
	    return NULL;
    } else {
	if (!FindNextFileA(dirp->hdl, &dirp->wfd))
	    return NULL;
	dirp->dir.d_off++;
    }
    return &dirp->dir;
}

struct wdirent *wreaddir(WDIR *dirp) {
    if (!dirp->hdl) {
	dirp->hdl = FindFirstFileW(dirp->path, &dirp->wfd);
	if (dirp->hdl == INVALID_HANDLE_VALUE)
	    return NULL;
    } else {
	if (!FindNextFileW(dirp->hdl, &dirp->wfd))
	    return NULL;
	dirp->dir.d_off++;
    }
    return &dirp->dir;
}

void seekdir(DIR *dirp, long pos) {
    if (pos == dirp->dir.d_off) {
	return;
    } else if (pos < dirp->dir.d_off) {
	FindClose(dirp->hdl);
	dirp->hdl = 0;
    } else {
	pos -= dirp->dir.d_off;
    }
    while (pos--)
	readdir(dirp);
}

void wseekdir(WDIR *dirp, long pos) {
    if (pos == dirp->dir.d_off) {
	return;
    } else if (pos < dirp->dir.d_off) {
	FindClose(dirp->hdl);
	dirp->hdl = 0;
    } else {
	pos -= dirp->dir.d_off;
    }
    while (pos--)
	wreaddir(dirp);
}

void closedir(DIR *dirp) {
    if (dirp->hdl != INVALID_HANDLE_VALUE)
	FindClose(dirp->hdl);
    free(dirp);
}

void wclosedir(WDIR *dirp) {
    if (dirp->hdl != INVALID_HANDLE_VALUE)
	FindClose(dirp->hdl);
    free(dirp);
}

int link(const char *from, const char *to) {
    wchar fbuf[MAX_PATH], tbuf[MAX_PATH];

    return A_TO_W(from, fbuf) && A_TO_W(to, tbuf) ? wlink(fbuf, tbuf) : -1;
}

int wlink(const wchar *from, const wchar *to) {
    wchar buf[MAX_PATH + 1];
    LPWSTR file;
    HANDLE hdl;
    LPVOID lpContext = NULL;
    DWORD sz, out;
    WIN32_STREAM_ID sid;
    uint lck;
    int ret = -1;

    if (to[1] == ':') {
	sz = (DWORD)wcslen(to);
    } else if ((sz = GetFullPathNameW(to, MAX_PATH, buf, &file)) == 0 || sz > MAX_PATH) {
	_dosmaperr(GetLastError());
	return ret;
    } else {
	to = buf;
    }
#pragma warning(push)
#pragma warning(disable: 6102)
    if (GetFileAttributesW(to) != (DWORD)-1) {
	errno = EEXIST;
	return ret;
    }
#pragma warning(pop)
    /* check for same drive */
    if (wcsnicmp(from, to, 2) != 0) {
	errno = EINVAL;
	return ret;
    }
    lck = rename_lock(from);
    if ((hdl = CreateFileW(from, 0,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, 0, NULL)) == INVALID_HANDLE_VALUE) {
	rename_unlock(lck);
	_dosmaperr(GetLastError());
	return ret;
    }
    rename_unlock(lck);
    sid.dwStreamId = BACKUP_LINK;
    sid.dwStreamAttributes = 0;
    sid.dwStreamNameSize = 0;
    sid.Size.HighPart = 0;
    sid.Size.LowPart = (sz + 1) * sizeof (wchar);
    out = (DWORD)((LPBYTE)&sid.cStreamName - (LPBYTE)&sid);
    if (!BackupWrite(hdl, (LPBYTE)&sid, out, &out, FALSE, FALSE, &lpContext)) {
	_dosmaperr(GetLastError());
	CloseHandle(hdl);
	return ret;
    }
    if (BackupWrite(hdl, (LPBYTE)to, sid.Size.LowPart,
	&out, FALSE, FALSE, &lpContext))
    	ret = 0;
    else
	_dosmaperr(GetLastError());
    BackupWrite(hdl, NULL, 0, &out, TRUE, FALSE, &lpContext);
    CloseHandle(hdl);
    return ret;
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

int wopen(const wchar *path, int oflag, ...) {
    HANDLE hdl;
    DWORD fileaccess;
    DWORD fileshare;
    DWORD filecreate;
    DWORD fileattrib;
    DWORD filetype = 0;
    DWORD in = 0;
    SECURITY_ATTRIBUTES sa;
    uint lck;
    int mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH;

    if (oflag & O_CREAT) {
	va_list ap;

	va_start(ap, oflag);
	mode = va_arg(ap, int);
	va_end(ap);
    }
    (void)mode;
    sa.nLength = sizeof (sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = (oflag & O_NOINHERIT) ? FALSE : TRUE;
    if ((oflag & O_BINARY) == 0) {
	if (oflag & O_TEXT || _fmode == O_TEXT)
	    oflag |= O_TEXT;
	else
	    oflag |= O_BINARY;
    }
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
    lck = rename_lock(path);
    hdl = CreateFileW(path, fileaccess, fileshare, &sa,
	filecreate, fileattrib, NULL);
    rename_unlock(lck);
    if (hdl == INVALID_HANDLE_VALUE) {
	_dosmaperr(GetLastError());
	return -1;
    }
    if (oflag & O_APPEND) {
	if (SetFilePointer(hdl, 0, 0, FILE_END) == -1) {
	    CloseHandle(hdl);
	    return -1;
	}
    }
    if (!(oflag & O_TEXT && oflag & O_RDWR))
	return (int)hdl;
    if ((filetype = GetFileType(hdl)) == FILE_TYPE_UNKNOWN)
	return (int)hdl;
    if (filetype != FILE_TYPE_PIPE && filetype != FILE_TYPE_CHAR) {
	/* remove CTRL-Z from end of file if present */
	char ch;

	if (SetFilePointer(hdl, 0, NULL, FILE_END) == (DWORD)-1) {
	    CloseHandle(hdl);
	    return -1;
	}
	if (ReadFile(hdl, &ch, 1, &in, NULL) && in && ch == 26) {
	    if (SetFilePointer(hdl, 1, NULL, FILE_END) == (DWORD)-1 ||
		!SetEndOfFile(hdl) ||
		SetFilePointer(hdl, 0, NULL, FILE_BEGIN) == (DWORD)-1) {
		CloseHandle(hdl);
		return -1;
	    }
	}
    }
    return (int)hdl;
}

/* rename that emulates atomic operations expensively */
int rename(const char *from, const char *to) {
    wchar fbuf[MAX_PATH], tbuf[MAX_PATH];

    return A_TO_W(from, fbuf) && A_TO_W(to, tbuf) ? wrename(fbuf, tbuf) : -1;
}

int wrename(const wchar *from, const wchar *to) {
    uint lck;
    wchar oldbuf[MAX_PATH + 10];
    const wchar *old;
    wchar *p;
    int ret = 0;

    if (MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING))
	return ret;
    wcscpy(oldbuf, to);
    p = wcsrchr(oldbuf, '/');
    wsprintfW(p ? p + 1 : oldbuf, L"%u", (uint)microticks() ^ rand());
    lck = rename_lock(to);
    old = oldbuf;
    if (!MoveFileExW(to, old, MOVEFILE_REPLACE_EXISTING)) {
	_dosmaperr(GetLastError());
	if (errno == ENOENT)
	    oldbuf[0] = '\0';
	else
	    ret = -1;
    }
    if (!ret && !MoveFileExW(from, to, MOVEFILE_REPLACE_EXISTING)) {
	_dosmaperr(GetLastError());
	MoveFileW(old, to);
	ret = -1;
    }
    rename_unlock(lck);
    if (!ret && oldbuf[0])
	DeleteFileW(old);
    return ret;
}

/* stat that opens the file so that inodes are set properly */
int stat(const char *path, struct stat *buf) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wstat(pbuf, buf) : -1;
}

static int file_stat(HANDLE hnd, struct stat *buf) {
    BY_HANDLE_FILE_INFORMATION bhfi;
    FILETIME LocalFTime;
    SYSTEMTIME SystemTime;

    if (!GetFileInformationByHandle(hnd, &bhfi)) {
	_dosmaperr(GetLastError());
	return -1;
    }
    buf->st_uid = buf->st_gid = 0;
    buf->st_mode = S_IFREG;
    buf->st_nlink = bhfi.nNumberOfLinks;
    buf->st_rdev = buf->st_dev = bhfi.dwVolumeSerialNumber;
    if (bhfi.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
	buf->st_mode |= (S_IREAD + (S_IREAD >> 3) + (S_IREAD >> 6));
    else
	buf->st_mode |= ((S_IREAD | S_IWRITE) + ((S_IREAD | S_IWRITE) >> 3)
	+ ((S_IREAD | S_IWRITE) >> 6));

    if (!FileTimeToLocalFileTime(&bhfi.ftLastWriteTime, &LocalFTime) ||
	!FileTimeToSystemTime(&LocalFTime, &SystemTime))
	return -1;
    buf->st_mtime = local_to_time_t(&SystemTime);
#ifdef ATIME_SUPPORT
    if (bhfi.ftLastAccessTime.dwLowDateTime ||
	bhfi.ftLastAccessTime.dwHighDateTime) {
	if (!FileTimeToLocalFileTime(&bhfi.ftLastAccessTime, &LocalFTime) ||
	    !FileTimeToSystemTime(&LocalFTime, &SystemTime))
	    return -1;
	buf->st_atime = local_to_time_t(&SystemTime);
    } else {
	buf->st_atime = buf->st_mtime;
    }
#else
    buf->st_atime = 0;
#endif
    if (bhfi.ftCreationTime.dwLowDateTime ||
	bhfi.ftCreationTime.dwHighDateTime) {
	if (!FileTimeToLocalFileTime(&bhfi.ftCreationTime, &LocalFTime) ||
	    !FileTimeToSystemTime(&LocalFTime, &SystemTime))
	    return -1;
	buf->st_ctime = local_to_time_t(&SystemTime);
    } else {
	buf->st_ctime = buf->st_mtime;
    }
#ifdef _USE_INT64
    buf->st_size = ((__int64)(bhfi.nFileSizeHigh)) * (0x100000000i64) +
	(__int64)(bhfi.nFileSizeLow);
#else
    buf->st_size = bhfi.nFileSizeLow;
#endif
    buf->st_ino = ((__int64)(bhfi.nFileIndexHigh)) * (0x100000000i64) +
	(__int64)(bhfi.nFileIndexLow);
    return 0;
}

static int dir_stat(const wchar *path, struct stat *buf) {
    FILETIME LocalFTime;
    SYSTEMTIME SystemTime;
    WIN32_FILE_ATTRIBUTE_DATA fad;

    if (GetFileAttributesExW(path, GetFileExInfoStandard, &fad)) {
	_dosmaperr(GetLastError());
	return -1;
    }
    buf->st_ino = buf->st_uid = buf->st_gid = 0;
    buf->st_nlink = 1;
    buf->st_rdev = buf->st_dev = 0;
    buf->st_mode = (ushort)(fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY ?
    S_IFDIR : S_IFREG);
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_READONLY)
	buf->st_mode |= (S_IREAD + (S_IREAD >> 3) + (S_IREAD >> 6));
    else
	buf->st_mode |= ((S_IREAD | S_IWRITE) + ((S_IREAD | S_IWRITE) >> 3)
	+ ((S_IREAD | S_IWRITE) >> 6));

    if (!FileTimeToLocalFileTime(&fad.ftLastWriteTime, &LocalFTime) ||
	!FileTimeToSystemTime(&LocalFTime, &SystemTime))
	return -1;
    buf->st_mtime = local_to_time_t(&SystemTime);
#ifdef ATIME_SUPPORT
    if (fad.ftLastAccessTime.dwLowDateTime ||
	fad.ftLastAccessTime.dwHighDateTime) {
	if (!FileTimeToLocalFileTime(&fad.ftLastAccessTime, &LocalFTime) ||
	    !FileTimeToSystemTime(&LocalFTime, &SystemTime))
	    return -1;
	buf->st_atime = local_to_time_t(&SystemTime);
    } else {
	buf->st_atime = buf->st_mtime;
    }
#else
    buf->st_atime = 0;
#endif
    if (fad.ftCreationTime.dwLowDateTime ||
	fad.ftCreationTime.dwHighDateTime) {
	if (!FileTimeToLocalFileTime(&fad.ftCreationTime, &LocalFTime) ||
	    !FileTimeToSystemTime(&LocalFTime, &SystemTime))
	    return -1;
	buf->st_ctime = local_to_time_t(&SystemTime);
    } else {
	buf->st_ctime = buf->st_mtime;
    }
#ifdef _USE_INT64
    buf->st_size = ((__int64)(fad.nFileSizeHigh)) * (0x100000000i64) +
	(__int64)(fad.nFileSizeLow);
#else
    buf->st_size = fad.nFileSizeLow;
#endif
    return 0;
}

int wstat(const wchar *path, struct stat *buf) {
    HANDLE hdl;
    uint lck;
    int ret;

    lck = rename_lock(path);
    hdl = CreateFileW(path, 0,
	FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
	OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_NO_BUFFERING, NULL);
    rename_unlock(lck);
    if (hdl == (HANDLE)-1) {
	ret = GetLastError();
	if (ret == ERROR_ACCESS_DENIED)
	    return dir_stat(path, buf);
	_dosmaperr(ret);
	ret = -1;
    } else {
	ret = file_stat(hdl, buf);
	CloseHandle(hdl);
    }
    return ret;
}

int fstat(int fd, struct stat *buf) {
    return file_stat((HANDLE)fd, buf);
}

int statvfs(const char *path, struct statvfs *buf) {
    wchar pbuf[MAX_PATH];

    return A_TO_W(path, pbuf) ? wstatvfs(pbuf, buf) : -1;
}

int wstatvfs(const wchar *path, struct statvfs *buf) {
    ulong bytesPerSector;
    ulong freeClusters;
    ulong sectorsPerCluster;
    ulong totalClusters;
    wchar *cp;
    int rc;

    /* try root directory. This doesn't handle filesystems not mapped 
     * to drive a letter or a path without a drive letter
     */
    cp = wcschr(path, ':');
    if (cp) {
	wchar rootdir[4];
	size_t size = cp - path + 1;

	if (size >= sizeof (rootdir) / sizeof (wchar))
	    size = (sizeof (rootdir) / sizeof (wchar)) - 1;
	wcsncpy(rootdir, path, size);
	rootdir[size] = '\0';
	rc = GetDiskFreeSpaceW(rootdir, &sectorsPerCluster, &bytesPerSector,
	    &freeClusters, &totalClusters);
    } else {
	rc = GetDiskFreeSpaceW(path, &sectorsPerCluster, &bytesPerSector,
	    &freeClusters, &totalClusters);
    }
    if (!rc) {
	_dosmaperr(GetLastError());
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

int _strcmp(const char *a, const char *b) {
    for (; *a == *b; a++, b++)
	if (*a == '\0')
	    return 0;
    return (*a < *b ? -1 : 1);
}

#define _BASE_YEAR	    70
#define _LEAP_YEAR_ADJUST   17
#define _MAX_YEAR	    138
#define _BASE_DOW	    4
#define DAY_MILLISEC	    (24L * 60L * 60L * 1000L)
#define IS_LEAP_YEAR(year)  ((year & 3) == 0)


#ifdef _DLL
int _lpdays[] = { -1, 30, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334, 365 };
#else
extern int _lpdays[];
#endif
static int _days[] = { -1, 30, 58, 89, 119, 150, 180, 211, 242, 272, 303, 333, 364 };

static int tzapiused;
static TIME_ZONE_INFORMATION tzinfo;

/*
* Structure used to represent DST transition date/times.
*/
typedef struct {
    int  yr;        /* year of interest */
    int  yd;        /* day of year */
    long ms;        /* milli-seconds in the day */
} transitiondate;

static transitiondate dststart = { -1, 0, 0L };
static transitiondate dstend   = { -1, 0, 0L };


static void cvtdate(int trantype, int datetype, int year, int month,
    int week, int dayofweek, int date, int hour, int min, int sec, int msec) {
    int yearday;
    int monthdow;
    
    if (datetype == 1) {
	yearday = 1 + (IS_LEAP_YEAR(year) ? _lpdays[month - 1] :
	    _days[month - 1]);
	monthdow = (yearday + ((year - 70) * 365) + ((year - 1) >> 2) -
	    _LEAP_YEAR_ADJUST + _BASE_DOW) % 7;
	if (monthdow < dayofweek)
	    yearday += (dayofweek - monthdow) + (week - 1) * 7;
	else
	    yearday += (dayofweek - monthdow) + week * 7;
	if ((week == 5) &&
	    (yearday > (IS_LEAP_YEAR(year) ? _lpdays[month] : _days[month]))) {
		yearday -= 7;
	}
    } else {
	yearday = IS_LEAP_YEAR(year) ? _lpdays[month - 1] : _days[month - 1];
	yearday += date;
    }

    if (trantype == 1) {
	dststart.yd = yearday;
	dststart.ms = (long)msec + (1000L * (sec + 60L * (min + 60L * hour)));
	dststart.yr = year;
    } else {
	dstend.yd = yearday;
	dstend.ms = (long)msec + (1000L * (sec + 60L * (min + 60L * hour)));
	if ((dstend.ms += (_dstbias * 1000L)) < 0) {
	    dstend.ms += DAY_MILLISEC;
	    dstend.ms--;
	} else if (dstend.ms >= DAY_MILLISEC) {
	    dstend.ms -= DAY_MILLISEC;
	    dstend.ms++;
	}
	dstend.yr = year;
    }
    return;
}

static int _isindst(struct tm *tb) {
    long ms;
    
    if (_daylight == 0)
	return 0;
    if (tb->tm_year != dststart.yr || tb->tm_year != dstend.yr) {
	if (tzapiused) {
	    if (tzinfo.DaylightDate.wYear == 0)
		cvtdate(1, 1, tb->tm_year, tzinfo.DaylightDate.wMonth,
		    tzinfo.DaylightDate.wDay, tzinfo.DaylightDate.wDayOfWeek,
		    0, tzinfo.DaylightDate.wHour, tzinfo.DaylightDate.wMinute,
		    tzinfo.DaylightDate.wSecond,
		    tzinfo.DaylightDate.wMilliseconds);
	    else
		cvtdate(1, 0, tb->tm_year, tzinfo.DaylightDate.wMonth, 0, 0,
		    tzinfo.DaylightDate.wDay, tzinfo.DaylightDate.wHour,
		    tzinfo.DaylightDate.wMinute, tzinfo.DaylightDate.wSecond,
		    tzinfo.DaylightDate.wMilliseconds);
	    if (tzinfo.StandardDate.wYear == 0)
		cvtdate(0, 1, tb->tm_year, tzinfo.StandardDate.wMonth,
		    tzinfo.StandardDate.wDay, tzinfo.StandardDate.wDayOfWeek, 0,
		    tzinfo.StandardDate.wHour, tzinfo.StandardDate.wMinute,
		    tzinfo.StandardDate.wSecond,
		    tzinfo.StandardDate.wMilliseconds);
	    else
		cvtdate(0, 0, tb->tm_year, tzinfo.StandardDate.wMonth, 0, 0,
		    tzinfo.StandardDate.wDay, tzinfo.StandardDate.wHour,
		    tzinfo.StandardDate.wMinute, tzinfo.StandardDate.wSecond,
		    tzinfo.StandardDate.wMilliseconds);
	} else {
	    /*
	     * GetTimeZoneInformation API was NOT used, or failed. USA
	     * daylight saving time rules are assumed.
	     */
	    cvtdate(1, 1, tb->tm_year, 4, 1, 0, 0, 2, 0, 0, 0);
	    cvtdate(0, 1, tb->tm_year, 10, 5, 0, 0, 2, 0, 0, 0);
	}
    }
    if (dststart.yd < dstend.yd) {
	if ((tb->tm_yday < dststart.yd) || (tb->tm_yday > dstend.yd))
	    return 0;
	if ((tb->tm_yday > dststart.yd) && (tb->tm_yday < dstend.yd))
	    return 1;
    } else {
	if ((tb->tm_yday < dstend.yd) || (tb->tm_yday > dststart.yd))
	    return 1;
	if ((tb->tm_yday > dstend.yd) && (tb->tm_yday < dststart.yd))
	    return 0;
    }
    ms = 1000L * (tb->tm_sec + 60L * tb->tm_min + 3600L * tb->tm_hour);
    if (tb->tm_yday == dststart.yd) {
	if (ms >= dststart.ms)
	    return 1;
	else
	    return 0;
    } else {
	if (ms < dstend.ms)
	    return 1;
	else
	    return 0;
    }
}

static ulong local_to_time_t(SYSTEMTIME *stm) {
    int tmpdays;
    ulong tmptim;
    struct tm tb;
    int year = stm->wYear - 1900;
    static int initialized;

    if (!initialized) {
	initialized = 1;
	tzset();
	tzapiused = (getenv("TZ") == NULL);
	_daylight = GetTimeZoneInformation(&tzinfo) == TIME_ZONE_ID_DAYLIGHT;
    }
    tmpdays = stm->wDay + _days[stm->wMonth - 1];
    if (IS_LEAP_YEAR(year) && stm->wMonth > 2)
	tmpdays++;
    tmptim = ((year - _BASE_YEAR) * 365 +
	((year - 1) >> 2) - _LEAP_YEAR_ADJUST + tmpdays) *
	24 + stm->wHour;
    tmptim = (tmptim * 60UL + stm->wMinute) * 60UL + stm->wSecond;
    tmptim += _timezone;
    /* Fill in enough fields of tb for _isindst() */
    tb.tm_yday = tmpdays;
    tb.tm_year = year;
    tb.tm_mon  = stm->wMonth - 1;
    tb.tm_hour = stm->wHour;
    tb.tm_sec = tb.tm_min = 0;
    if (_daylight && _isindst(&tb))
	tmptim += _dstbias;
    return tmptim;
}

struct errentry {
    ulong oscode;			/* OS return value */
    int errnocode;			/* System V error code */
};

#ifdef _DLL

static struct errentry errtable[] = {
    {  ERROR_INVALID_FUNCTION,       EINVAL    },  /* 1 */
    {  ERROR_FILE_NOT_FOUND,         ENOENT    },  /* 2 */
    {  ERROR_PATH_NOT_FOUND,         ENOENT    },  /* 3 */
    {  ERROR_TOO_MANY_OPEN_FILES,    EMFILE    },  /* 4 */
    {  ERROR_ACCESS_DENIED,          EACCES    },  /* 5 */
    {  ERROR_INVALID_HANDLE,         EBADF     },  /* 6 */
    {  ERROR_ARENA_TRASHED,          ENOMEM    },  /* 7 */
    {  ERROR_NOT_ENOUGH_MEMORY,      ENOMEM    },  /* 8 */
    {  ERROR_INVALID_BLOCK,          ENOMEM    },  /* 9 */
    {  ERROR_BAD_ENVIRONMENT,        E2BIG     },  /* 10 */
    {  ERROR_BAD_FORMAT,             ENOEXEC   },  /* 11 */
    {  ERROR_INVALID_ACCESS,         EINVAL    },  /* 12 */
    {  ERROR_INVALID_DATA,           EINVAL    },  /* 13 */
    {  ERROR_INVALID_DRIVE,          ENOENT    },  /* 15 */
    {  ERROR_CURRENT_DIRECTORY,      EACCES    },  /* 16 */
    {  ERROR_NOT_SAME_DEVICE,        EXDEV     },  /* 17 */
    {  ERROR_NO_MORE_FILES,          ENOENT    },  /* 18 */
    {  ERROR_LOCK_VIOLATION,         EACCES    },  /* 33 */
    {  ERROR_BAD_NETPATH,            ENOENT    },  /* 53 */
    {  ERROR_NETWORK_ACCESS_DENIED,  EACCES    },  /* 65 */
    {  ERROR_BAD_NET_NAME,           ENOENT    },  /* 67 */
    {  ERROR_FILE_EXISTS,            EEXIST    },  /* 80 */
    {  ERROR_CANNOT_MAKE,            EACCES    },  /* 82 */
    {  ERROR_FAIL_I24,               EACCES    },  /* 83 */
    {  ERROR_INVALID_PARAMETER,      EINVAL    },  /* 87 */
    {  ERROR_NO_PROC_SLOTS,          EAGAIN    },  /* 89 */
    {  ERROR_DRIVE_LOCKED,           EACCES    },  /* 108 */
    {  ERROR_BROKEN_PIPE,            EPIPE     },  /* 109 */
    {  ERROR_DISK_FULL,              ENOSPC    },  /* 112 */
    {  ERROR_INVALID_TARGET_HANDLE,  EBADF     },  /* 114 */
    {  ERROR_INVALID_HANDLE,         EINVAL    },  /* 124 */
    {  ERROR_WAIT_NO_CHILDREN,       ECHILD    },  /* 128 */
    {  ERROR_CHILD_NOT_COMPLETE,     ECHILD    },  /* 129 */
    {  ERROR_DIRECT_ACCESS_HANDLE,   EBADF     },  /* 130 */
    {  ERROR_NEGATIVE_SEEK,          EINVAL    },  /* 131 */
    {  ERROR_SEEK_ON_DEVICE,         EACCES    },  /* 132 */
    {  ERROR_DIR_NOT_EMPTY,          ENOTEMPTY },  /* 145 */
    {  ERROR_NOT_LOCKED,             EACCES    },  /* 158 */
    {  ERROR_BAD_PATHNAME,           ENOENT    },  /* 161 */
    {  ERROR_MAX_THRDS_REACHED,      EAGAIN    },  /* 164 */
    {  ERROR_LOCK_FAILED,            EACCES    },  /* 167 */
    {  ERROR_ALREADY_EXISTS,         EEXIST    },  /* 183 */
    {  ERROR_FILENAME_EXCED_RANGE,   ENOENT    },  /* 206 */
    {  ERROR_NESTING_NOT_ALLOWED,    EAGAIN    },  /* 215 */
    {  ERROR_NOT_ENOUGH_QUOTA,       ENOMEM    }    /* 1816 */
};

/* size of the table */
#define ERRTABLESIZE (sizeof (errtable) / sizeof (errtable[0]))

/* The following two constants must be the minimum and maximum
   values in the (contiguous) range of Exec Failure errors. */
#define MIN_EXEC_ERROR ERROR_INVALID_STARTING_CODESEG
#define MAX_EXEC_ERROR ERROR_INFLOOP_IN_RELOC_CHAIN

/* These are the low and high value in the range of errors that are
   access violations */
#define MIN_EACCES_RANGE ERROR_WRITE_PROTECT
#define MAX_EACCES_RANGE ERROR_SHARING_BUFFER_EXCEEDED

void __dosmaperr(ulong oserrno) {
    int i;

    _doserrno = oserrno;        /* set _doserrno */
    /* check the table for the OS error code */
    for (i = 0; i < ERRTABLESIZE; ++i) {
	if (oserrno == errtable[i].oscode) {
		errno = errtable[i].errnocode;
		return;
	}
    }
    /* The error code wasn't in the table.  We check for a range of */
    /* EACCES errors or exec failure errors (ENOEXEC).  Otherwise   */
    /* EINVAL is returned.                                          */
    if (oserrno >= MIN_EACCES_RANGE && oserrno <= MAX_EACCES_RANGE)
        errno = EACCES;
    else if (oserrno >= MIN_EXEC_ERROR && oserrno <= MAX_EXEC_ERROR)
	errno = ENOEXEC;
    else
	errno = EINVAL;
}

#endif
