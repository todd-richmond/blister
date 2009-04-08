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

#ifndef _WIN32_WCE
#undef _UNICODE
#endif
#include "stdapi.h"
#include <ctype.h>
#include <errno.h>
#include <mmsystem.h>
#ifndef _WIN32_WCE
#include <fcntl.h>
#include <share.h>
#endif
#include <signal.h>
#include <stdarg.h>
#include <time.h>
#include <windows.h>

#define HASH_SIZE   769
#define rename_unlock(lck)  if (locks) InterlockedExchange(locks + lck, 0)

#ifdef _WIN32_WCE
#define MoveFileEx(a, b, c) MoveFile(a, b)
#define tzset()
#define TPATHVAR(s)	    tchar s[256]
#define TPATH(a, b)	    MultiByteToWideChar(CP_ACP, 0, a, -1, b, 255);

int _doserrno;
int _dstbias;
int _daylight;
int _timezone;

#else
#define TPATHVAR(s)	    const char *s
#define TPATH(a, b)	    (b = a)
#endif

#pragma comment(lib, "winmm.lib")

static HANDLE lockhdl;
static long *locks;

static int dir_stat(const char *dir, struct stat *buf);
static int file_stat(HANDLE hnd, struct stat *buf);
static ulong local_to_time_t(SYSTEMTIME *stm);

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

static msec_t _mticks(void) {
    ulong now;
    msec_t ret;
    static ulong cnt = (ulong)-1, last = (ulong)-1;
    static long lck;

    while (InterlockedExchange(&lck, 1))
	usleep(1);
    now = timeGetTime();	    /* GetTickCount() has 16ms accuracy only */
    if (now < last) {
	if (!++cnt) {
	    last = now;
	} else {
	    ulong tmp = now;

	    now += now - last;
	    last = tmp;
	}
    }
    ret = (msec_t)cnt * (ulong)-1 + now - last;
    InterlockedExchange(&lck, 0);
    return ret;
}

usec_t uticks(void) {
    static uint64 tps = (uint64)-1;

    if (tps == (uint64)-1 &&
	!QueryPerformanceFrequency((LARGE_INTEGER *)&tps))
	tps = 0;
    if (tps) {
	uint64 now;

	if (QueryPerformanceCounter((LARGE_INTEGER *)&now))
	    return now * 1000000 / tps;
    }
    return _mticks() * 1000;
}

msec_t mticks(void) { return uticks() / 1000; }

static uint rename_lock(const char *path) {
    uint hash = 0;
    static volatile int init, init1;

    if (!init) {
	if (init1) {
	    while (!init)
		usleep(1);
	} else {
	    init1 = TRUE;
	    if ((lockhdl = CreateFileMappingA((HANDLE)0xFFFFFFFF, NULL,
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
    while (*path)
	hash = hash * *path + *path++;
    hash = hash % HASH_SIZE;
    if (locks) {
	while (InterlockedExchange(locks + hash, 1))
	    Sleep(1);
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

#if !defined(_WIN32_WCE) || defined(_WIN32_WCE_EMULATION)
int close(int fd) {
    if (fd == -1) {
	errno = EINVAL;
	return -1;
    }
    if (!CloseHandle((HANDLE)fd)) {
	_dosmaperr(GetLastError());
	return -1;
    }
    return 0;
}
#endif

int creat(const char *path, int flag) {
    return open(path, O_CREAT|O_TRUNC, flag);
}

int dup(int fd) {
#ifdef _WIN32_WCE
    return -1;
#else
    HANDLE hdl;

    if (!DuplicateHandle(GetCurrentProcess(), (HANDLE)fd,
	GetCurrentProcess(), &hdl, 0L, TRUE, DUPLICATE_SAME_ACCESS)) {
	_dosmaperr(GetLastError());
	return -1;
    }
    return (int)hdl;
#endif
}

FILE *fdopen(int fd, const char *how) {
#ifdef _WIN32_WCE
    return NULL;
#else
    int flags = 0;

    if (*how == 'a')
	flags |= O_APPEND;
    else if (!strcmp(how, "r"))
	flags |= O_RDONLY;
    return _fdopen(_open_osfhandle(fd, flags), how);
#endif
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
#ifdef _WIN32_WCE
	_dosmaperr(GetLastError());
	return -1;
#else
	if (GetFileType((HANDLE)fd) != FILE_TYPE_CHAR) {
	    _dosmaperr(GetLastError());
	    return -1;
	}
#endif
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
    if (whence == SEEK_SET)
	ov.Offset = start;
    else if (whence == SEEK_CUR)
	ov.Offset = SetFilePointer((HANDLE)fd, 0, 0, FILE_CURRENT) + start;
    else if (whence == SEEK_END)
	ov.Offset = GetFileSize((HANDLE)fd, NULL) - start;
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

#if !defined(_WIN32_WCE) || defined(_WIN32_WCE_EMULATION)
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
#endif

long writev(int fd, const struct iovec *io , int num) {
    ulong len = 0;
    char buf[1024];
    char *p = buf;
    int i;
    int out;

    if (num == 1)
	return write(fd, io->iov_base, io->iov_len);
    for (i = 0; i < num; i++, io++) {
	if (p - buf + io->iov_len > sizeof (buf)) {
	    if (p != buf) {
		if ((out = write(fd, buf, p - buf)) == -1)
		    return len;
		len += out;
		p = buf;
	    }
	    if (io->iov_len > sizeof (buf) || i == num - 1) {
		if ((out = write(fd, io->iov_base, io->iov_len)) == -1)
		    return len;
		len += out;
		continue;
	    }
	}
	memcpy(p, io->iov_base, io->iov_len);
	p += io->iov_len;
    }
    if (p != buf) {
	if ((out = write(fd, buf, p - buf)) == -1)
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

int copy_file(const char *f, const char *t, int check) {
    TPATHVAR(from);
    TPATHVAR(to);

    TPATH(f, from);
    TPATH(t, to);
    return CopyFileA(from, to, check) ? 0 : -1;
}

DIR *opendir(const char *name) {
    DIR *dirp;
    DWORD attr;
    const char *p;
    const char *wild = NULL;
    int len;
    TPATHVAR(path);

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
    if ((dirp = malloc(sizeof (struct DIR) + len + 1 +
	(wild ? strlen(wild) : sizeof ("/*.*")))) == NULL)
       return dirp;
    memcpy(&dirp->path, name, len);
    dirp->path[len] = '\0';
    TPATH(dirp->path, path);
    if ((attr = GetFileAttributesA(path)) == (DWORD)-1 ||
	!(attr & FILE_ATTRIBUTE_DIRECTORY)) {
	errno = ENOTDIR;
	free(dirp);
	return 0;
    }
    strcpy(dirp->path + len, "/");
    if (wild)
	strcpy(dirp->path + len + 1, wild);
    else
	strcpy(dirp->path + len + 1, "*.*");
    dirp->hdl = 0;
    dirp->dir.d_off = 0;
    if ((dirp->wfd = malloc(sizeof (*(dirp->wfd)))) == NULL) {
	free(dirp);
	return 0;
    }
#ifdef _WIN32_WCE
    WideCharToMultiByte(CP_THREAD_ACP, 0, dirp->wfd->cFileName, -1,
	dirp->pbuf, sizeof (dirp->pbuf) / 2, NULL, NULL);
    dirp->dir.d_name = dirp->pbuf;
#else
    dirp->dir.d_name = dirp->wfd->cFileName;
#endif
    return dirp;
}

struct dirent *readdir(DIR *dirp) {
    TPATHVAR(path);

    TPATH(dirp->path, path);
    if (!dirp->hdl) {
	dirp->hdl = FindFirstFileA(path, dirp->wfd);
	if (dirp->hdl == INVALID_HANDLE_VALUE)
	    return NULL;
    } else {
	if (!FindNextFileA(dirp->hdl, dirp->wfd))
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

void closedir(DIR *dirp) {
    if (dirp->hdl != INVALID_HANDLE_VALUE)
	FindClose(dirp->hdl);
    free(dirp->wfd);
    free(dirp);
}

int link(const char *from, const char *to) {
#ifdef _WIN32_WCE
    return -1;
#else
    HANDLE hdl;
    WIN32_STREAM_ID sid;
    DWORD out;
    LPVOID lpContext = NULL;
    WCHAR FileLink[MAX_PATH];
    WCHAR buf[MAX_PATH];
    LPWSTR FilePart;
    int sz;
    uint lck;
    int ret = -1;

    /* check for same drive */
    if (strnicmp(from, to, 2)) {
	errno = EINVAL;
	return ret;
    }
    if (GetFileAttributesA(to) != (DWORD)-1) {
	errno = EEXIST;
	return ret;
    }
#ifdef _UNICODE
    (void)buf;
    sz = GetFullPathName(to, MAX_PATH, FileLink, &FilePart);
#else
    MultiByteToWideChar(CP_ACP, 0, to, strlen(to) + 1, buf, sizeof (buf));
    sz = GetFullPathNameW(buf, MAX_PATH, FileLink, &FilePart);
#endif
    if (sz == 0) {
	_dosmaperr(GetLastError());
	return ret;
    }
    lck = rename_lock(from);
    if ((hdl = CreateFileA(from, 0,
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
    sid.Size.LowPart = (sz + 1) * sizeof (WCHAR);
    out = (LPBYTE)&sid.cStreamName - (LPBYTE)&sid;
    if (!BackupWrite(hdl, (LPBYTE)&sid, out, &out, FALSE, FALSE, &lpContext)) {
	_dosmaperr(GetLastError());
	CloseHandle(hdl);
	return ret;
    }
    if (BackupWrite(hdl, (LPBYTE)FileLink, sid.Size.LowPart,
	&out, FALSE, FALSE, &lpContext))
    	ret = 0;
    else
	_dosmaperr(GetLastError());
    BackupWrite(hdl, NULL, 0, &out, TRUE, FALSE, &lpContext);
    CloseHandle(hdl);
    return ret;
#endif
}

int open(const char *p, int oflag, ...) {
    char ch;
    HANDLE hdl;
    DWORD fileaccess;
    DWORD fileshare;
    DWORD filecreate;
    DWORD fileattrib;
    DWORD filetype;
    DWORD in = 0;
    SECURITY_ATTRIBUTES sa;
    uint lck;
    int mode = 0666;
    TPATHVAR(path);

    (void)ch; (void)filetype;
    TPATH(p, path);
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

    /* figure out binary/text mode */
    if ((oflag & O_BINARY) == 0) {
	if (oflag & O_TEXT || _fmode == O_TEXT)
	    oflag |= O_TEXT;
	else
	    oflag |= O_BINARY;
    }

    /* decode the access flags */
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
    if (oflag & O_SHORT_LIVED)
	fileattrib |= FILE_ATTRIBUTE_TEMPORARY;
    if (oflag & O_COMPRESSED)
	fileattrib |= FILE_ATTRIBUTE_COMPRESSED;
    if (oflag & O_TEMPORARY)
	fileattrib |= FILE_FLAG_DELETE_ON_CLOSE;
    if (oflag & O_SYNC)
	fileattrib |= FILE_FLAG_WRITE_THROUGH;
    if (oflag & O_NOBUFFERING)
	fileattrib |= FILE_FLAG_NO_BUFFERING;
    if (oflag & O_OVERLAPPED)
	fileattrib |= FILE_FLAG_OVERLAPPED;
    if (oflag & O_BACKUP)
	fileattrib |= FILE_FLAG_BACKUP_SEMANTICS;
    if (oflag & O_POSIX) {
	if (path[1] == ':')
	    *((LPTSTR)path) = (char)totupper(path[0]);
	fileattrib |= FILE_FLAG_POSIX_SEMANTICS;
    }
    if (oflag & O_SEQUENTIAL)
	fileattrib |= FILE_FLAG_SEQUENTIAL_SCAN;
    else if (oflag & O_RANDOM)
	fileattrib |= FILE_FLAG_RANDOM_ACCESS;

    /* try to open/create the file */
    lck = rename_lock(p);
    hdl = CreateFileA(path, fileaccess, fileshare, &sa,
	filecreate, fileattrib, NULL);
    rename_unlock(lck);
    if (hdl == (HANDLE)0xffffffff ) {
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
#ifndef _WIN32_WCE
    /* find out what type of file (file/device/pipe) */
    if ((filetype = GetFileType(hdl)) == FILE_TYPE_UNKNOWN) {
	CloseHandle(hdl);
	_dosmaperr(GetLastError());	/* map error */
	return -1;
    }
    if (filetype != FILE_TYPE_PIPE && filetype != FILE_TYPE_CHAR) {
	/* We have a text mode file.  If it ends in CTRL-Z, we wish to
	   remove the CTRL-Z character, so that appending will work.
	   We do this by seeking to the end of file, reading the last
	   byte, and shortening the file if it is a CTRL-Z.
	 */
	if (SetFilePointer(hdl, 0, NULL, FILE_END) == (DWORD)-1) {
	    CloseHandle(hdl);
	    return -1;
	}
	/* Seek was OK, read the last char in file. The last
	   char is a CTRL-Z if and only if _read returns 0
	   and ch ends up with a CTRL-Z.
	 */
	if (ReadFile(hdl, &ch, 1, &in, NULL) && in && ch == 26) {
	    /* read was OK and we got CTRL-Z! Wipe it out! */
	    if (SetFilePointer(hdl, 1, NULL, FILE_END) == (DWORD)-1 ||
		!SetEndOfFile(hdl) ||
		SetFilePointer(hdl, 0, NULL, FILE_BEGIN) == (DWORD)-1) {
		    CloseHandle(hdl);
		    return -1;
	    }
	}
    }
#endif
    return (int)hdl;
}

/* rename that emulates atomic operations very expensively */
int rename(const char *f, const char *t) {
    char oldbuf[260 + 10];
    uint lck;
    int ret = 0;
    char *p;
    TPATHVAR(from);
    TPATHVAR(to);
    TPATHVAR(old);

    TPATH(f, from);
    TPATH(t, to);
    if (MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING))
	return ret;
    strcpy(oldbuf, t);
    if ((p = strrchr(oldbuf, '/')) != NULL)
	sprintf(p + 1, "%lu.tmp", GetTickCount() ^ rand());
    else
	sprintf(oldbuf, "%s%lu.tmp", to, GetTickCount() ^ rand());
    lck = rename_lock(t);
    TPATH(oldbuf, old);
    if (!MoveFileExA(to, old, MOVEFILE_REPLACE_EXISTING)) {
	_dosmaperr(GetLastError());
	if (errno == ENOENT)
	    oldbuf[0] = '\0';
	else
	    ret = -1;
    }
    if (!ret && !MoveFileExA(from, to, MOVEFILE_REPLACE_EXISTING)) {
	_dosmaperr(GetLastError());
	MoveFileA(old, to);
	ret = -1;
    }
    rename_unlock(lck);
    if (!ret && oldbuf[0])
	DeleteFileA(old);
    return ret;
}

/* stat that opens the file so that inodes are set properly */
int stat(const char *p, struct stat *buf) {
    HANDLE hdl;
    uint lck;
    int ret;
    TPATHVAR(path);

    TPATH(p, path);
    lck = rename_lock(p);
    hdl = CreateFileA(path, 0,
	FILE_SHARE_DELETE | FILE_SHARE_READ | FILE_SHARE_WRITE,
	NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    rename_unlock(lck);
    if (hdl == (HANDLE)-1) {
	ret = GetLastError();
	if (ret == ERROR_ACCESS_DENIED)
	    return dir_stat(p, buf);
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
	buf->st_mode |= ((S_IREAD|S_IWRITE) + ((S_IREAD|S_IWRITE) >> 3)
	  + ((S_IREAD|S_IWRITE) >> 6));

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

static int dir_stat(const char *d, struct stat *buf) {
    WIN32_FILE_ATTRIBUTE_DATA fad;
    FILETIME LocalFTime;
    SYSTEMTIME SystemTime;
    TPATHVAR(dir);

    TPATH(d, dir);
    if (!GetFileAttributesExA(dir, GetFileExInfoStandard, &fad)) {
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
	buf->st_mode |= ((S_IREAD|S_IWRITE) + ((S_IREAD|S_IWRITE) >> 3)
	  + ((S_IREAD|S_IWRITE) >> 6));

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

int statvfs(const char *path, struct statvfs *buf) {
    ulong sectorsPerCluster;
    ulong bytesPerSector;
    ulong freeClusters;
    ulong totalClusters;
    
#ifdef _WIN32_WCE
    sectorsPerCluster = 1;
    bytesPerSector = 512;
    freeClusters = (ulong)-1;
    totalClusters = (ulong)-1;
#else
    int rc;
    char *cp;
    char rootdir[4];

    /* try root directory. This doesn't handle filesystems not mapped 
     * to drive a letter or a path without a drive letter
     */
    cp = strchr(path, ':');
    if (cp) {
	int size = cp - path + 1;

	if (size >= sizeof (rootdir))
	    size = sizeof (rootdir) - 1;
	strncpy(rootdir, path, size);
	rootdir[size] = '\0';
	rc = GetDiskFreeSpaceA(rootdir, &sectorsPerCluster, &bytesPerSector,
	    &freeClusters, &totalClusters);
    } else {
	rc = GetDiskFreeSpaceA(path, &sectorsPerCluster, &bytesPerSector,
	    &freeClusters, &totalClusters);
    }
    if (!rc) {
	_dosmaperr(GetLastError());
	return -1;
    }
#endif
    memset(buf, 0, sizeof (*buf));
    buf->f_bsize = buf->f_frsize = sectorsPerCluster * bytesPerSector;
    buf->f_blocks = totalClusters;
    buf->f_bfree = buf->f_bavail = freeClusters;
    return 0;
}

int sigsend(idtype_t type, id_t id, int sig) {
#ifdef _WIN32_WCE
    return -1;
#else
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
#endif
}

int _strcmp(const char *a, const char *b) {
    for (; *a == *b; a++, b++)
	if (*a == '\0')
	    return 0;
    return (*a < *b ? -1 : 1);
}

#ifdef _WIN32_WCE
int access(const char *p, int mode) {
    DWORD attr;
    TPATHVAR(path);

    TPATH(p, path);
    if ((attr = GetFileAttributes(path)) == (DWORD)-1)
	return -1;
    if (mode & 2 && attr & FILE_ATTRIBUTE_READONLY | FILE_ATTRIBUTE_DIRECTORY)
	return -1;
    else if (mode & 1 && attr & FILE_ATTRIBUTE_DIRECTORY)
	return -1;
    return 0;
}

int __cdecl _stricmp(const char *a, const char *b) {
    for (; tolower(*a) == tolower(*b); a++, b++)
	if (*a == '\0')
	    return 0;
    return (tolower(*a) < tolower(*b) ? -1 : 1);
}

int __cdecl _strnicmp(const char *a, const char *b, uint len) {
    for (; len-- && tolower(*a) == tolower(*b); a++, b++)
	if (*a == '\0')
	    return 0;
    return (tolower(*a) < tolower(*b) ? -1 : 1);
}

int unlink(const char *p) {
    TPATHVAR(path);

    TPATH(p, path);
    return DeleteFile(path) == TRUE;
}

#endif

#if 0
extern __cdecl tmain(int argc, tchar **argv);

int winmain(HINSTANCE instance, HINSTANCE prev, tchar *cmd, int show) {
    int argc = 0;
    tchar *argv[16];
    tchar prog[128];
    tchar *p = cmd, *pp = cmd, *end;

    GetModuleFileName(NULL, prog, sizeof (prog) / sizeof (tchar));
    argv[argc++] = prog;
#ifdef _UNICODE
    p = tstrtok(cmd , T("\t "), &end);
#else
    (void)end;
    p = tstrtok(cmd, T("\t "));
#endif
    while (p) {
	argv[argc++] = p;
	pp = p;
#ifdef _UNICODE
	p = tstrtok(NULL, T("\t "), &end);
#else
	p = tstrtok(NULL, T("\t "));
#endif
    }
    return tmain(argc, argv);
}
#endif // 0

#define _BASE_YEAR	    70
#define _LEAP_YEAR_ADJUST   17
#define _MAX_YEAR	    138
#define _BASE_DOW	    4
#define DAY_MILLISEC	    (24L * 60L * 60L * 1000L)
#define IS_LEAP_YEAR(year)  ((year & 3) == 0)


#if defined(_DLL) || defined(_WIN32_WCE)
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

#if defined(_DLL) || defined(_WIN32_WCE)

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
