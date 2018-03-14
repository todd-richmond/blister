/*
 * Copyright 2001-2017 Todd Richmond
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

#ifndef stdapi_h
#define stdapi_h

// defines, typedefs and code to make non-UNIX systems support POSIX APIs
#define CPP_STR(s)		#s
#ifdef _MSC_VER
#define PRAGMA_WARN_DISABLE(e)	_Pragma(warning(disable: e))
#define PRAGMA_WARN_ENABLE(e)	_Pragma(warning(enable: e))
#define PRAGMA_WARN_POP		_Pragma(warning(pop))
#define PRAGMA_WARN_PUSH	_Pragma(warning(push))
#else
#define PRAGMA_WARN_POP		_Pragma(CPP_STR(GCC pop_options))
#define PRAGMA_WARN_PUSH	_Pragma(CPP_STR(GCC push_options))
#define PRAGMA_WARN_DISABLE(e)	_Pragma(CPP_STR(GCC diagnostic ignored #e))
#define PRAGMA_WARN_ENABLE(e)	_Pragma(CPP_STR(GCC diagnostic warning #e))
#endif
#define PRAGMA_WARN_PUSH_DISABLE(e)	PRAGMA_WARN_PUSH PRAGMA_WARN_DISABLE(e)

#ifdef __cplusplus
#define EXTERNC		extern "C" {
#define EXTERNC_	}
#else
#define EXTERNC
#define EXTERNC_
#endif

#ifdef _WIN32

#pragma inline_depth(69)
#pragma warning(disable: 4018 4068 4097 4100 4103 4127 4146 4201 4250 4335 4503)
#pragma warning(disable: 4511 4512 4530 4577 4619 4625 4626 4668 4710 4711 4786)
#pragma warning(disable: 4820 4996 5026 5027 26135 28125)

#ifndef WIN32
#define WIN32
#endif
#define NTDDI_VERSION	NTDDI_WIN8 
#define _WIN32_WINNT	_WIN32_WINNT_WIN8
#define NOIME
#define NOMCX
#define NOSERVICE
#define WIN32_LEAN_AND_MEAN

#define fstat		__fstat
#define ino_t		__ino_t
#define rename		_rename
#define stat		__sstat
#define statvfs		__statvfs
#define wstatvfs	__wstatvfs
#define _INO_T_DEFINED
#define _STAT_DEFINED
#define _STATVFS_DEFINED
#define _WSTAT_DEFINED
#define _WSTATVFS_DEFINED

#if _MSC_VER >= 1900
typedef __int64 _ino_t;
#endif
#define __STDC__ 1
#include <direct.h>
#include <io.h>
#include <stdint.h>
#include <stdio.h>
#undef __STDC__
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <winsock2.h>
#include <sys/stat.h>

#undef _INO_T_DEFINED
#undef _STAT_DEFINED
#undef _WSTAT_DEFINED
#undef fstat
#undef ino_t
#undef rename
#undef stat

#ifndef __cplusplus
#define inline		__inline
#endif

#if _MSC_VER < 1600
#define EADDRNOTAVAIL   WSAEADDRNOTAVAIL
#define EADDRINUSE	WSAEADDRINUSE
#define ECONNABORTED	WSAECONNABORTED
#define ECONNREFUSED	WSAECONNREFUSED
#define ECONNRESET	WSAECONNRESET
#define EINPROGRESS	WSAEINPROGRESS
#define	ENOBUFS		WSAENOBUFS
#define ENOTCONN	WSAENOTCONN
#define ENOSR		ENOBUFS
#define ETIMEDOUT	WSAETIMEDOUT
#define EWOULDBLOCK	WSAEWOULDBLOCK
#endif

#define O_CLOEXEC	0
#define O_COMPRESSED	0x010000
#define O_POSIX		0x020000
#define O_SYNC		0x040000
#define O_DIRECT	0x080000
#define O_OVERLAPPED	0x100000
#define O_BACKUP	0x200000
#define O_NONBLOCK	0x400000
#define O_DSYNC		O_SYNC
#define O_SHORT_LIVED	_O_SHORT_LIVED
#define O_TMPFILE	O_TEMPORARY

#define SIGHUP		SIGBREAK
#define SIGCHLD		80	// out of range
#define SIGPIPE		81

#define S_IRUSR		_S_IREAD
#define S_IWUSR		_S_IWRITE
#define S_IXUSR		_S_IEXEC
#define S_IRWXU		S_IRUSR | S_IWUSR | S_IXUSR
#define S_IRGRP		00040
#define S_IWGRP		00020
#define S_IXGRP		00010
#define S_IRWXG		S_IRGRP | S_IWGRP | S_IXGRP
#define S_IROTH		00004
#define S_IWOTH		00002
#define S_IXOTH		00001
#define S_IRWXO		S_IROTH | S_IWOTH | S_IXOTH

#define F_OK		0
#define X_OK		(1 << 0)
#define W_OK		(1 << 1)
#define R_OK		(1 << 2)

#define F_ULOCK		0
#define F_LOCK		1
#define F_TLOCK		2
#define F_TEST		3

#define F_RDLCK		0
#define F_WRLCK		1
#define F_UNLCK		2
#define F_GETLK		5
#define F_SETLK		6
#define F_SETLKW	7

#define LOCK_SH		1
#define LOCK_EX		2
#define LOCK_NB		4
#define LOCK_UN		8

#define PATH_MAX	MAX_PATH

#define bcopy(a, b, c)  memmove(b, a, c)
#define bzero(a, b)	memset(a, 0, b)
#define chown(p, o, g)	0
#define fchown(f, o, g)	0
#define lchown(p, o, g)	0
#define getcwd		_getcwd
#define getuid()	0
#define getgid()	0
#define geteuid		getuid
#define getegid		getgid
#define getpid		_getpid
#define kill(pid, sig)	sigsend(P_PID, pid, sig)
#define	popen		_popen
#define	pclose		_pclose
#define setuid(uid)	0
#define setgid(gid)	0
#define seteuid		setuid
#define setegid		setgid
#define sleep(x)	Sleep((x) * 1000)
#define strcasecmp	stricmp
#define strncasecmp	strnicmp
#define snprintf	_snprintf
#define usleep(x)	Sleep((x) / 1000)
#define waitpid(pid, sts, opt)	cwait(sts, pid, opt)
#define wcserror	_wcserror
#define	wexecvp		_wexecvp
#define wgetcwd		_wgetcwd
#define wgetenv		_wgetenv
#define wtof		_wtof
#define wtoi		_wtoi
#define wtol		_wtol

typedef __int64 llong;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned __int64 ullong;
typedef wchar_t wchar;

typedef ushort gid_t;
typedef int id_t;
typedef llong ino_t;
typedef short nlink_t;
typedef long pid_t;
typedef ushort uid_t;

typedef enum idtype {
    P_PID, P_PPID, P_PGID, P_SID, P_CID, P_UID, P_GID, P_ALL
} idtype_t;

// UNIX directory emulation
typedef struct dirent {
    char *d_ino;
    long d_off;
    char *d_name;
} dirent;

typedef struct wdirent {
    wchar *d_ino;
    long d_off;
    wchar *d_name;
} wdirent;

typedef struct DIR {
    void *hdl;
    dirent dir;
    WIN32_FIND_DATAA wfd;
    char path[1];
} DIR;

typedef struct WDIR {
    void *hdl;
    wdirent dir;
    WIN32_FIND_DATAW wfd;
    wchar path[1];
} WDIR;

#define telldir(p)		(p->dir.d_off)
#define rewinddir(dirp)		seekdir(dirp, 0L)
#define wrewinddir(dirp)	wseekdir(dirp, 0L)

// stat routines that support inodes and devices properly
struct stat {
    ino_t st_ino;
    ulong st_dev;
    ulong st_rdev;
    ulong st_size;
    ulong st_atime;
    ulong st_mtime;
    ulong st_ctime;
    nlink_t st_nlink;
    ushort st_mode;
    ushort st_uid;
    ushort st_gid;
};

// statvfs emulation
#define FSTYPSZ 16

typedef struct statvfs {
    ulong f_bsize;			// preferred file system block size
    ulong f_frsize;			// fundamental file system block size
    ulong f_blocks;			// total # of blocks of f_frsize
    ulong f_bfree;			// total # of free blocks of f_frsize
    ulong f_bavail;			// # of free blocks for non-superuser
    ulong f_files;			// total # of file nodes (inodes)
    ulong f_ffree;			// total # of free file nodes
    ulong f_favail;			// # of free nodes for non-superuser
    ulong f_fsid;			// file system id (dev for now)
    char f_basetype[FSTYPSZ];		// target fs type name
    ulong f_flag;			// bit-mask of flags
    ulong f_namemax;			// maximum file name length
} statvfs_t;

// writev emulation
typedef struct iovec {
    size_t iov_len;
    char *iov_base;
} iovec_t;

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

// replacement CLib supports atomic rename, deleting open files and socket fds
#define fileno(stream)	(_get_osfhandle((stream)->_file))

EXTERNC
extern int access(const char *path, int mode);
extern int chmod(const char *path, int mode);
extern int chsize(int fd, long len);
extern int close(int fd);
extern void closedir(DIR *dir);
extern int creat(const char *path, int mode);
extern int copy_file(const char *from, const char *to, int check);
extern int dup(int fd);
extern int dup2(int from, int to);
extern int eof(int fd);
extern long filelength(int fd);
extern int flock(int fd, int op);
extern int fstat(int fd, struct stat *buf);
extern int fsync(int fd);
extern int ftruncate(int fd, long len);
extern int gettimeofday(struct timeval *tv, struct timezone *tz);
extern int isatty(int fd);
extern int link(const char *from, const char *to);
extern int lockf(int fd, int op, long len);
extern long lseek(int, long, int);
extern char *mktemp(char *path);
extern int open(const char *path, int mode, ...);
extern DIR *opendir(const char *path);
extern int read(int, void *, unsigned int);
extern dirent *readdir(DIR *dir);
extern long readv(int fd, struct iovec *vec, int numvec);
extern int rename(const char *from, const char *to);
extern void seekdir(DIR *dir, long offset);
extern int setmode(int fd, int mode);
extern int sigsend(idtype_t idtype, id_t id, int sig);
extern int stat(const char *path, struct stat *buf);
extern int statvfs(const char *path, struct statvfs *buf);
extern long tell(int fd);
extern int umask(int mode);
extern int unlink(const char *path);
extern int waccess(const wchar *path, int mode);
extern int wchmod(const wchar *path, int mode);
extern void wclosedir(WDIR *dir);
extern int wcopy_file(const wchar *from, const wchar *to, int check);
extern int wcreat(const wchar *path, int mode);
extern wchar *wmktemp(wchar *path);
extern int wlink(const wchar *from, const wchar *to);
extern int wopen(const wchar *path, int mode, ...);
extern WDIR *wopendir(const wchar *path);
extern wdirent *wreaddir(WDIR *dir);
extern int wrename(const wchar *from, const wchar *to);
extern int write(int, const void *, uint);
extern long writev(int fd, const struct iovec *vec, int numvec);
extern void wseekdir(WDIR *dir, long);
extern int wstat(const wchar *wpath, struct stat *buf);
extern int wstatvfs(const wchar *wpath, struct statvfs *buf);
extern int wunlink(const wchar *path);
EXTERNC_

#define asctime_r(tm, buf, len)	((void)(buf, len), asctime(tm))
#define ctime_r(clock, buf)	((void)(buf), ctime(clock))
#define gmtime_r(clock, buf)	((void)(buf), gmtime(clock))
#define localtime_r(clock, buf)	((void)(buf), localtime(clock))
#define strerror_r(e, buf, sz)	strlcpy(buf, strerror(e), sz)

#else // _WIN32

#ifndef _POSIX_PTHREAD_SEMANTICS
#define _POSIX_PTHREAD_SEMANTICS
#endif
#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <unistd.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <sys/uio.h>

#define __declspec(x)
#define __cdecl
#define __fastcall
#define __stdcall

#if defined(__GNUC__)
#define GNUC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + \
    __GNUC_PATCHLEVEL__)
#define __forceinline	__attribute__((always_inline))
#endif

#ifndef __DBL_EPSILON__
#define DBL_EPSILON	2.2204460492503131e-016
#define FLT_EPSILON	1.192092896e-07F
#endif
#ifndef ENOSR
#define ENOSR		ENOBUFS
#endif

#ifndef O_BINARY
#define O_BINARY	0
#endif
#define O_COMPRESSED	0
#ifndef O_DIRECT
#define O_DIRECT	0
#endif
#define O_SEQUENTIAL	0
#define O_SHORT_LIVED	0
#ifndef O_TMPFILE
#define O_TMPFILE	0
#endif
#define O_TEMPORARY	O_TMPFILE

#define stricmp		strcasecmp
#define strnicmp	strncasecmp
#define wcsicmp		wcscasecmp

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
#endif

typedef long long llong;
typedef unsigned long long ullong;
typedef wchar_t wchar;

#ifdef __APPLE__
#ifndef CLOCK_REALTIME
#define APPLE_NO_CLOCK_GETTIME
#define CLOCK_REALTIME	0
#define CLOCK_MONOTONIC	1

EXTERNC
extern int clock_gettime(int, struct timespec *ts);
EXTERNC_
#endif
#ifndef PATH_MAX
#define PATH_MAX	1024
#endif
#endif

#ifdef CLOCK_MONOTONIC_FAST
#define CLOCK_BOOTTIME		CLOCK_UPTIME
#define CLOCK_BOOTTIME_COURSE	CLOCK_UPTIME_FAST
#define CLOCK_MONOTONIC_COURSE	CLOCK_MONOTONIC_FAST
#define CLOCK_REALTIME_COURSE	CLOCK_REALTIME_FAST
#elif !defined(CLOCK_BOOTTIME)
#ifdef CLOCK_MONOTONIC_RAW
#define CLOCK_BOOTTIME		CLOCK_MONOTONIC_RAW
#else
#define CLOCK_BOOTTIME		CLOCK_MONOTONIC
#endif
#endif
#ifndef CLOCK_MONOTONIC_COARSE
#define CLOCK_MONOTONIC_COARSE	CLOCK_MONOTONIC
#endif
#ifndef CLOCK_MONOTONIC_RAW
#define CLOCK_MONOTONIC_RAW	CLOCK_MONOTONIC
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__sun__)
EXTERNC
extern int wcscasecmp(const wchar_t *, const wchar_t *);
EXTERNC_
#endif
#endif // _WIN32

#ifdef __has_feature
#define __no_sanitize(check)	 __attribute__((no_sanitize(check)))
#else
#define __no_sanitize(check)
#endif

// primitive type value limits
#define MAXUCHAR	~(uchar)0
#ifndef MAXCHAR
#define MAXCHAR		(char)(MAXUCHAR >> 1)
#endif
#ifndef MINCHAR
#define MINCHAR		(char)~MAXCHAR
#endif
#define MAXUSHORT	~(ushort)0
#ifndef MAXSHORT
#define MAXSHORT	(short)(MAXUSHORT >> 1)
#endif
#ifndef MINSHORT
#define MINSHORT	(short)~MAXSHORT
#endif
#ifndef MAXUINT
#define MAXUINT		~(uint)0
#endif
#ifndef MAXINT
#define MAXINT		(int)(MAXUINT >> 1)
#endif
#ifndef MININT
#define MININT		(int)~MAXINT
#endif
#define MAXULONG	~(ulong)0
#ifndef MAXLONG
#define MAXLONG		(long)(MAXULONG >> 1)
#endif
#ifndef MINLONG
#define MINLONG		(long)~MAXLONG
#endif
#define MAXULLONG	~(ullong)0
#define MAXLLONG	(llong)(MAXULLONG >> 1)
#define MINLLONG	(llong)~MAXLLONG
#define MAXBYTE		0xff
#define MAXWORD		0xffff
#define MAXDWORD	0xffffffff

#define ZERO(x)		memset(&(x), 0, sizeof (x))

// recursive macros for compile-time optimization
#define STDAPI_REPEAT(i, m, d)	STDAPI_REPEAT_I(i, m, d)
#define STDAPI_REPEAT_I(i, m, d)STDAPI_REPEAT_##i(m, d)
#define STDAPI_REPEAT_0(m, d)
#define STDAPI_REPEAT_1(m, d)	m(0, d)
#define STDAPI_REPEAT_2(m, d)	STDAPI_REPEAT_1(m, d)	m(1, d)
#define STDAPI_REPEAT_3(m, d)	STDAPI_REPEAT_2(m, d)	m(2, d)
#define STDAPI_REPEAT_4(m, d)	STDAPI_REPEAT_3(m, d)	m(3, d)
#define STDAPI_REPEAT_5(m, d)	STDAPI_REPEAT_4(m, d)	m(4, d)
#define STDAPI_REPEAT_6(m, d)	STDAPI_REPEAT_5(m, d)	m(5, d)
#define STDAPI_REPEAT_7(m, d)	STDAPI_REPEAT_6(m, d)	m(6, d)
#define STDAPI_REPEAT_8(m, d)	STDAPI_REPEAT_7(m, d)	m(7, d)
#define STDAPI_REPEAT_9(m, d)	STDAPI_REPEAT_8(m, d)	m(8, d)
#define STDAPI_REPEAT_10(m, d)	STDAPI_REPEAT_9(m, d)	m(9, d)
#define STDAPI_REPEAT_11(m, d)	STDAPI_REPEAT_10(m, d)	m(10, d)
#define STDAPI_REPEAT_12(m, d)	STDAPI_REPEAT_11(m, d)	m(11, d)
#define STDAPI_REPEAT_13(m, d)	STDAPI_REPEAT_12(m, d)	m(12, d)
#define STDAPI_REPEAT_14(m, d)	STDAPI_REPEAT_13(m, d)	m(13, d)
#define STDAPI_REPEAT_15(m, d)	STDAPI_REPEAT_14(m, d)	m(14, d)
#define STDAPI_REPEAT_16(m, d)	STDAPI_REPEAT_15(m, d)	m(15, d)
#define STDAPI_REPEAT_17(m, d)	STDAPI_REPEAT_16(m, d)	m(16, d)
#define STDAPI_REPEAT_18(m, d)	STDAPI_REPEAT_17(m, d)	m(17, d)
#define STDAPI_REPEAT_19(m, d)	STDAPI_REPEAT_18(m, d)	m(18, d)
#define STDAPI_REPEAT_20(m, d)	STDAPI_REPEAT_19(m, d)	m(19, d)
#define STDAPI_REPEAT_21(m, d)	STDAPI_REPEAT_20(m, d)	m(20, d)
#define STDAPI_REPEAT_22(m, d)	STDAPI_REPEAT_21(m, d)	m(21, d)
#define STDAPI_REPEAT_23(m, d)	STDAPI_REPEAT_22(m, d)	m(22, d)
#define STDAPI_REPEAT_24(m, d)	STDAPI_REPEAT_23(m, d)	m(23, d)
#define STDAPI_REPEAT_25(m, d)	STDAPI_REPEAT_24(m, d)	m(24, d)
#define STDAPI_REPEAT_26(m, d)	STDAPI_REPEAT_25(m, d)	m(25, d)
#define STDAPI_REPEAT_27(m, d)	STDAPI_REPEAT_26(m, d)	m(26, d)
#define STDAPI_REPEAT_28(m, d)	STDAPI_REPEAT_27(m, d)	m(27, d)
#define STDAPI_REPEAT_29(m, d)	STDAPI_REPEAT_28(m, d)	m(28, d)
#define STDAPI_REPEAT_30(m, d)	STDAPI_REPEAT_29(m, d)	m(29, d)
#define STDAPI_REPEAT_31(m, d)	STDAPI_REPEAT_30(m, d)	m(30, d)
#define STDAPI_REPEAT_32(m, d)	STDAPI_REPEAT_31(m, d)	m(31, d)
#define STDAPI_REPEAT_33(m, d)	STDAPI_REPEAT_32(m, d)	m(32, d)
#define STDAPI_REPEAT_34(m, d)	STDAPI_REPEAT_33(m, d)	m(33, d)
#define STDAPI_REPEAT_35(m, d)	STDAPI_REPEAT_34(m, d)	m(34, d)
#define STDAPI_REPEAT_36(m, d)	STDAPI_REPEAT_35(m, d)	m(35, d)
#define STDAPI_REPEAT_37(m, d)	STDAPI_REPEAT_36(m, d)	m(36, d)
#define STDAPI_REPEAT_38(m, d)	STDAPI_REPEAT_37(m, d)	m(37, d)
#define STDAPI_REPEAT_39(m, d)	STDAPI_REPEAT_38(m, d)	m(38, d)
#define STDAPI_REPEAT_40(m, d)	STDAPI_REPEAT_39(m, d)	m(39, d)
#define STDAPI_REPEAT_41(m, d)	STDAPI_REPEAT_40(m, d)	m(40, d)
#define STDAPI_REPEAT_42(m, d)	STDAPI_REPEAT_41(m, d)	m(41, d)
#define STDAPI_REPEAT_43(m, d)	STDAPI_REPEAT_42(m, d)	m(42, d)
#define STDAPI_REPEAT_44(m, d)	STDAPI_REPEAT_43(m, d)	m(43, d)
#define STDAPI_REPEAT_45(m, d)	STDAPI_REPEAT_44(m, d)	m(44, d)
#define STDAPI_REPEAT_46(m, d)	STDAPI_REPEAT_45(m, d)	m(45, d)
#define STDAPI_REPEAT_47(m, d)	STDAPI_REPEAT_46(m, d)	m(46, d)
#define STDAPI_REPEAT_48(m, d)	STDAPI_REPEAT_47(m, d)	m(47, d)
#define STDAPI_REPEAT_49(m, d)	STDAPI_REPEAT_48(m, d)	m(48, d)
#define STDAPI_REPEAT_50(m, d)	STDAPI_REPEAT_49(m, d)	m(49, d)
#define STDAPI_REPEAT_51(m, d)	STDAPI_REPEAT_50(m, d)	m(50, d)
#define STDAPI_REPEAT_52(m, d)	STDAPI_REPEAT_51(m, d)	m(51, d)
#define STDAPI_REPEAT_53(m, d)	STDAPI_REPEAT_52(m, d)	m(52, d)
#define STDAPI_REPEAT_54(m, d)	STDAPI_REPEAT_53(m, d)	m(53, d)
#define STDAPI_REPEAT_55(m, d)	STDAPI_REPEAT_54(m, d)	m(54, d)
#define STDAPI_REPEAT_56(m, d)	STDAPI_REPEAT_55(m, d)	m(55, d)
#define STDAPI_REPEAT_57(m, d)	STDAPI_REPEAT_56(m, d)	m(56, d)
#define STDAPI_REPEAT_58(m, d)	STDAPI_REPEAT_57(m, d)	m(57, d)
#define STDAPI_REPEAT_59(m, d)	STDAPI_REPEAT_58(m, d)	m(58, d)
#define STDAPI_REPEAT_60(m, d)	STDAPI_REPEAT_59(m, d)	m(59, d)
#define STDAPI_REPEAT_61(m, d)	STDAPI_REPEAT_60(m, d)	m(60, d)
#define STDAPI_REPEAT_62(m, d)	STDAPI_REPEAT_61(m, d)	m(61, d)
#define STDAPI_REPEAT_63(m, d)	STDAPI_REPEAT_62(m, d)	m(62, d)
#define STDAPI_REPEAT_64(m, d)	STDAPI_REPEAT_63(m, d)	m(63, d)

#ifndef O_NOATIME
#define O_NOATIME	0
#endif

// 8 / 16 bit char string macros
#ifdef _UNICODE
#ifndef UNICODE
#define UNICODE
#endif

#define _T(str)		L##str
#define T(str)		_T(str)

#define tstring		wstring
#define tstrcmp		wcscmp
#define tstricmp	wcsicmp
#define tstrncmp	wcsncmp
#define tstrnicmp	wcsnicmp
#define tstrcat		wcscat
#define tstrlcat	wcslcat
#define tstrncat	wcsncat
#define tstrcpy		wcscpy
#define tstlncpy	wcslcpy
#define tstrncpy	wcsncpy
#define tstrlen		wcslen
#define	tstrchr		wcschr
#define tstrrchr	wcsrchr
#define tstrspn		wcsspn
#define tstrcspn	wcscspn
#define tstrpbrk	wcspbrk
#define tstrstr		wcsstr
#define tstrtok		wcstok
#define tstrdup		wcsdup
#define tstrerror	wcserror
#define tstrerror_r(e, buf, sz)	wcsncpy(buf, wcserror(e), sz)
#define tstrftime	wcsftime
#define ttof		wtof
#define ttoi		wtoi
#define ttol		wtol
#define tstrtod		wcstod
#define tstrtol		wcstol
#define tstrtoul	wcstoul
#define texecvp		wexecvp
#define tgetcwd		wgetcwd
#define tgetenv		wgetenv
#define istalnum	iswalnum
#define istalpha	iswalpha
#define istblank	iswblank
#define istcntrl	iswcntrl
#define istdigit	iswdigit
#define istgraph	iswgraph
#define istlower	iswlower
#define istprint	iswprint
#define istpunct	iswpunct
#define istspace	iswspace
#define istupper	iswupper
#define istxdigit	iswxdigit
#define totupper	towupper
#define totlower	towlower
#define tmain		wmain

#define tfprintf	fwprintf
#define tprintf		fwprintf
#define tsprintf	swprintf
#define tvfprintf	vfwprintf
#define tvprintf	vfwprintf
#define tvsprintf	vswprintf
#define tfscanf		fwscanf
#define tscanf		wscanf
#define tsscanf		swscanf

#define tdirent		wdirent
#define tDIR		WDIR

#define taccess		_waccess
#define tclosedir	wclosedir
#define tlink		wlink
#define topendir	wopendir
#define treaddir	wreaddir
#define trename		wrename
#define trewinddir	wrewinddir
#define tseekdir	wseekdir
#define tstat		wstat
#define tstatvfs	wstatvfs
#define tunlink		_wunlink

typedef wchar tchar;
typedef wchar tuchar;

#else	// UNICODE
#define T(str)		str

#define tstring		string
#define tstrcmp		strcmp
#define tstricmp	stricmp
#define tstrncmp	strncmp
#define tstrnicmp	strnicmp
#define tstrcat		strcat
#define tstrlcat	strlcat
#define tstrncat	strncat
#define tstrcpy		strcpy
#define tstrlcpy	strlcpy
#define tstrncpy	strncpy
#define tstrlen		strlen
#define	tstrchr		strchr
#define tstrrchr	strrchr
#define tstrspn		strspn
#define tstrcspn	strcspn
#define tstrpbrk	strpbrk
#define tstrstr		strstr
#define tstrtok		strtok
#define tstrdup		strdup
#define tstrerror	strerror
#define tstrerror_r	strerror_r
#define tstrftime	strftime
#define ttof		atof
#define ttoi		atoi
#define ttol		atol
#define tstrtod		strtod
#define tstrtol		strtol
#define tstrtoul	strtoul
#define texecvp		execvp
#define tgetcwd		getcwd
#define tgetenv		getenv
#define istalnum(c)	isalnum((uchar)c)
#define istalpha(c)	isalpha((uchar)c)
#define istblank(c)	isblank((uchar)c)
#define istcntrl(c)	iscntrl((uchar)c)
#define istdigit(c)	isdigit((uchar)c)
#define istgraph(c)	isgraph((uchar)c)
#define istlower(c)	islower((uchar)c)
#define istprint(c)	isprint((uchar)c)
#define istpunct(c)	ispunct((uchar)c)
#define istspace(c)	isspace((uchar)c)
#define istupper(c)	isupper((uchar)c)
#define istxdigit(c)	isxdigit((uchar)c)
#define totupper(c)	toupper((uchar)c)
#define totlower(c)	tolower((uchar)c)
#define tmain		main

#define tfprintf	fprintf
#define tprintf		fprintf
#define tsprintf	sprintf
#define tvfprintf	vfprintf
#define tvprintf	vfprintf
#define tvsprintf	vsprintf
#define tfscanf		fscanf
#define tscanf		scanf
#define tsscanf		sscanf

#define tdirent		dirent
#define tDIR		DIR

#define taccess		access
#define tclosedir	closedir
#define tlink		link
#define topendir	opendir
#define treaddir	readdir
#define trename		rename
#define trewinddir	rewinddir
#define tseekdir	seekdir
#define tstat		stat
#define tstatvfs	statvfs
#define tunlink		unlink

typedef char tchar;
typedef unsigned char tuchar;
#endif // UNICODE

#define tstreq(a, b)	!tstrcmp(a, b)
#define tstrieq(a, b)	!tstricmp(a, b)

typedef unsigned char byte;
typedef unsigned char uchar;
typedef unsigned short word;

// process resource usage in kb / msec
struct pidstat {
    uint64_t pss;
    uint64_t rss;
    uint64_t sz;
    uint64_t stime;
    uint64_t utime;
};

// current and linear time routines
typedef uint64_t msec_t;
typedef uint64_t usec_t;

inline usec_t microtime(void) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (usec_t)tv.tv_sec * (usec_t)1000000 + (usec_t)tv.tv_usec;
}

inline void time_adjust_msec(struct timespec *ts, ulong msec) {
    ts->tv_sec += (time_t)(msec / 1000U);
    *(ulong *)&ts->tv_nsec += (msec % 1000U) * 1000000U;
    if ((ulong)ts->tv_nsec > 1000000000U) {
	*(ulong *)&ts->tv_nsec -= 1000000000U;
	++ts->tv_sec;
    }
}

#define millitime()	((msec_t)(microtime() / 1000))

EXTERNC
extern int lockfile(int fd, short type, short whence, ulong start, ulong len,
    short test);
extern msec_t mticks(void);
extern usec_t uticks(void);
#pragma GCC push_options
#pragma GCC diagnostic ignored "-Wshadow"
extern int pidstat(pid_t pid, struct pidstat *psbuf);
#pragma GCC pop_options
EXTERNC_

// common includes, defines and code for C++ software
#ifdef __cplusplus

#include <functional>
#include <iostream>
#include <string>

using namespace std;
#if _MSC_VER >= 1500 && _MSC_VER < 1600
using namespace stdext;
#endif

// cross-compiler support for unordered maps and sets
#if defined(__GNUC__) && (!defined(__clang_major__) || __clang_major__ < 5) && \
    __cplusplus < 201103L
#if GNUC_VERSION < 40300
#define STL_UNORDERED_MAP_H	<ext/hash_map>
#define STL_UNORDERED_SET_H	<ext/hash_set>
#define unordered_map		hash_map
#define unordered_multimap	hash_multimap
#define unordered_set		hash_set
#define unordered_multiset	hash_multiset

using namespace __gnu_cxx;
#else
#define STL_UNORDERED_MAP_H	<tr1/unordered_map>
#define STL_UNORDERED_SET_H	<tr1/unordered_set>

namespace std { namespace tr1 {} }
using namespace std::tr1;
#endif

#else

#define STL_UNORDERED_MAP_H	<unordered_map>
#define STL_UNORDERED_SET_H	<unordered_set>
#endif

// narrow / wide sring routines
extern const wstring _achartowstring(const char *s, size_t len);
extern const string _wchartoastring(const wchar *s, size_t len);

inline const wstring astringtowstring(const string &s) {
    return _achartowstring(s.c_str(), s.size() + 1);
}

inline const string wstringtoastring(const wstring &s) {
    return _wchartoastring(s.c_str(), s.size() + 1);
}

#define achartowchar(s)		achartowstring(s).c_str()
#define achartowstring(s)	_achartowstring((s), -1)
#define astringtoachar(s)	(s).c_str()
#define astringtowchar(s)	astringtowstring(s).c_str()
#define wchartoachar(s)		wchartoastring(s).c_str()
#define wchartoastring(s)	_wchartoastring((s), -1)
#define wstringtoachar(s)	wstringtoastring(s).c_str()
#define wstringtowchar(s)	(s).c_str()

#ifdef UNICODE
#define achartotchar(s)		achartowchar(s)
#define achartotstring(s)	achartowstring(s)
#define astringtotchar(s)	astringtowchar(s)
#define astringtotstring(s)	astringtowstring(s)
#define tchartoachar(s)		wchartoachar(s)
#define tchartowchar(s)		(s)
#define tchartotstring(s)	wstring(s)
#define tstringtoachar(s)	wstringtoachar(s)
#define tstringtoastring(s)	wstringtoastring(s)
#define tstringtowchar(s)	wstringtowchar(s)
#define tstringtowstring(s)	(s)
#define wchartotchar(s)		wchartowchar(s)
#define wchartotstring(s)	wchartowstring(s)
#define wstringtotchar(s)	wstringtowchar(s)
#define wstringtotstring(s)	wstringtowstring(s)

#define tcerr			wcerr
#define tcin			wcin
#define tcout			wcout
#define tstreambuf		wstreambuf
#define tistream		wistream
#define tostream		wostream
#define tiostream		wiostream
#define tfstream		wfstream
#define tifstream		wifstream
#define tofstream		wofstream
#define tstringstream		wstringstream
#define tistringstream		wistringstream
#define tostringstream		wostringstream
#define tstrstream		wstrstream
#define tistrstream		wistrstream
#define tostrstream		wostrstream
#define tstringbuf		wstringbuf

#else

#define achartotchar(s)		(s)
#define achartotstring(s)	string(s)
#define astringtotchar(s)	astringtoachar(s)
#define astringtotstring(s)	(s)
#define tchartoachar(s)		(s)
#define tchartowchar(s)		achartowchar(s)
#define tchartotstring(s)	string(s)
#define tstringtoachar(s)	astringtoachar(s)
#define tstringtoastring(s)	(s)
#define tstringtowchar(s)	astringtowchar(s)
#define tstringtowstring(s)	astringtowstring(s)
#define wchartotchar(s)		wchartoachar(s)
#define wchartotstring(s)	wchartoastring(s)
#define wstringtotchar(s)	wstringtoachar(s)
#define wstringtotstring(s)	wstringtoastring(s)

#define tcerr			cerr
#define tcin			cin
#define tcout			cout
#define tstreambuf		streambuf
#define tistream		istream
#define tostream		ostream
#define tiostream		iostream
#define tfstream		fstream
#define tifstream		ifstream
#define tofstream		ofstream
#define tstringstream		stringstream
#define tistringstream		istringstream
#define tostringstream		ostringstream
#define tstrstream		strstream
#define tistrstream		istrstream
#define tostrstream		ostrstream
#define tstringbuf		stringbuf
#endif

// useful string utils
inline int to_lower(int c) { return _tolower((uchar)(c)); }
inline int to_upper(int c) { return _toupper((uchar)(c)); }
inline int stringcmp(const char *a, const char *b) { return strcmp(a, b); }
inline int stringcmp(const wchar *a, const wchar *b) { return wcscmp(a, b); }
inline int stringicmp(const char *a, const char *b) { return stricmp(a, b); }
inline int stringicmp(const wchar *a, const wchar *b) { return wcsicmp(a, b); }

template<class C>
inline bool stringeq(const C *a, const C *b) {
    do {
	if (*a != *b)
	    return false;
    } while (a++, *b++);
    return true;
}

template<class C>
inline bool stringeq(const C &a, const C &b) {
    return stringeq(a.c_str(), b.c_str());
}

template<class C>
inline bool stringless(const C *a, const C *b) {
    do {
	if (*a < *b)
	    return true;
	else if (*a != *b)
	    return false;
    } while (a++, *b++);
    return false;
}

template<class C>
inline bool stringless(const C &a, const C &b) {
    return stringless(a.c_str(), b.c_str());
}

template<class C>
__no_sanitize("unsigned-integer-overflow") inline size_t stringhash(const C *s) {
    size_t ret = 0;

    while (*s)
	ret = ret * 101 + (size_t)*s++;
    return ret;
}

__no_sanitize("unsigned-integer-overflow") inline size_t stringihash(const char
    *s) {
    size_t ret = 0;

    while (*s)
	ret = ret * 101 + (size_t)to_upper(*s++);
    return ret;
}

__no_sanitize("unsigned-integer-overflow") inline size_t stringihash(const wchar
    *s) {
    size_t ret = 0;

    while (*s)
	ret = ret * 101 + (size_t)towupper((ushort)*s++);
    return ret;
}

template<class C>
struct ptrhash {
    size_t operator ()(const C *p) const { return (size_t)p; }
};

struct llonghash {
    size_t operator ()(llong l) const { return (size_t)((l >> 32) ^ l); }
};

struct ullonghash {
    size_t operator ()(ullong u) const { return (size_t)((u >> 32) ^ u); }
};

template <class C>
struct strhash {
    size_t operator ()(const C *s) const { return stringhash(s); }
    size_t operator ()(const basic_string<C> &s) const {
	return stringhash(s.c_str());
    }
};

template <class C>
struct strihash {
    size_t operator ()(const C *s) const { return stringihash(s); }
    size_t operator ()(const basic_string<C> &s) const {
	return stringihash(s.c_str());
    }
};

template<class C>
struct streq {
    bool operator()(const C *a, const C *b) const { return stringeq(a, b); }
    bool operator()(const basic_string<C> &a, const basic_string<C> &b) const {
	return stringeq(a, b);
    }
    static bool equal(const C *a, const C *b) { return stringeq(a, b); }
    static bool equal(const basic_string<C> &a, const basic_string<C> &b) {
	return stringeq(a, b);
    }
};

template<class C>
struct strieq {
    bool operator()(const C *a, const C *b) const {
	return stringicmp(a, b) == 0;
    }
    bool operator()(const basic_string<C> &a, const basic_string<C> &b) const {
	return stringicmp(a.c_str(), b.c_str()) == 0;
    }
    static bool equal(const C *a, const C *b) { return stringicmp(a, b) == 0; }
    static bool equal(const basic_string<C> &a, const basic_string<C> &b) {
	return stringicmp(a, b) == 0;
    }
};

template <class C>
struct strless {
    bool operator ()(const C *a, const C *b) const { return stringless(a, b); }
    bool operator ()(const basic_string<C> &a, const basic_string<C> &b) const {
	return stringless(a, b);
    }
    static bool less(const C *a, const C *b) { return stringless(a, b); }
    static bool less(const basic_string<C> &a, const basic_string<C> &b) {
	return stringless(a, b);
    }
};

template <class C>
struct striless {
    bool operator ()(const C *a, const C *b) const {
	return stringicmp(a, b) < 0;
    }
    bool operator ()(const basic_string<C> &a, const basic_string<C> &b) const {
	return stringicmp(a.c_str(), b.c_str()) < 0;
    }
    static bool less(const C *a, const C *b) { return stringicmp(a, b) < 0; }
    static bool less(const basic_string<C> &a, const basic_string<C> &b) {
	return stringicmp(a, b) < 0;
    }
};

// compile time string hashing
#define STRING_HASH_PRE(i, d)	((
#define STRING_HASH_POST(i, d)	* 101) + (size_t)s[i])
#define STRING_HASH(i) __forceinline StringHash(const tchar (&s)[i]): \
    hash(STDAPI_REPEAT(i, STRING_HASH_PRE, ~) 0 STDAPI_REPEAT(i, \
	STRING_HASH_POST, ~)) {}

class StringHash {
public:
    struct DynamicString {
	__forceinline DynamicString(const tchar *str): s(str) {}

	const tchar *s;
    };

    __forceinline StringHash(const DynamicString &ds): hash(stringhash(ds.s)) {}

    STRING_HASH(1) STRING_HASH(2) STRING_HASH(3) STRING_HASH(4)
    STRING_HASH(5) STRING_HASH(6) STRING_HASH(7) STRING_HASH(8)
    STRING_HASH(9) STRING_HASH(10) STRING_HASH(11) STRING_HASH(12)
    STRING_HASH(13) STRING_HASH(14) STRING_HASH(15) STRING_HASH(16)
    STRING_HASH(17) STRING_HASH(18) STRING_HASH(19) STRING_HASH(20)
    STRING_HASH(21) STRING_HASH(22) STRING_HASH(23) STRING_HASH(24)
    STRING_HASH(25) STRING_HASH(26) STRING_HASH(27) STRING_HASH(28)
    STRING_HASH(29) STRING_HASH(30) STRING_HASH(31) STRING_HASH(32)
    STRING_HASH(33) STRING_HASH(34) STRING_HASH(35) STRING_HASH(36)
    STRING_HASH(37) STRING_HASH(38) STRING_HASH(39) STRING_HASH(40)
    STRING_HASH(41) STRING_HASH(42) STRING_HASH(43) STRING_HASH(44)
    STRING_HASH(45) STRING_HASH(46) STRING_HASH(47) STRING_HASH(48)
    STRING_HASH(49) STRING_HASH(50) STRING_HASH(51) STRING_HASH(52)
    STRING_HASH(53) STRING_HASH(54) STRING_HASH(55) STRING_HASH(56)
    STRING_HASH(57) STRING_HASH(58) STRING_HASH(59) STRING_HASH(60)
    STRING_HASH(61) STRING_HASH(62) STRING_HASH(63) STRING_HASH(64)

    __forceinline operator size_t(void) const { return hash; }

private:
    size_t hash;
};

// prohibit object copies by subclassing this
class nocopy {
protected:
    nocopy() {}

private:
    nocopy(const nocopy &);
    const nocopy & operator =(const nocopy &);
};

// fast single linked object list
template <class C>
class ObjectList: nocopy {
public:
    ObjectList(): back(NULL), front(NULL), sz(0) {}

    bool operator !(void) const { return front == NULL; }
    operator bool(void) const { return front != NULL; }
    bool empty(void) const { return front == NULL; }
    const C *peek(void) const { return front; }
    uint size(void) const { return sz; }

    void pop(C &obj) {
	if (front == &obj) {
	    if ((front = obj.next) == NULL)
		back = NULL;
	    --sz;
	} else {
	    for (C *p = front; p; p = p->next) {
		if (p->next == &obj) {
		    if ((p->next = obj.next) == NULL)
			back = p;
		    else
			obj.next = NULL;
		    --sz;
		    break;
		}
	    }
	}
    }
    C *pop_back(void) {
	C *obj = back;

	if (front == back) {
	    front = back = NULL;
	} else {
	    C *p = front;

	    while (p->next != back)
		p = p->next;
	    back = p;
	    back->next = NULL;
	}
	--sz;
	return obj;
    }
    C *pop_front(void) {
	C *obj = front;

	if ((front = front->next) == NULL)
	    back = NULL;
	else
	    obj->next = NULL;
	--sz;
	return obj;
    }
    void push_back(C &obj) {
	if (back)
	    back->next = &obj;
	else
	    front = &obj;
	back = &obj;
	++sz;
    }
    void push_back(ObjectList &lst) {
	if (lst.front) {
	    if (back)
		back->next = lst.front;
	    else
		front = lst.front;
	    back = lst.back;
	    lst.front = lst.back = NULL;
	    sz += lst.sz;
	    lst.sz = 0;
	}
    }
    void push_front(C &obj) {
	if ((obj.next = front) == NULL)
	    back = &obj;
	front = &obj;
	++sz;
    }
    void push_front(ObjectList &lst) {
	if (lst.back) {
	    lst.back->next = front;
	    front = lst.front;
	    lst.front = lst.back = NULL;
	    sz += lst.sz;
	    lst.sz = 0;
	}
    }

private:
    C *back, *front;
    uint sz;
};

#endif

#endif // stdapi_h
