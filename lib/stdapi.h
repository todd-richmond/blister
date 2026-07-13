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

#ifndef stdapi_h
#define stdapi_h

// defines, typedefs and code to make non-UNIX systems support POSIX APIs
#define CPP_STR(s)		#s

#if defined(__GNUC__) || defined(__clang__)
#define LIKELY(c)		__builtin_expect(!!(c), 1)
#define UNLIKELY(c)		__builtin_expect(!!(c), 0)
#else
#define LIKELY(x)		(x)
#define UNLIKELY(x)		(x)
#endif

#ifdef _MSC_VER
#define __no_sanitize(check)
#define __no_sanitize_address
#define __no_sanitize_memory
#define __no_sanitize_thread
#define __no_sanitize_unsigned
#define __builtin_prefetch(p, i, j)
#define DLL_EXPORT		__declspec(dllexport)
#define DLL_IMPORT		__declspec(dllimport)
#define DLL_LOCAL
#define PRAGMA_STR(s)		__pragma(s)
#define WARN_DISABLE(w)		PRAGMA_STR(warning(disable: w))
#define WARN_ENABLE(w)		PRAGMA_STR(warning(enable: w))
#define WARN_POP()		PRAGMA_STR(warning(pop))
#define WARN_PUSH()		PRAGMA_STR(warning(push))
#elif defined(__GNUC__)
#define GNUC_VERSION (__GNUC__ * 10000 + __GNUC_MINOR__ * 100 + \
    __GNUC_PATCHLEVEL__)
#ifdef __OPTIMIZE__
#define __forceinline		__attribute__((always_inline))
#else
#define __forceinline		inline
#endif
#ifdef __has_feature
#define __no_sanitize(check)	__attribute__((no_sanitize(check)))
#else
#define __no_sanitize(check)
#endif
#define __no_sanitize_address	__no_sanitize("address")
#define __no_sanitize_memory	__no_sanitize("memory")
#define __no_sanitize_thread	__no_sanitize("thread")
#define __no_sanitize_unsigned	__no_sanitize("unsigned-integer-overflow")
#define DLL_EXPORT		__attribute__((visibility("default")))
#define DLL_IMPORT		__attribute__((visibility("default")))
#define DLL_LOCAL		__attribute__((visibility("hidden")))
#define PRAGMA_STR(s)		_Pragma (#s)
#define WARN_DISABLE(w)		PRAGMA_STR(GCC diagnostic ignored #w)
#define WARN_ENABLE(w)		PRAGMA_STR(GCC diagnostic warning #w)
#define WARN_POP()		PRAGMA_STR(GCC pop_options)
#define WARN_PUSH()		PRAGMA_STR(GCC push_options)
#endif

#define WARN_PUSH_DISABLE(w)	WARN_PUSH() \
				WARN_DISABLE(w)

#ifdef __cplusplus
#if __cplusplus <= 201103L
#define CPLUSPLUS	11
#elif __cplusplus <= 201402L
#define CPLUSPLUS	14
#elif __cplusplus <= 201703L
#define CPLUSPLUS	17
#elif __cplusplus <= 202002L
#define CPLUSPLUS	20
#elif __cplusplus <= 202302L
#define CPLUSPLUS	23
#else
#define CPLUSPLUS	26
#endif
#define EXTERNC		extern "C" {
#define EXTERNC_	}
#define LAMBDA(m)	[this]() { m(); }
#else
#define EXTERNC
#define EXTERNC_
#endif

#ifdef BUILD_BLISTER
#define BLISTER			DLL_EXPORT
#else
#define BLISTER			DLL_IMPORT
#endif

#ifdef _WIN32
#ifndef BLISTER_DLL
#undef BLISTER
#define BLISTER
#endif

#pragma inline_depth(69)
#pragma warning(disable: 4018 4068 4097 4100 4103 4127 4146 4200 4201 4250)
#pragma warning(disable: 4251 4335 4324 4503 4511 4512 4530 4577 4619 4625 4626)
#pragma warning(disable: 4668 4710 4711 4786 4820 4996 5026 5027)
#pragma warning(disable: 26110 26135 26400 26401 26408 26409 26426 26429 26432)
#pragma warning(disable: 26433 26434 26438 26440 26443 26446 26447 26455 26457)
#pragma warning(disable: 26462 26472 26494 26496 26497 28125 26477 26481 26482)
#pragma warning(disable: 26485 26486 26487 26489 26492 26493 26812 26814 26818)
#pragma warning(disable: 26819 26826)

#ifndef WIN32
#define WIN32
#endif
#define _WIN32_WINNT	_WIN32_WINNT_WIN10
#define NTDDI_VERSION	NTDDI_WIN10
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
typedef __int64 _ino_t;	// -V677
#endif
#define __STDC__ 1
#include <ctype.h>
#include <direct.h>
#include <io.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#undef __STDC__
#ifdef _CRT_INTERNAL_NONSTDC_NAMES
#undef _CRT_INTERNAL_NONSTDC_NAMES
#define _CRT_INTERNAL_NONSTDC_NAMES 1
#endif
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>
#include <WinSock2.h>
#include <ws2def.h>
#include <sys/stat.h>

#undef _INO_T_DEFINED
#undef _STAT_DEFINED
#undef _WSTAT_DEFINED
#undef fstat
#undef ino_t
#undef rename
#undef stat
#undef wstat
#define stricmp		_stricmp
#define wcsicmp		_wcsicmp

#ifndef __cplusplus
#define inline		__inline
#endif

#define O_COMPRESSED	0x010000
#define O_POSIX		0x020000
#define O_SYNC		0x040000
#define O_DIRECT	0x080000
#define O_OVERLAPPED	0x100000
#define O_BACKUP	0x200000
#define O_NONBLOCK	0x400000
#define O_CLOEXEC	0
#define O_DSYNC		O_SYNC
#define O_SHORT_LIVED	_O_SHORT_LIVED
#define O_TMPFILE	O_TEMPORARY

#define SIGHUP		SIGBREAK
#define SIGCHLD		80	// out of range
#define SIGPIPE		81

#define S_IRUSR		_S_IREAD
#define S_IWUSR		_S_IWRITE
#define S_IXUSR		_S_IEXEC
#define S_IRWXU		(S_IRUSR | S_IWUSR | S_IXUSR)
#define S_IRGRP		00040
#define S_IWGRP		00020
#define S_IXGRP		00010
#define S_IRWXG		(S_IRGRP | S_IWGRP | S_IXGRP)
#define S_IROTH		00004
#define S_IWOTH		00002
#define S_IXOTH		00001
#define S_IRWXO		(S_IROTH | S_IWOTH | S_IXOTH)

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
typedef llong ino_t;	// -V677
typedef short nlink_t;
typedef long pid_t;
typedef long timer_t;
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
typedef struct _WSABUF iovec;
typedef struct _WSABUF iovec_t;
typedef ULONG iovlen_t;
#define iov_len len
#define iov_base buf

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

// replacement CLib supports atomic rename, deleting open files and socket fds
#define fileno(stream)	(_get_osfhandle((stream)->_file))

EXTERNC
extern BLISTER int access(const char *path, int mode);
extern BLISTER int chmod(const char *path, int mode);
extern BLISTER int chsize(int fd, long len);
extern BLISTER int close(int fd);
extern BLISTER void closedir(DIR *dir);
extern BLISTER int creat(const char *path, int mode);
extern BLISTER int copy_file(const char *from, const char *to, int check);
extern BLISTER int dup(int fd);
extern BLISTER int dup2(int from, int to);
extern BLISTER int eof(int fd);
extern BLISTER long filelength(int fd);
extern BLISTER int flock(int fd, int op);
extern BLISTER int fstat(int fd, struct stat *buf);
extern BLISTER int fsync(int fd);
extern BLISTER int ftruncate(int fd, long len);
extern BLISTER int gettimeofday(struct timeval *tv, struct timezone *tz);
extern BLISTER int isatty(int fd);
extern BLISTER int link(const char *from, const char *to);
extern BLISTER int lockf(int fd, int op, long len);
extern BLISTER long lseek(int, long, int);
extern BLISTER char *mktemp(char *path);
extern BLISTER int open(const char *path, int mode, ...);
extern BLISTER DIR *opendir(const char *path);
extern BLISTER int read(int, void *, unsigned int);
extern BLISTER dirent *readdir(DIR *dir);
extern BLISTER long readv(int fd, iovec *vec, int numvec);
extern BLISTER int rename(const char *from, const char *to);
extern BLISTER void seekdir(DIR *dir, long offset);
extern BLISTER int setmode(int fd, int mode);
extern BLISTER int sigsend(idtype_t idtype, id_t id, int sig);
extern BLISTER int stat(const char *path, struct stat *buf);
extern BLISTER int statvfs(const char *path, struct statvfs *buf);
extern BLISTER long tell(int fd);
extern BLISTER int umask(int mode);
extern BLISTER int unlink(const char *path);
extern BLISTER int waccess(const wchar *path, int mode);
extern BLISTER int wchmod(const wchar *path, int mode);
extern BLISTER void wclosedir(WDIR *dir);
extern BLISTER int wcopy_file(const wchar *from, const wchar *to, int check);
extern BLISTER int wcreat(const wchar *path, int mode);
extern BLISTER wchar *wmktemp(wchar *path);
extern BLISTER int wlink(const wchar *from, const wchar *to);
extern BLISTER int wopen(const wchar *path, int mode, ...);
extern BLISTER WDIR *wopendir(const wchar *path);
extern BLISTER wdirent *wreaddir(WDIR *dir);
extern BLISTER int wrename(const wchar *from, const wchar *to);
extern BLISTER int write(int, const void *, uint);
extern BLISTER long writev(int fd, const iovec *vec, int numvec);
extern BLISTER void wseekdir(WDIR *dir, long);
extern BLISTER int wstat(const wchar *wpath, struct stat *buf);
extern BLISTER int wstatvfs(const wchar *wpath, struct statvfs *buf);
extern BLISTER int wunlink(const wchar *path);
EXTERNC_

#define asctime_r(tm, buf, sz)	asctime_s(buf, sz, tm)
#define ctime_r(clock, buf)	(ctime_s(buf, 26, clock), (buf))
#define gmtime_r(clock, buf)	(gmtime_s((buf), (clock)), (buf))
#define localtime_r(clock, buf)	(localtime_s((buf), (clock)), (buf))
#define strerror_r(e, buf, sz)	strlcpy(buf, strerror(e), sz)

#else // _WIN32

#define _DARWIN_C_SOURCE
#define _FILE_OFFSET_BITS	64
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _LARGEFILE_SOURCE
#define _LARGEFILE_SOURCE	1
#define _LARGEFILE64_SOURCE	1
#endif
#ifndef _REENTRANT
#define _REENTRANT
#endif
#define MAC_OS_X_VERSION_MIN_REQUIRED MAC_OS_X_VERSION_15_0
#define __BSD_VISIBLE		1

#include <ctype.h>
#include <unistd.h>
#include <limits.h>
#ifdef __AVX2__
#include <immintrin.h>
#elif defined(__ARM_NEON)
#include <arm_neon.h>
#endif
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/time.h>
#include <sys/uio.h>
#define __cdecl
#define __declspec(x)
#ifndef __fastcall
#define __fastcall
#endif
#define __stdcall

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
#ifndef O_CLOEXEC
#define O_CLOEXEC	0
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
#ifdef __APPLE__
typedef long timer_t;
#endif
#define BSD_BASE
typedef unsigned short ushort;
typedef unsigned int uint;
#endif

typedef size_t iovlen_t;
typedef long long llong;
typedef unsigned long ulong;
typedef unsigned long long ullong;
typedef wchar_t wchar;

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
#ifndef CLOCK_REALTIME_COARSE
#define CLOCK_REALTIME_COARSE	CLOCK_REALTIME
#endif

#if (defined(BSD_BASE) || defined(__sun__)) && !defined(__APPLE__)
EXTERNC
extern int wcscasecmp(const wchar_t *, const wchar_t *);
EXTERNC_
#endif
#endif // _WIN32

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
#define tstring_view	wstring_view
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
#define tstrtoll	wcstoll
#define tstrtoul	wcstoul
#define tstrtoull	wcstoull
#define tstrtoq		wcstoq
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
#define tsnprintf	snwprintf
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

#define tspawnl		_wspawnvl
#define tspawnle	_wspawnle
#define tspawnlp	_wspawnlp
#define tspawnlpe	_wspawnlpe
#define tspawnv		_wspawnv
#define tspawnve	_wspawnve
#define tspawnvp	_wspawnvp
#define tspawnvpe	_wspawnvpe

typedef wchar tchar;
typedef wchar tuchar;

#else	// UNICODE
#define T(str)		str

#define tstring		string
#define tstring_view	string_view
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
#define tstrtoll	strtoll
#define tstrtoul	strtoul
#define tstrtoull	strtoull
#define tstrtoq		strtoq
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
#define tsnprintf	snprintf
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

#define tspawnl		_spawnvl
#define tspawnle	_spawnle
#define tspawnlp	_spawnlp
#define tspawnlpe	_spawnlpe
#define tspawnv		_spawnv
#define tspawnve	_spawnve
#define tspawnvp	_spawnvp
#define tspawnvpe	_spawnvpe

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

inline void time_adjust_msec(struct timespec *ts, ulong msec) {
    ulong nsec = (ulong)ts->tv_nsec + (msec % 1000UL) * 1000000UL;

    ts->tv_sec += (time_t)(msec / 1000UL);
    if (nsec >= 1000000000UL) {
	nsec -= 1000000000UL;
	++ts->tv_sec;
    }
    ts->tv_nsec = (long)nsec;
}

EXTERNC
extern BLISTER int lockfile(int fd, short type, short whence, ulong start, ulong
    len, short test);
extern BLISTER msec_t mticks(void);
extern BLISTER usec_t uticks(void);
#ifndef _WIN32
WARN_PUSH_DISABLE(-Wshadow)
extern BLISTER int pidstat(pid_t pid, struct pidstat *psbuf);
WARN_POP()
#endif
EXTERNC_

// common includes, defines and code for C++ software
#ifdef __cplusplus

#include <chrono>
#include <functional>
#include <iostream>
#include <new>
#include <string>
#include <string_view>

using namespace std;

// narrow / wide string routines
extern BLISTER wstring _achartowstring(const char *s, size_t len);
extern BLISTER string _wchartoastring(const wchar *s, size_t len);

inline wstring astringtowstring(const string &s) {
    return _achartowstring(s.c_str(), s.size() + 1);
}

inline string wstringtoastring(const wstring &s) {
    return _wchartoastring(s.c_str(), s.size() + 1);
}

#define achartowchar(s)		achartowstring(s).c_str()
#define achartowstring(s)	_achartowstring((s), (size_t)-1)
#define astringtoachar(s)	(s).c_str()
#define astringtowchar(s)	astringtowstring(s).c_str()
#define wchartoachar(s)		wchartoastring(s).c_str()
#define wchartoastring(s)	_wchartoastring((s), (size_t)-1)
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
template<typename T>
__forceinline T atou(const tchar *str) {
    size_t d, val = 0;

    while ((d = (size_t)(tuchar)*str - '0') <= 9) {
	size_t d2 = (size_t)(tuchar)str[1] - '0';

	if (d2 > 9) {
	    val = val * 10 + d;
	    break;
	}
	val = val * 100 + d * 10 + d2;
	str += 2;
    }
    return (T)val;
}

#ifndef UNICODE
inline uint32_t swar4(const char *s) {
    uint32_t chunk;

    memcpy(&chunk, s, sizeof (chunk));
    chunk -= 0x30303030U;
    chunk = chunk * 10 + (chunk >> 8);
    chunk &= 0x00FF00FFU;
    return (chunk * (100 * 65536 + 1)) >> 16;
}

inline uint32_t swar8(const char *s) {
    uint64_t chunk;

    memcpy(&chunk, s, sizeof (chunk));
    chunk -= 0x3030303030303030ULL;
    chunk = chunk * 10 + (chunk >> 8);
    chunk = (((chunk & 0x000000FF000000FFULL) * 0x000F424000000064ULL) +
	((chunk >> 16 & 0x000000FF000000FFULL) * 0x0000271000000001ULL)) >> 32;
    return (uint32_t)chunk;
}
#endif

template<typename T>
__forceinline T atoun(const tchar *str, size_t len) {
#ifndef UNICODE
    size_t val = 0;

    if (len >= 8) {
	val = swar8(str);
	str += 8;
	len -= 8;
	if (len >= 8) {
	    val = val * 100000000ULL + swar8(str);
	    str += 8;
	    len -= 8;
	}
    }
    if (len >= 4) {
	val = val * 10000 + swar4(str);
	str += 4;
	len -= 4;
    }
    switch (len) {  // NOSONAR
    case 3: val = val * 1000 + (size_t)(str[0] - '0') * 100 +
	(size_t)(str[1] - '0') * 10 + (size_t)(str[2] - '0'); break;
    case 2: val = val * 100 + (size_t)(str[0] - '0') * 10 +
	(size_t)(str[1] - '0'); break;
    case 1: val = val * 10 + (size_t)(str[0] - '0'); break;
    }
    return (T)val;
#else
    size_t val = 0;
    for (size_t i = 0; i < len; ++i) {
	size_t d = (size_t)(tuchar)str[i] - '0';
	if (d > 9) break;
	val = val * 10 + d;
    }
    return (T)val;
#endif
}

template<typename T>
__forceinline T atoi(const tchar *str) {
    return *str == '-' ? (T)(~atou<size_t>(str + 1) + 1) : atou<T>(str);
}

template<typename T>
__forceinline T atod(const tchar *str) {
    return (T)tstrtod(str, nullptr);
}

template<typename T>
__forceinline T atoin(const tchar *str, size_t len) {
    return *str == '-' ? (T)(~atoun<size_t>(str + 1, len - 1) + 1) :
	atoun<T>(str, len);
}

// wchar_t to_chars overload
template<typename T>
auto to_chars(wchar_t *first, wchar_t *last, T value) {
    struct result {
	wchar_t *ptr;
	errc ec;
    };
    char buf[128];
    auto [char_end, char_ec] = to_chars(buf, buf + sizeof (buf), value);
    result r{first, char_ec};

    for (char *p = buf; p != char_end && r.ptr != last; ++p)
	*r.ptr++ = static_cast<wchar_t>(static_cast<uchar>(*p));
    if (r.ptr == last && char_ec == errc{})
	r.ec = errc::value_too_large;
    return r;
}

template<typename T>
__forceinline tchar *to_str(tchar *buf, tchar *last, T val) {
    auto [end, ec] = to_chars(buf, last, val);
    if (end < last) {
	*end = '\0';
	return end;
    }
    return buf;
}

// modern time(NULL) replacement
static inline time_t seconds(void) {
    return chrono::system_clock::to_time_t(chrono::system_clock::now());
}

// string comparison functions
template<class C>
__forceinline int stringcmp(const C *a, const C *b) { return tstrcmp(a, b); }

template<typename T>
__forceinline int stringcmp(const T &a, const T &b) {
    if constexpr (is_same_v<T, basic_string<typename T::value_type>>) {
	return a.compare(b);
    } else {
	size_t asz = a.size(), bsz = b.size();
	int ret = tstrncmp(a.data(), b.data(), asz < bsz ? asz : bsz);

	if (ret != 0)
	    return ret;
	if (asz < bsz)
	    return -1;
	return asz > bsz ? 1 : 0;
    }
}

template<class C>
__forceinline int stringicmp(const C *a, const C *b) { return tstricmp(a, b); }

template<typename T>
__forceinline int stringicmp(const T &a, const T &b) {
    if constexpr (is_same_v<T, basic_string<typename T::value_type>>) {
	return tstricmp(a.c_str(), b.c_str());
    } else {
	size_t asz = a.size(), bsz = b.size();
	int ret = tstrnicmp(a.data(), b.data(), asz < bsz ? asz : bsz);

	if (ret != 0)
	    return ret;
	if (asz < bsz)
	    return -1;
	return asz > bsz ? 1 : 0;
    }
}

template<class C>
__forceinline bool stringeq(const C *a, const C *b) {
    return *a == *b && tstrcmp(a, b) == 0;
}

template<typename T>
__forceinline bool stringeq(const T &a, const T &b) {
    if constexpr (is_same_v<T, basic_string<typename T::value_type>>) {
	return a == b;
    } else {
	return a.size() == b.size() && tstrncmp(a.data(), b.data(),
	    a.size()) == 0;
    }
}

template<class C, typename T>
__forceinline bool stringeq(const C *a, const basic_string_view<T> &b) {
    return tstrncmp(a, b.data(), b.size()) == 0 && a[b.size()] == '\0';
}

template<class C, typename T>
__forceinline bool stringeq(const C *a, const T &b) {
    return stringeq(a, basic_string_view<C>(b));
}

template<class C, typename T>
__forceinline bool stringeq(const T &a, const C *b) { return stringeq(b, a); }

template<typename T1, typename T2>
__forceinline bool stringeq(const T1 &a, const T2 &b) {
    if constexpr (is_same_v<T1, T2>) {
        return a == b;
    } else if constexpr (is_pointer_v<T1> && is_pointer_v<T2>) {
        return tstrcmp(a, b) == 0;
    } else if constexpr (is_pointer_v<T1>) {
        using CharType = remove_pointer_t<T1>;
        if constexpr (is_convertible_v<T2, basic_string_view<CharType>>) {
            basic_string_view<CharType> bv(b);

            return tstrncmp(a, bv.data(), bv.size()) == 0 && a[bv.size()] ==
		'\0';
        } else {
            return tstrcmp(a, tstring(b).c_str()) == 0;
        }
    } else if constexpr (is_pointer_v<T2>) {
        using CharType = remove_pointer_t<T2>;
        if constexpr (is_convertible_v<T1, basic_string_view<CharType>>) {
            basic_string_view<CharType> av(a);

            return tstrncmp(av.data(), b, av.size()) == 0 && b[av.size()] == '\0';
        } else {
            return tstrcmp(tstring(a).c_str(), b) == 0;
        }
    } else if constexpr (is_convertible_v<T1,
	basic_string_view<typename T1::value_type>> && is_convertible_v<T2,
	basic_string_view<typename T2::value_type>>) {
        basic_string_view<typename T1::value_type> av(a);
        basic_string_view<typename T2::value_type> bv(b);

        return av == bv;
    } else {
        return tstring(a) == tstring(b);
    }
}

template<class C>
__forceinline bool stringieq(const C *a, const C *b) {
    return stringicmp(a, b) == 0;
}

template<typename T>
__forceinline bool stringieq(const T &a, const T &b) {
    if constexpr (is_same_v<T, basic_string<typename T::value_type>>) {
	return a.size() == b.size() && tstricmp(a.c_str(), b.c_str()) == 0;
    } else {
	return a.size() == b.size() && tstrnicmp(a.data(), b.data(),
	    a.size()) == 0;
    }
}

template<class C, typename T>
__forceinline bool stringieq(const C *a, const basic_string_view<T> &b) {
    return tstrnicmp(a, b.data(), b.size()) == 0 && a[b.size()] == '\0';
}

template<class C, typename T>
__forceinline bool stringieq(const C *a, const T &b) {
    return stringieq(a, basic_string_view<C>(b));
}

template<class C, typename T>
__forceinline bool stringieq(const T &a, const C *b) { return stringieq(b, a); }

template<class C>
__forceinline bool stringless(const C *a, const C *b) {
    return tstrcmp(a, b) < 0;
}

template<typename T>
__forceinline bool stringless(const T &a, const T &b) {
    return a < b;
}

template<class C, typename T>
__forceinline bool stringless(const C *a, const basic_string_view<T> &b) {
	return tstrncmp(a, b.data(), b.size()) < 0;
}

template<class C, typename T>
__forceinline bool stringless(const C *a, const T &b) {
    return stringless(a, basic_string_view<C>(b));
}

template<class C, typename T>
__forceinline bool stringless(const T &a, const C *b) {
    basic_string_view<C> av(a);
    int ret = tstrncmp(av.data(), b, av.size());

    return ret < 0 || (ret == 0 && b[av.size()] != '\0');
}

// string comparison functors
struct streq {
    using is_transparent = void;
    template<typename T1, typename T2>
    bool operator ()(const T1 &a, const T2 &b) const { return stringeq(a, b); }
};

struct strieq {
    using is_transparent = void;
    template<typename T1, typename T2>
    bool operator ()(const T1 &a, const T2 &b) const { return stringieq(a, b); }
};

struct strless {
    using is_transparent = void;
    template<typename T1, typename T2>
    bool operator ()(const T1 &a, const T2 &b) const { return stringless(a, b); }
};

struct striless {
    using is_transparent = void;
    template<typename T1, typename T2>
    bool operator ()(const T1 &a, const T2 &b) const { return stringicmp(a, b) < 0; }
};

// Bernstein string hash with transform
using strhash_t = uint64_t;

template<class C, class F = decltype([](C c) { return c; })>
constexpr strhash_t bernstein_hash(const C *s, size_t len, F xfrm = {}) {
    size_t i;
    strhash_t r0 = 5381, r1 = 5381, ret;

    for (i = 0; i + 4 <= len; i += 4) {
	r0 = ((r0 << 5) + r0) ^ (strhash_t)xfrm(s[i]);
	r1 = ((r1 << 5) + r1) ^ (strhash_t)xfrm(s[i + 1]);
	r0 = ((r0 << 5) + r0) ^ (strhash_t)xfrm(s[i + 2]);
	r1 = ((r1 << 5) + r1) ^ (strhash_t)xfrm(s[i + 3]);
    }
    ret = r0 ^ r1;
    for (; i < len; ++i)
	ret = ((ret << 5) + ret) ^ (strhash_t)xfrm(s[i]);
    return ret;
}

template<class C, class F = decltype([](C c) { return c; })>
__forceinline strhash_t bernstein_hash(const C *s, F xfrm = {}) {
    C c0, c1, c2, c3;
    strhash_t r0 = 5381, r1 = 5381, ret;

    while ((c0 = s[0]) && (c1 = s[1]) && (c2 = s[2]) && (c3 = s[3])) {
	r0 = ((r0 << 5) + r0) ^ (strhash_t)xfrm(c0);
	r1 = ((r1 << 5) + r1) ^ (strhash_t)xfrm(c1);
	r0 = ((r0 << 5) + r0) ^ (strhash_t)xfrm(c2);
	r1 = ((r1 << 5) + r1) ^ (strhash_t)xfrm(c3);
	s += 4;
    }
    ret = r0 ^ r1;
    while ((c0 = *s++) != '\0')
	ret = ((ret << 5) + ret) ^ (strhash_t)xfrm(c0);
    return ret;
}

// compile-time version for string literals
template<class C, size_t N, class F = decltype([](C c) { return c; })>
constexpr strhash_t bernstein_hash(const C (&s)[N], F xfrm = {}) {
    static_assert(N > 0, "string literal required");
    return bernstein_hash(s, N - 1, xfrm);
}

// rapidhash for arbitrary binary data
static __forceinline strhash_t rapidmix(strhash_t a, strhash_t b) {
#ifdef _MSC_VER
    strhash_t hi;
    ullong r = _umul128(a, b, &hi);

    return r ^ hi;
#elif defined(__SIZEOF_INT128__)
    __uint128_t r = (__uint128_t)a * b;

    return (strhash_t)r ^ (strhash_t)(r >> 64);
#else
    strhash_t a_lo = (uint32_t)a, a_hi = a >> 32;
    strhash_t b_lo = (uint32_t)b, b_hi = b >> 32;
    strhash_t cross = a_lo * b_hi + a_hi * b_lo;
    strhash_t lo = a_lo * b_lo + (cross << 32);
    strhash_t hi = a_hi * b_hi + (cross >> 32);

    return lo ^ hi;
#endif
}

inline strhash_t rapid_hash(const void *data, size_t len) {
    static constexpr strhash_t RAPID_SECRET0 = 0x9e3779b97f4a7c15ULL;
    static constexpr strhash_t RAPID_SECRET1 = 0x6c62272e07bb0142ULL;
    static constexpr strhash_t RAPID_SECRET2 = 0x94d049bb133111ebULL;
    strhash_t a = RAPID_SECRET0 ^ (strhash_t)len;
    strhash_t b = RAPID_SECRET1;
    strhash_t c = RAPID_SECRET2;
    const uint8_t *p = (const uint8_t *)data;
    strhash_t r0, r1;

    if (LIKELY(len <= 16)) {
	r0 = r1 = 0;
	if (LIKELY(len >= 8)) {
	    memcpy(&r0, p, 8);
	    memcpy(&r1, p + len - 8, 8);
	} else if (len >= 4) {
	    uint32_t lo, hi;

	    memcpy(&lo, p, 4);
	    memcpy(&hi, p + len - 4, 4);
	    r0 = ((strhash_t)lo << 32) | hi;
	} else if (len > 0) {
	    r0 = ((strhash_t)p[0] << 16) | ((strhash_t)p[len >> 1] << 8) |
		p[len - 1];
	}
	a = rapidmix(r0 ^ RAPID_SECRET0, r1 ^ a);
	b = rapidmix(r1 ^ RAPID_SECRET1, r0 ^ b);
    } else {
	if (UNLIKELY(len >= 48)) {
	    strhash_t d = a, e = b, f = c;

	    do {
		strhash_t s0, s1, s2, s3, s4, s5;

		memcpy(&s0, p, 8); memcpy(&s1, p +  8, 8);
		memcpy(&s2, p + 16, 8); memcpy(&s3, p + 24, 8);
		memcpy(&s4, p + 32, 8); memcpy(&s5, p + 40, 8);
		a = rapidmix(s0 ^ RAPID_SECRET0, s1 ^ a);
		b = rapidmix(s2 ^ RAPID_SECRET1, s3 ^ b);
		c = rapidmix(s4 ^ RAPID_SECRET2, s5 ^ c);
		d = rapidmix(s1 ^ RAPID_SECRET0, s0 ^ d);
		e = rapidmix(s3 ^ RAPID_SECRET1, s2 ^ e);
		f = rapidmix(s5 ^ RAPID_SECRET2, s4 ^ f);
		p += 48;
		len -= 48;
	    } while (LIKELY(len >= 48));
	    a ^= d; b ^= e; c ^= f;
	}
	while (len >= 16) {
	    memcpy(&r0, p, 8); memcpy(&r1, p + 8, 8);
	    a = rapidmix(r0 ^ RAPID_SECRET0, r1 ^ a);
	    b = rapidmix(r1 ^ RAPID_SECRET1, r0 ^ b);
	    p += 16;
	    len -= 16;
	}
	if (len >= 8) {
	    memcpy(&r0, p, 8);
	    a = rapidmix(r0 ^ RAPID_SECRET0, a ^ RAPID_SECRET2);
	    p += 8;
	    len -= 8;
	}
	if (len >= 4) {
	    uint32_t r32;

	    memcpy(&r32, p, 4);
	    b = rapidmix((strhash_t)r32 ^ RAPID_SECRET1, b ^ RAPID_SECRET0);
	    p += 4;
	    len -= 4;
	}
	for (size_t i = 0; i < len; ++i)
	    a ^= (strhash_t)p[i] << (i * 8);
    }
    return rapidmix(a ^ b ^ c ^ RAPID_SECRET0, a ^ b ^ RAPID_SECRET1);
}

template<class C, size_t N>
constexpr strhash_t stringhash(const C (&s)[N]) {
    return bernstein_hash(s);
}

template<typename T>
__forceinline strhash_t stringhash(const T &s) {
    if constexpr (is_class_v<T> && requires { typename T::value_type;
	s.c_str(); s.size(); }) {
	return bernstein_hash(s.c_str(), s.size());
    } else if constexpr (requires { s.data(); s.size(); }) {
	return bernstein_hash(s.data(), s.size());
    } else {
	return bernstein_hash(s);
    }
}

template<typename C>
constexpr auto ascii_fold = [](C c) { return c | (C)((c - 'A') <= (C)('Z' - 'A') ? 0x20 : 0); };
constexpr auto unicode_fold = [](wchar c) { return towupper((ushort)c); };

template<typename C, size_t N>
constexpr strhash_t stringiasciihash(const C (&s)[N]) {
    return bernstein_hash(s, ascii_fold<C>);
}

template<typename T>
__forceinline strhash_t stringiasciihash(const T &s) {
    if constexpr (is_class_v<T> && requires { typename T::value_type;
	s.c_str(); s.size(); }) {
	return bernstein_hash(s.c_str(), s.size(), ascii_fold<typename
	    T::value_type>);
    } else if constexpr (requires { s.data(); s.size(); }) {
	return bernstein_hash(s.data(), s.size(), ascii_fold<typename
	    T::value_type>);
    } else {
	using C = remove_pointer_t<remove_cv_t<T>>;
	return bernstein_hash(s, ascii_fold<C>);
    }
}

template<typename C, size_t N>
constexpr strhash_t stringihash(const C (&s)[N]) {
    if constexpr (is_same_v<C, wchar>) {
	return bernstein_hash(s, unicode_fold);
    } else {
	return bernstein_hash(s, ascii_fold<C>);
    }
}

template<typename T>
__forceinline strhash_t stringihash(const T &s) {
    if constexpr (is_class_v<T> && requires { typename T::value_type;
	s.c_str(); s.size(); }) {
	if constexpr (is_same_v<typename T::value_type, wchar>) {
	    return bernstein_hash(s.c_str(), s.size(), unicode_fold);
	} else {
	    return bernstein_hash(s.c_str(), s.size(), ascii_fold<typename
		T::value_type>);
	}
    } else if constexpr (requires { s.data(); s.size(); }) {
	if constexpr (is_same_v<typename T::value_type, wchar>) {
	    return bernstein_hash(s.data(), s.size(), unicode_fold);
	} else {
	    return bernstein_hash(s.data(), s.size(), ascii_fold<typename
		T::value_type>);
	}
    } else {
	using C = remove_pointer_t<remove_cv_t<T>>;
	if constexpr (is_same_v<C, wchar>) {
	    return bernstein_hash(s, unicode_fold);
	} else {
	    return bernstein_hash(s, ascii_fold<C>);
	}
    }
}

template<class C>
struct ptrhash {
    constexpr size_t operator ()(const C *p) const {
	if constexpr (sizeof (size_t) == 4 && sizeof (char *) == 8) {
	    uintptr_t addr = (uintptr_t)p;

	    return (size_t)((addr >> 32) ^ addr);
	} else {
	    return (size_t)p;
	}
    }
};

struct llonghash {
    constexpr size_t operator ()(llong l) const {
	if constexpr (sizeof (size_t) == 4)
	    return (size_t)((l >> 32) ^ l);
	else
	    return (size_t)l;
    }
};

struct ullonghash {
    constexpr size_t operator ()(ullong u) const {
	if constexpr (sizeof (size_t) == 4)
	    return (size_t)((u >> 32) ^ u);
	else
	    return (size_t)u;
    }
};

template <class C>
struct strhash {
    using is_transparent = void;
    template<typename T>
    size_t operator ()(const T &s) const { return stringhash(s); }
    template<size_t N>
    constexpr size_t operator ()(const char (&s)[N]) const {
	return bernstein_hash<char, N>(s);
    }
    template<size_t N>
    constexpr size_t operator ()(const wchar (&s)[N]) const {
	return bernstein_hash<wchar, N>(s);
    }
};

template <class C>
struct striasciihash {
    using is_transparent = void;
    template<typename T>
    size_t operator ()(const T &s) const { return stringiasciihash(s); }
    template<size_t N>
    constexpr size_t operator ()(const char (&s)[N]) const {
	return bernstein_hash<char, N>(s, ascii_fold<char>);
    }
    template<size_t N>
    constexpr size_t operator ()(const wchar (&s)[N]) const {
	return bernstein_hash<wchar, N>(s, ascii_fold<wchar>);
    }
};

template <class C>
struct strihash {
    using is_transparent = void;
    template<typename T>
    size_t operator ()(const T &s) const { return stringihash(s); }
    template<size_t N>
    constexpr size_t operator ()(const char (&s)[N]) const {
	return bernstein_hash<char, N>(s, ascii_fold<char>);
    }
    template<size_t N>
    constexpr size_t operator ()(const wchar (&s)[N]) const {
	return bernstein_hash<wchar, N>(s, unicode_fold);
    }
};

// prohibit object copies by subclassing this
class BLISTER nocopy {
public:
    nocopy(const nocopy &) = delete;
    nocopy(nocopy &&) = delete;
    nocopy & operator =(const nocopy &) = delete;
    nocopy & operator =(nocopy &&) = delete;

protected:
    nocopy() = default;
    ~nocopy() = default;
};

// fast single linked object list
template <class C>
class BLISTER ObjectList: nocopy {
public:
    struct BLISTER Node: nocopy {
	__forceinline Node(): next(nullptr) {}

	C *next;
    };

    class BLISTER const_iterator {
    public:
	__forceinline explicit const_iterator(const C *c): cur(c) {}
	__forceinline const C &operator *() const { return *cur; }
	__forceinline const C *operator ->() const { return cur; }
	__forceinline const_iterator &operator ++() {
	    cur = cur->next;
	    return *this;
	}
	__forceinline const_iterator operator ++(int) {
	    const_iterator tmp(*this);

	    cur = cur->next;
	    return tmp;
	}
	bool operator ==(const const_iterator &it) const = default;

    private:
	const C *cur;
    };

    ObjectList(): back(nullptr), front(nullptr) {}

    __forceinline bool operator !(void) const { return front == nullptr; }
    __forceinline explicit operator bool(void) const { return front != nullptr; }
    __forceinline const_iterator begin(void) const {
	return const_iterator(front);
    }
    __forceinline bool empty(void) const { return front == nullptr; }
    __forceinline const_iterator end(void) const {
	return const_iterator(nullptr);
    }
    __forceinline C *peek(void) const { return front; }

    void erase(void) { back = front = nullptr; }
    void free(void) {
	C *c = front;

	back = front = nullptr;
	while (c) {
	    C *next = c->next;

	    delete c;
	    c = next;
	}
    }
    bool pop(C &obj) {
	if (front == &obj) {
	    if ((front = (C *)obj.next) == nullptr)
		back = nullptr;
	    obj.next = nullptr;
	    return true;
	}
	for (C *p = front; LIKELY(p); p = (C *)p->next) {
	    if (UNLIKELY(p->next == &obj)) {
		if ((p->next = obj.next) == nullptr)
		    back = p;
		obj.next = nullptr;
		return true;
	    }
	}
	return false;
    }
    C *pop_back(void) {
	C *obj = back;

	if (UNLIKELY(!obj))
	    return nullptr;
	if (front == back) {
	    front = back = nullptr;
	} else {
	    C *p = front;

	    while (LIKELY(p->next != back))
		p = (C *)p->next;
	    back = p;
	    back->next = nullptr;
	}
	return obj;
    }
    __forceinline C *pop_front(void) {
	C *obj = front;

	if ((front = (C *)obj->next) == nullptr)
	    back = nullptr;
	else
	    obj->next = nullptr;
	return obj;
    }
    __forceinline void push_back(C &obj) {
	obj.next = nullptr;
	if (front) {
	    back->next = &obj;
	    back = &obj;
	} else {
	    back = front = &obj;
	}
    }
    void push_back(ObjectList &lst) {
	if (!lst.front)
	    return;
	if (back)
	    back->next = lst.front;
	else
	    front = lst.front;
	back = lst.back;
	lst.front = lst.back = nullptr;
    }
    __forceinline void push_front(C &obj) {
	if ((obj.next = front) == nullptr)
	    back = &obj;
	front = &obj;
    }
    void push_front(ObjectList &lst) {
	if (lst.back) {
	    if (front)
		lst.back->next = front;
	    else
		back = lst.back;
	    front = lst.front;
	    lst.front = lst.back = nullptr;
	}
    }

protected:
    C *back, *front;
};

// default non-atomic size-counter policy for SizedObjectList
struct ObjectListSize {
    __forceinline uint get(void) const { return n; }
    __forceinline void add(uint v) { n += v; }
    __forceinline void dec(void) { --n; }
    __forceinline void inc(void) { ++n; }
    __forceinline void zero(void) { n = 0; }

    uint n = 0;
};

// ObjectList with size counter
template <class C, class Size = ObjectListSize>
class BLISTER SizedObjectList: public ObjectList<C> {
public:
    using Base = ObjectList<C>;

    __forceinline uint size(void) const { return sz.get(); }

    void erase(void) { Base::erase(); sz.zero(); }
    void free(void) { Base::free(); sz.zero(); }
    __forceinline bool pop(C &obj) {
	bool removed = Base::pop(obj);

	if (LIKELY(removed))
	    sz.dec();
	return removed;
    }
    __forceinline C *pop_back(void) {
	C *obj = Base::pop_back();

	if (LIKELY(obj != nullptr))
	    sz.dec();
	return obj;
    }
    __forceinline C *pop_front(void) {
	C *obj = Base::pop_front();

	sz.dec();
	return obj;
    }
    __forceinline void push_back(C &obj) { Base::push_back(obj); sz.inc(); }
    __forceinline void push_front(C &obj) { Base::push_front(obj); sz.inc(); }
    void push_back(SizedObjectList &lst) {
	Base::push_back(static_cast<Base &>(lst));
	sz.add(lst.size());
	lst.sz.zero();
    }
    void push_front(SizedObjectList &lst) {
	Base::push_front(static_cast<Base &>(lst));
	sz.add(lst.size());
	lst.sz.zero();
    }

protected:
    Size sz;
};

template <class C>
struct BLISTER ObjectListNode: ObjectList<ObjectListNode<C>>::Node {
    __forceinline explicit ObjectListNode(const C &c): val(c) {}

    C val;
};

#endif

#endif // stdapi_h
