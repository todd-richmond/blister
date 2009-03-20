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

#ifndef stdapi_h
#define stdapi_h

// defines and code to make non-UNIX systems support POSIX APIs

#ifdef __cplusplus
#define EXTERNC extern "C" {
#define EXTERNC_ }
#else
#define EXTERNC
#define EXTERNC_
#endif

#define ZERO(x)	    memset((&x), 0, sizeof (x))

typedef const char cchar;
typedef unsigned char byte;
typedef unsigned char uchar;
typedef unsigned short word;
typedef unsigned long dword;

#ifdef _WIN32

#pragma warning(disable: 4018)
#pragma warning(disable: 4097)
#pragma warning(disable: 4100)
#pragma warning(disable: 4103)
#pragma warning(disable: 4127)
#pragma warning(disable: 4146)
#pragma warning(disable: 4201)
#pragma warning(disable: 4355)
#pragma warning(disable: 4503)
#pragma warning(disable: 4511)
#pragma warning(disable: 4512)
#pragma warning(disable: 4530)
#pragma warning(disable: 4663)
#pragma warning(disable: 4710)
#pragma warning(disable: 4711)
#pragma warning(disable: 4786)
#pragma warning(disable: 4996)

#ifndef WIN32
#define WIN32
#endif
#define NOSERVICE
#define NOMCX
#define NOIME
#define WIN32_LEAN_AND_MEAN

#define rename _rename
#define __STDC__ 1
#ifndef _WIN32_WCE
#include <direct.h>
#include <io.h>
#endif
#include <stdio.h>
#undef __STDC__
#include <stdlib.h>
#include <string.h>
#define _INO_T_DEFINED
#define _STAT_DEFINED
#define _WSTAT_DEFINED
#include <wchar.h>
#undef _INO_T_DEFINED
#undef _STAT_DEFINED
#undef _WSTAT_DEFINED

#ifdef _WIN32_WCE
#include <winsock.h>
#else
#include <winsock2.h>
#endif

#undef rename

#ifdef _WIN32_WCE
#define EINVAL		1
#define ENOENT		2
#define EMFILE		3
#define EACCES		4
#define EBADF		5
#define ENOTDIR		6
#define ENOMEM		7
#define E2BIG		8
#define EXDEV		9
#define EEXIST		10
#define EAGAIN		11
#define EPIPE		12
#define ENOSPC		13
#define ECHILD		14
#define ENOTEMPTY	15
#define ENOEXEC		16

#define O_RDONLY	0x0000
#define O_WRONLY	0x0001
#define O_RDWR		0x0002
#define O_APPEND	0x0008
#define O_CREAT		0x0100
#define O_TRUNC		0x0200
#define O_EXCL		0x0400
#define O_TEXT		0x4000
#define O_BINARY	0x8000
#define O_NOINHERIT	0
#define O_RANDOM	0
#define O_SEQUENTIAL	0
#define _O_SHORT_LIVED	0
#define O_TEMPORARY	0
#define S_IFMT          0170000
#define S_IFDIR         0040000
#define S_IFCHR         0020000
#define S_IFIFO         0010000
#define S_IFREG         0100000
#define S_IREAD         0000400
#define S_IWRITE        0000200
#define S_IEXEC         0000100

#define _fmode		O_BINARY

#define SetProcessAffinityMask(h, m) 1
#define stricmp		_stricmp
#define strnicmp	_strnicmp
#define wcsicmp		_wcsicmp
#define wcsnicmp	_wcsnicmp

EXTERNC
extern int __cdecl _stricmp(const char *, const char *);
extern int __cdecl _strnicmp(const char *, const char *, size_t);
extern int __cdecl _wcsicmp(const wchar *, const wchar *);
extern int __cdecl _wcsnicmp(const wchar *, const wchar *, size_t);
EXTERNC_

#else
#define ino_t		__ino_t
#define fstat		__fstat
#define stat		__sstat
#include <sys/stat.h>
#undef ino_t
#undef fstat
#undef stat
#endif

#ifndef __cplusplus
#define inline		__inline
#endif

#define MAXCHAR		0x7f
#define MAXUCHAR	0xff
#define MAXSHORT	0x7fff
#define MAXUSHORT	0xffff
#ifndef MAXINT
#define MAXINT		0x7fffffff
#define MAXUINT		0xffffffff
#endif
#define MAXLONG		0x7fffffff
#define MAXULONG	0xffffffff
#define MAXBYTE		0xff
#define MAXWORD		0xffff
#define MAXDWORD	0xffffffff

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

#define O_SHORT_LIVED	_O_SHORT_LIVED
#define O_COMPRESSED	0x010000
#define O_POSIX		0x020000
#define O_SYNC		0x040000
#define O_NOBUFFERING	0x080000
#define O_OVERLAPPED	0x100000
#define O_BACKUP	0x200000
#define O_NONBLOCK	0x400000
#define O_DSYNC		O_SYNC

#define SIGHUP		SIGBREAK
#define SIGCHLD		80	/* out of range */
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

#define bcopy(a, b, c)  memmove(b, a, c)
#define bzero(a, b)	memset(a, 0, b)
#define chown(path, owner, group)   0
#define fchown(fd, owner, group)    0
#define lchown(path, owner, group)  0
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
#define strcasecmp	stricmp
#define strncasecmp	strnicmp
#define snprintf	_snprintf
#define getcwd		_getcwd
#define wgetcwd		_wgetcwd
#define wgetenv		_wgetenv
#define waitpid(pid, status, opt)	cwait(status, pid, opt)

#define sleep(x)	Sleep(x * 1000)
#define usleep(x)	Sleep(x / 1000)

typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef __int64 int64;
typedef unsigned __int64 uint64;
typedef wchar_t wchar;

typedef ushort gid_t;
typedef int id_t;
typedef int64 ino_t;
typedef long pid_t;
typedef ushort uid_t;

typedef enum idtype {
    P_PID, P_PPID, P_PGID, P_SID, P_CID, P_UID, P_GID, P_ALL
} idtype_t;

/* local MSVC routines we need in overridden versions */
#if defined(_DLL) || defined(_WIN32_WCE)
#define _dosmaperr  __dosmaperr
#endif
extern void _dosmaperr(ulong oserrno);

/*
 * replacement CLib calls support automic rename, deleting open files
 * and using sockets as fds
 */
#define fileno(stream)	(_get_osfhandle((stream)->_file))

/* UNIX directory emulation */
typedef struct dirent {
    char *d_ino;
    long d_off;
    char *d_name;
} dirent;

typedef struct DIR {
    void *hdl;
    dirent  dir;
#ifdef _WIN32_WCE
    char pbuf[260];
    struct _WIN32_FIND_DATAW *wfd;
#else
    struct _WIN32_FIND_DATAA *wfd;
#endif
    char path[1];
} DIR;

#define telldir(p)	(p->dir.d_off)
#define rewinddir(dirp)	seekdir(dirp, 0L)

/* stat routines that support inodes and devices properly */
struct stat {
    ulong st_dev;
    ulong st_rdev;
    ulong st_nlink;
    ulong st_size;
    ino_t st_ino;
    ulong st_atime;
    ulong st_mtime;
    ulong st_ctime;
    ushort st_mode;
    ushort st_uid;
    ushort st_gid;
};

/* statvfs emulation */
#define FSTYPSZ 16

typedef struct statvfs {
    ulong f_bsize;			/* preferred file system block size */
    ulong f_frsize;			/* fundamental file system block size */
    ulong f_blocks;			/* total # of blocks of f_frsize on fs */
    ulong f_bfree;			/* total # of free blocks of f_frsize */
    ulong f_bavail;			/* # of free blocks avail to non-superuser */
    ulong f_files;			/* total # of file nodes (inodes) */
    ulong f_ffree;			/* total # of free file nodes */
    ulong f_favail;			/* # of free nodes avail to non-superuser */
    ulong f_fsid;			/* file system id (dev for now) */
    char f_basetype[FSTYPSZ];		/* target fs type name, null-terminated */
    ulong f_flag;			/* bit-mask of flags */
    ulong f_namemax;			/* maximum file name length */
} statvfs_t;

/* writev emulation */
typedef struct iovec {
    size_t iov_len;
    char *iov_base;
} iovec_t;

struct timezone {
    int tz_minuteswest;
    int tz_dsttime;
};

EXTERNC
extern int access(const char *, int);
extern int chmod(const char *, int);
extern int chsize(int, long);
extern int close(int);
extern int creat(const char *, int);
extern int dup(int);
extern int dup2(int, int);
extern int eof(int);
extern long filelength(int);
extern int flock(int, int);
extern int gettimeofday(struct timeval *tv, struct timezone *tz);
extern int isatty(int);
extern int lockf(int fd, int op, long len);
extern int locking(int, int, long);
extern long lseek(int, long, int);
extern char *mktemp(char *);
extern int open(const char *, int, ...);
extern int read(int, void *, unsigned int);
extern int rename(const char *, const char *);
extern int setmode(int, int);
extern int sopen(const char *, int, int, ...);
extern long tell(int);
extern int umask(int);
extern int unlink(const char *);
extern int write(int, const void *, unsigned int);
extern int fsync(int fd);
extern int ftruncate(int fd, long len);
extern int link(const char *, const char *);
extern int fstat(int fd, struct stat *);
extern int sigsend(idtype_t idtype, id_t id, int sig);
extern int stat(const char *, struct stat *);
extern int statvfs(const char *path, struct statvfs *buf);
extern long readv(int fd, struct iovec *vec, int numvec);
extern long writev(int fd, const struct iovec *vec, int numvec);
extern void closedir(DIR *);
extern DIR *opendir(const char *);
extern dirent *readdir(DIR *);
extern void seekdir(DIR *, long);
EXTERNC_

#define asctime_r(tm, buf, len)	((void)(buf, len), asctime(tm))
#define ctime_r(clock, buf)	((void)(buf), ctime(clock))
#define gmtime_r(clock, buf)	((void)(buf), gmtime(clock))
#define localtime_r(clock, buf)	((void)(buf), localtime(clock))

#else // _WIN32

#ifndef _POSIX_PTHREAD_SEMANTICS
#define _POSIX_PTHREAD_SEMANTICS
#endif
#ifndef _REENTRANT
#define _REENTRANT
#endif

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <sys/time.h>
#include <sys/uio.h>

#define __declspec(x)
#define __cdecl
#define __fastcall
#define __stdcall

#ifndef O_BINARY
#define O_BINARY	0
#endif
#define O_COMPRESSED	0
#define O_NOBUFFERING	0
#define O_SEQUENTIAL	0
#define O_SHORT_LIVED	0

#define stricmp		strcasecmp
#define strnicmp	strncasecmp
#define wcsicmp		wcscasecmp

typedef long long int64;
typedef unsigned long long uint64;
typedef wchar_t wchar;

#ifdef __APPLE__
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

extern int wcscasecmp(const wchar *, const wchar *);
#endif

#endif // _WIN32

#if defined(_WIN32) || defined(__APPLE__)
#define gethostbyname_r(host, buf, a, b, c) \
	((void)buf, (void)a, (void)b, (void)c, gethostbyname(host))
#define gethostbyaddr_r(addr, len, type, buf, a, b, c)	\
	((void)(void)buf, (void)a, (void)b, (void)c, gethostbyaddr(addr, len, type))
#define getservbyname_r(serv, proto, buf, a, b) \
	((void)buf, (void)a, (void)b, getservbyname(serv, proto))
#define getservbyport_r(port, proto, buf, a, b) \
	((void)buf, (void)a, (void)b, getservbyport(port, proto))
#endif

#ifdef _UNICODE
#define UNICODE

#define T(str)	    L##str

#define tstring	    wstring
#define tstrcmp	    wcscmp
#define tstricmp    wcsicmp
#define tstrncmp    wcsncmp
#define tstrnicmp   wcsnicmp
#define tstrcat	    wcscat
#define tstrncat    wcsncat
#define tstrcpy	    wcscpy
#define tstrncpy    wcsncpy
#define tstrlen	    wcslen
#define	tstrchr	    wcschr
#define tstrrchr    wcsrchr
#define tstrspn	    wcsspn
#define tstrcspn    wcscspn
#define tstrpbrk    wcspbrk
#define tstrstr	    wcsstr
#define tstrtok	    wcstok
#define tstrdup	    wcsdup
#define ttof	    wtof
#define ttoi	    wtoi
#define ttol	    wtol
#define tstrtod     wcstod
#define tstrtol	    wcstol
#define tstrtoul    wcstoul
#define tstrftime   wcsftime
#define tgetcwd	    wgetcwd
#define tgetenv	    wgetenv
#define istalnum    iswalnum
#define istalpha    iswalpha
#define istdigit    iswdigit
#define istgraph    iswgraph
#define istlower    iswlower
#define istprint    iswprint
#define istpunct    iswpunct
#define istspace    iswspace
#define istupper    iswupper
#define totupper    towupper
#define totlower    towlower
#define tmain	    wmain
#define tcerr	    wcerr
#define tcin	    wcin
#define tcout	    wcout

#define tfprintf    fwprintf
#define tprintf     fwprintf
#define tsprintf    swprintf
#define tvfprintf   vfwprintf
#define tvprintf    vfwprintf
#define tvsprintf   vswprintf
#define tfscanf     fwscanf
#define tscanf      wscanf
#define tsscanf     swscanf

#define tstreambuf  wstreambuf
#define tistream    wistream
#define tostream    wostream
#define tiostream   wiostream
#define tfstream    wfstream
#define tifstream   wifstream
#define tofstream   wofstream
#define tstringstream	wstringstream
#define tistringstream  wistringstream
#define tostringstream  wostringstream
#define tstrstream	wstrstream
#define tistrstream	wistrstream
#define tostrstream	wostrstream

#define atotstring(s)	atowide(s)
#define wtotstring(s)	string(s)
#define tchartoa(s)	widetoa(s)
#define tchartow(s)	wstring(s)
#define tstringtoa(s)	widetoa((s).c_str())
#define tstringtow(s)	(s)

typedef wchar tchar;

#else	// UNICODE
#define T(str)	    str

#define tstring	    string
#define tstrcmp	    strcmp
#define tstricmp    stricmp
#define tstrncmp    strncmp
#define tstrnicmp   strnicmp
#define tstrcat	    strcat
#define tstrncat    strncat
#define tstrcpy	    strcpy
#define tstrncpy    strncpy
#define tstrlen	    strlen
#define	tstrchr	    strchr
#define tstrrchr    strrchr
#define tstrspn	    strspn
#define tstrcspn    strcspn
#define tstrpbrk    strpbrk
#define tstrstr	    strstr
#define tstrtok	    strtok
#define tstrdup	    strdup
#define ttof	    atof
#define ttoi	    atoi
#define ttol	    atol
#define tstrtod	    strtod
#define tstrtol	    strtol
#define tstrtoul    strtoul
#define tstrftime   strftime
#define tgetcwd	    getcwd
#define tgetenv	    getenv
#define istalnum    isalnum
#define istalpha    isalpha
#define istdigit    isdigit
#define istgraph    isgraph
#define istlower    islower
#define istprint    isprint
#define istpunct    ispunct
#define istspace    isspace
#define istupper    isupper
#define totupper    toupper
#define totlower    tolower
#define tmain	    main
#define tcerr	    cerr
#define tcin	    cin
#define tcout	    cout

#define tstreambuf  streambuf
#define tistream    istream
#define tostream    ostream
#define tiostream   iostream
#define tfstream    fstream
#define tifstream   ifstream
#define tofstream   ofstream
#define tstringstream	stringstream
#define tistringstream  istringstream
#define tostringstream  ostringstream
#define tstrstream	strstream
#define tistrstream	istrstream
#define tostrstream	ostrstream

#define tfprintf    fprintf
#define tprintf     fprintf
#define tsprintf    sprintf
#define tvfprintf   vfprintf
#define tvprintf    vfprintf
#define tvsprintf   vsprintf
#define tfscanf     fscanf
#define tscanf      scanf
#define tsscanf     sscanf

#define atotstring(s)	string(s)
#define wtotstring(s)	widetoa(s)
#define tchartoa(s)	string(s)
#define tchartow(s)	atowide((s).c_str())
#define tstringtoa(s)	(s)
#define tstringtow(s)	atowide((s).c_str())

typedef char tchar;
#endif // UNICODE

typedef const tchar ctchar;
typedef uint64 msec_t;
typedef uint64 usec_t;

// common includes, defines and code for C/C++ software
static inline usec_t microtime(void) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (usec_t)tv.tv_sec * (usec_t)1000000 + tv.tv_usec;
}

EXTERNC
extern msec_t mticks(void);
extern usec_t uticks(void);
extern int lockfile(int fd, short type, short whence, ulong start, ulong len,
    short test);
EXTERNC_

#define millitime() ((msec_t)(microtime() / 1000))

#ifdef __cplusplus

#include <iostream>
#include <string>
#include <vector>
#include <functional>

#ifndef _WIN32_WCE
using namespace std;
#if _MSC_VER >= 1500
using namespace stdext;
#endif
#endif
#if defined(__GNUC__)
#if __GNUC__ >= 3
using namespace __gnu_cxx;
#endif
#define STL_HASH_MAP	<ext/hash_map>
#define STL_HASH_SET    <ext/hash_set>	
#define STL_HASH_MAP_4ARGS
#define STL_HASH_PARMS
#else
#define STL_HASH_MAP	<hash_map>
#define STL_HASH_SET    <hash_set>	
#define STL_HASH_PARMS	enum { bucket_size = 4, min_buckets = 8 };
#endif

// structs useful for hash maps
template<class C>
struct ptrhash {
    size_t operator ()(const C *a) const { return (size_t)a; }
    bool operator ()(const C *a, const C *b) const { return a == b; }
    STL_HASH_PARMS
};

struct int64hash {
    size_t operator ()(int64 a) const { return (size_t)((a >> 32) ^ a); }
    bool operator ()(int64 a, int64 b) const { return a == b; }
    STL_HASH_PARMS
};

struct uint64hash {
    size_t operator ()(uint64 u) const { return (size_t)((u >> 32) ^ u); }
    bool operator ()(uint64 a, uint64 b) const { return a == b; }
    STL_HASH_PARMS
};

// Derive from this to prohibit copying
class nocopy {
protected:
    nocopy() {}

private:
    nocopy(const nocopy &);
    const nocopy& operator =(const nocopy &);
};

inline int to_lower(int c) { return _tolower((uchar)(c)); }
inline int to_upper(int c) { return _toupper((uchar)(c)); }

inline int stringcmp(const char *a, const char *b) {
    return strcmp(a, b);
}

inline int stringcmp(const wchar *a, const wchar *b) {
    return wcscmp(a, b);
}

inline int stringicmp(const char *a, const char *b) {
    return stricmp(a, b);
}

inline int stringicmp(const wchar *a, const wchar *b) {
    return wcsicmp(a, b);
}

template<class C>
inline size_t stringhash(const C *s) {
    size_t ret = 0;

    while (*s)
	ret += (ret << 3) + *s++;
    return ret;
}

inline size_t stringihash(const char *s) {
    size_t ret = 0;

    while (*s)
	ret += (ret << 3) + to_upper(*s++);
    return ret;
}

inline size_t stringihash(const wchar *s) {
    size_t ret = 0;

    while (*s)
	ret += (ret << 3) + towupper(*s++);
    return ret;
}

template <class C>
struct strhash {
    size_t operator ()(const C *s) const { return stringhash(s); }
    size_t operator ()(const basic_string<C> &s) const {
	return stringhash(s.c_str());
    }
    bool operator ()(const C *a, const C *b) const {
	return stringcmp(a, b) < 0;
    }
    bool operator ()(const basic_string<C> &a, const basic_string<C> &b) const {
	return stringcmp(a.c_str(), b.c_str()) < 0;
    }
    STL_HASH_PARMS
};

template <class C>
struct strihash {
    size_t operator ()(const C *s) const { return stringihash(s); }
    size_t operator ()(const basic_string<C> &s) const {
	return stringihash(s.c_str());
    }
    bool operator ()(const C *a, const C *b) const {
	return stringicmp(a, b) < 0;
    }
    bool operator ()(const basic_string<C> &a, const basic_string<C> &b) const {
	return stringicmp(a.c_str(), b.c_str()) < 0;
    }
    STL_HASH_PARMS
};

template<class C>
struct strhasheq {
    bool operator()(const C *a, const C *b) const {
	return stringcmp(a, b) == 0;
    }
    bool operator()(const basic_string<C> &a, const basic_string<C> &b) const {
	return stringcmp(a.c_str(), b.c_str()) == 0;
    }
};

template<class C>
struct strihasheq {
    bool operator()(const C *a, const C *b) const {
	return stringicmp(a, b) == 0;
    }
    bool operator()(const basic_string<C> &a, const basic_string<C> &b) const {
	return stringicmp(a.c_str(), b.c_str()) == 0;
    }
};

template <class C>
struct strless {
    bool operator ()(const C *a, const C *b) const {
	return stringcmp(a, b) < 0;
    }
    bool operator ()(const basic_string<C> &a, const basic_string<C> &b) const {
	return stringcmp(a.c_str(), b.c_str()) < 0;
    }
    static bool less(const C *a, const C *b) { return stringcmp(a, b) < 0; }
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
};

#ifdef _WIN32
inline const string widetoa(const wchar *s) {
    int len = WideCharToMultiByte(CP_ACP, 0, s, -1,
	NULL, NULL, NULL, NULL);
    char sbuf[256];
    char *buf = sbuf;
    string ret;

    if (len > sizeof (sbuf))
	buf = new char[len];
    WideCharToMultiByte(CP_ACP, 0, s, -1, buf, len, NULL, NULL);
    ret = buf;
    if (len > sizeof (sbuf))
	delete [] buf;
    return ret;
}

inline const wstring atowide(const char *s) {
    int len = MultiByteToWideChar(CP_ACP, 0, s, -1, NULL, NULL);
    wchar sbuf[128];
    wchar *buf = sbuf;
    wstring ret;

    if (len > sizeof (sbuf) / sizeof (wchar))
	buf = new wchar[len];
    MultiByteToWideChar(CP_ACP, 0, s, -1, buf, len);
    ret = buf;
    if (len > sizeof (sbuf))
	delete [] buf;
    return ret;
}
#endif

#endif

#endif /* stdapi_h */
