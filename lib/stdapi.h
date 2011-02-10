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
#include <direct.h>
#include <io.h>
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

#include <winsock2.h>

#undef rename

#define fstat		__fstat
#define ino_t		__ino_t
#define stat		__sstat
#include <sys/stat.h>
#undef fstat
#undef ino_t
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
#define wcserror	_wcserror
#define wtof		_wtof
#define wtoi		_wtoi
#define wtol		_wtol

#define getcwd		_getcwd
#define wgetcwd		_wgetcwd
#define wgetenv		_wgetenv
#define	wexecvp		_wexecvp
#define waitpid(pid, status, opt)	cwait(status, pid, opt)

#define sleep(x)	Sleep(x * 1000)
#define usleep(x)	Sleep(x / 1000)

typedef __int64 llong;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
typedef unsigned __int64 ullong;
typedef wchar_t wchar;

typedef ushort gid_t;
typedef int id_t;
typedef llong ino_t;
typedef long pid_t;
typedef ushort uid_t;

typedef enum idtype {
    P_PID, P_PPID, P_PGID, P_SID, P_CID, P_UID, P_GID, P_ALL
} idtype_t;

/* local MSVC routines we need in overridden versions */
#ifdef _DLL
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
    struct _WIN32_FIND_DATAA *wfd;
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

#ifndef ENOSR
#define ENOSR		ENOBUFS
#endif

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

typedef long long llong;
typedef unsigned long long ullong;
typedef wchar_t wchar;

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;
#endif

#if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__sun__)
extern int wcscasecmp(const wchar *, const wchar *);
#endif

#endif // _WIN32

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

typedef char int8;
typedef uchar uint8;
typedef short int16;
typedef ushort uint16;
typedef long int32;
typedef ulong uint32;
typedef llong int64;
typedef ullong uint64;

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
#define tstrncat	wcsncat
#define tstrcpy		wcscpy
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
#define tstrncat	strncat
#define tstrcpy		strcpy
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
#define istalnum	isalnum
#define istalpha	isalpha
#define istblank	isblank
#define istcntrl	iscntrl
#define istdigit	isdigit
#define istgraph	isgraph
#define istlower	islower
#define istprint	isprint
#define istpunct	ispunct
#define istspace	isspace
#define istupper	isupper
#define istxdigit	isxdigit
#define totupper	toupper
#define totlower	tolower
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

typedef char tchar;
typedef uchar tuchar;
#endif // UNICODE

typedef const tchar ctchar;
typedef uint64 msec_t;
typedef uint64 usec_t;

// common includes, defines and code for C/C++ software
inline usec_t microtime(void) {
    struct timeval tv;

    gettimeofday(&tv, NULL);
    return (usec_t)tv.tv_sec * (usec_t)1000000 + tv.tv_usec;
}

EXTERNC
extern usec_t microticks(void);
extern int lockfile(int fd, short type, short whence, ulong start, ulong len,
    short test);
EXTERNC_

#define millitime()	((msec_t)(microtime() / 1000))
#define milliticks()	((msec_t)(microticks() / 1000))

#ifdef __cplusplus

#include <functional>
#include <iostream>
#include <string>
#include <vector>

using namespace std;
#if _MSC_VER >= 1500 && _MSC_VER < 1600
using namespace stdext;
#endif

extern const wstring _achartowstring(const char *s, int len);
extern const string _wchartoastring(const wchar *s, int len);

inline const wstring astringtowstring(const string &s) {
    return _achartowstring(s.c_str(), (int)s.size() + 1);
}

inline const string wstringtoastring(const wstring &s) {
    return _wchartoastring(s.c_str(), (int)s.size() + 1);
}

#define achartowchar(s)	    achartowstring(s).c_str()
#define achartowstring(s)   _achartowstring((s), -1)
#define astringtoachar(s)   (s).c_str()
#define astringtowchar(s)   astringtowstring(s).c_str()
#define wchartoachar(s)	    wchartoastring(s).c_str()
#define wchartoastring(s)   _wchartoastring((s), -1)
#define wstringtoachar(s)   wstringtoastring(s).c_str()
#define wstringtowchar(s)   (s).c_str()

#ifdef UNICODE
#define achartotchar(s)	    achartowchar(s)
#define achartotstring(s)   achartowstring(s)
#define astringtotchar(s)   astringtowchar(s)
#define astringtotstring(s) astringtowstring(s)
#define tchartoachar(s)	    wchartoachar(s)
#define tchartowchar(s)	    (s)
#define tchartotstring(s)   wstring(s)
#define tstringtoachar(s)   wstringtoachar(s)
#define tstringtoastring(s) wstringtoastring(s)
#define tstringtowchar(s)   wstringtowchar(s)
#define tstringtowstring(s) (s)
#define wchartotchar(s)	    wchartowchar(s)
#define wchartotstring(s)   wchartowstring(s)
#define wstringtotchar(s)   wstringtowchar(s)
#define wstringtotstring(s) wstringtowstring(s)

#define tcerr		    wcerr
#define tcin		    wcin
#define tcout		    wcout
#define tstreambuf	    wstreambuf
#define tistream	    wistream
#define tostream	    wostream
#define tiostream	    wiostream
#define tfstream	    wfstream
#define tifstream	    wifstream
#define tofstream	    wofstream
#define tstringstream	    wstringstream
#define tistringstream	    wistringstream
#define tostringstream	    wostringstream
#define tstrstream	    wstrstream
#define tistrstream	    wistrstream
#define tostrstream	    wostrstream
#define tstringbuf	    wstringbuf

#else

#define achartotchar(s)	    (s)
#define achartotstring(s)   string(s)
#define astringtotchar(s)   astringtoachar(s)
#define astringtotstring(s) (s)
#define tchartoachar(s)	    (s)
#define tchartowchar(s)	    achartowchar(s)
#define tchartotstring(s)   string(s)
#define tstringtoachar(s)   astringtoachar(s)
#define tstringtoastring(s) (s)
#define tstringtowchar(s)   astringtowchar(s)
#define tstringtowstring(s) astringtowstring(s)
#define wchartotchar(s)	    wchartoachar(s)
#define wchartotstring(s)   wchartoastring(s)
#define wstringtotchar(s)   wstringtoachar(s)
#define wstringtotstring(s) wstringtoastring(s)

#define tcerr		    cerr
#define tcin		    cin
#define tcout		    cout
#define tstreambuf	    streambuf
#define tistream	    istream
#define tostream	    ostream
#define tiostream	    iostream
#define tfstream	    fstream
#define tifstream	    ifstream
#define tofstream	    ofstream
#define tstringstream	    stringstream
#define tistringstream	    istringstream
#define tostringstream	    ostringstream
#define tstrstream	    strstream
#define tistrstream	    istrstream
#define tostrstream	    ostrstream
#define tstringbuf	    stringbuf
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
#define STL_HASH_MAP	    <hash_map>
#define STL_HASH_SET	    <hash_set>	
#define STL_HASH_PARMS	    enum { bucket_size = 4, min_buckets = 8 };
#endif

// structs useful for hash maps
template<class C>
struct ptrhash {
    size_t operator ()(const C *a) const { return (size_t)a; }
    bool operator ()(const C *a, const C *b) const { return a == b; }
    STL_HASH_PARMS
};

struct llonghash {
    size_t operator ()(llong a) const { return (size_t)((a >> 32) ^ a); }
    bool operator ()(llong a, llong b) const { return a == b; }
    STL_HASH_PARMS
};

struct ullonghash {
    size_t operator ()(ullong u) const { return (size_t)((u >> 32) ^ u); }
    bool operator ()(ullong a, ullong b) const { return a == b; }
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

#endif

#endif /* stdapi_h */
