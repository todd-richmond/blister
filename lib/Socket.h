/*
 * Copyright 2001-2019 Todd Richmond
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

#ifndef Socket_h
#define Socket_h

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable: 4365 6386)
#include <winsock2.h>
#include <ws2tcpip.h>
#pragma warning(pop)
#pragma warning(disable: 4097)

#define SSET_FD(i)	fds->fd_array[i]
#define SOCK_SIZE_T	int
#define s6_addr16	u.Word
#define s6_addr32	u.Dword

typedef ushort sa_family_t;
typedef int socklen_t;
typedef SOCKET socket_t;

inline int sockerrno(void) { return WSAGetLastError(); }

#else
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/un.h>

#define ioctlsocket	ioctl
#define INVALID_SOCKET	-1
#define SSET_FD(i)	fds[i].fd
#define SOCK_SIZE_T	size_t
#define WSAEALREADY	EALREADY
#define WSAEINPROGRESS	EINPROGRESS
#define WSAEINTR	EINTR
#define WSAEWOULDBLOCK	EWOULDBLOCK

#ifdef BSD_BASE
#define s6_addr16	__u6_addr.__u6_addr16
#define s6_addr32	__u6_addr.__u6_addr32
#endif

typedef int socket_t;

inline int closesocket(socket_t fd) { return ::close(fd); }
inline int sockerrno(void) { return errno; }
#endif

#include <vector>
#include "Streams.h"

const int SOCK_BACKLOG = 128;
const int SOCK_BUFSZ = 3 * 1024;
const uint SOCK_INFINITE = (uint)-1;
const socket_t SOCK_INVALID = INVALID_SOCKET;

inline bool blocked(int e) {
#ifdef _WIN32
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY;
#elif EAGAIN == EWOULDBLOCK
    return e == EAGAIN || e == ENOBUFS || e == ENOSR || e == EINPROGRESS ||
	e == EALREADY;
#else
    return e == EWOULDBLOCK || e == EAGAIN || e == ENOBUFS ||
	e == ENOSR || e == EINPROGRESS || e == EALREADY;
#endif
}

inline bool interrupted(int e) { return e == WSAEINTR; }

/*
 * Socket address class to wrap sockaddr structures and deal with Win32 startup
 * requirements. Limited to IPV4/6 TCP or UDP addresses and UNIX domain paths
 */
WARN_PUSH_DISABLE(26495)
class BLISTER Sockaddr {
public:
    enum Proto { TCP, UDP, TCP4, UDP4, TCP6, UDP6, UNIX, UNSPEC };

    Sockaddr(const Sockaddr &sa): addr(sa.addr), name(sa.name) {}
    explicit Sockaddr(const addrinfo *ai) { set(ai); }
    explicit Sockaddr(const hostent *h) { set(h); }
    explicit Sockaddr(Proto proto = TCP) {
	ZERO(addr);
	family(proto);
    }
    explicit Sockaddr(const sockaddr &sa) { set(sa); }
    explicit Sockaddr(const tchar *host, Proto proto = TCP) {
	set(host, proto);
    }
    // cppcheck-suppress syntaxError
    Sockaddr(const tchar *host, ushort port, Proto proto = TCP) {
	set(host, port, proto);
    }
    Sockaddr(const tchar *host, const tchar *service, Proto proto = TCP) {
	set(host, service, proto);
    }

    bool operator ==(const Sockaddr &sa) const {
	return !memcmp(&addr, &sa.addr, size());
    }
    bool operator !=(const Sockaddr &sa) const { return !operator ==(sa); }
    Sockaddr &operator =(const Sockaddr &sa) {
	if (this != &sa) {
	    addr = sa.addr;
	    name = sa.name;
	}
	return *this;
    }
    operator const in_addr *() const { return &addr.sa4.sin_addr; }
    operator const in6_addr *() const { return &addr.sa6.sin6_addr; }
    operator const sockaddr *() const { return &addr.sa; }
    operator const sockaddr_in *() const { return &addr.sa4; }
    operator const sockaddr_in6 *() const { return &addr.sa6; }
    operator const sockaddr_un *() const { return &addr.sau; }

    const void *address(void) const;
    void clear(void) { ZERO(addr); name.clear(); }
    sockaddr *data(void) { name.clear(); return &addr.sa; }
    ushort family(void) const { return addr.sa.sa_family; }
    void family(sa_family_t fam) { addr.sa.sa_family = fam; }
    void family(Proto proto) { addr.sa.sa_family = families[(uint)proto]; }
    const tstring &host(void) const;
    bool host(const tchar *host, Proto proto = TCP) {
	return port() ? set(host, port(), proto) : set(host, proto);
    }
    const tstring ip(void) const;
    const tstring ipstr(void) const { return str(ip()); }
    bool ipv4(void) const { return family() == AF_INET; }
    bool ipv6(void) const { return family() == AF_INET6; }
#ifndef _WIN32
    const char *path(void) const {
	return family() == AF_UNIX ? *addr.sau.sun_path == '\0' ?
	    addr.sau.sun_path + 1 : addr.sau.sun_path : NULL;
    }
#endif
    ushort port(void) const;
    void port(ushort port);
    Proto proto(void) const;
    bool service(const tchar *service, Proto proto = TCP);
    bool set(const addrinfo *h);
    bool set(const tchar *host, Proto proto = TCP);
    bool set(const tchar *host, ushort port, Proto proto = TCP);
    bool set(const tchar *host, const tchar *service, Proto proto = TCP);
    bool set(const hostent *h);
    bool set(const sockaddr &sa);
    ushort size(void) const { return size(family()); }
    const tstring str(void) const { return str(host()); }
    bool v4mapped(void) const {
	const in6_addr &sa6 = addr.sa6.sin6_addr;

	return ipv6() && sa6.s6_addr16[0] == 0 && sa6.s6_addr16[1] == 0 &&
	    sa6.s6_addr16[2] == 0 && sa6.s6_addr16[3] == 0 &&
	    sa6.s6_addr16[4] == 0 && sa6.s6_addr16[5] == 0xFFFF;
    }

    static bool dgram(Proto proto) {
	return proto == UDP || proto == UDP4 || proto == UDP6;
    }
    static addrinfo *getaddrinfo(const tchar *host, const tchar *service, Proto
	proto = TCP);
    static const tstring &hostname(void);
    static const tstring service_name(ushort port, Proto proto = TCP);
    static ushort service_port(const tchar *service, Proto proto = TCP);
    static ushort size(ushort family);
    static bool stream(Proto proto) {
	return proto == TCP || proto == TCP4 || proto == TCP6 || proto == UNIX;
    }

private:
    typedef union {
	sockaddr sa;
	sockaddr_in sa4;
	sockaddr_in6 sa6;
#ifndef _WIN32
	sockaddr_un sau;
#endif
    } sockaddr_any;

#ifdef _WIN32
    class BLISTER SockInit {
    public:
	SockInit() { WSADATA w; (void)WSAStartup(2 | (0 << 8), &w); }
	~SockInit() { WSACleanup(); }
    };

    static SockInit init;
#endif

    sockaddr_any addr;
    mutable tstring name;
    static sa_family_t families[];

    const tstring str(const tstring &val) const;
};
WARN_POP

inline tostream &operator <<(tostream &os, const Sockaddr &addr) {
    return os << addr.str();
}

// Socket address list for hosts that resolve to multiple results
class BLISTER SockaddrList: public ObjectList<ObjectListNode<Sockaddr> > {
public:
    SockaddrList() {}
    SockaddrList(const tchar *host, ushort port, Sockaddr::Proto proto =
	Sockaddr::TCP) { insert(host, port, proto); }
    SockaddrList(const tchar *host, const tchar *service = NULL,
	Sockaddr::Proto proto = Sockaddr::TCP) { insert(host, service, proto); }
    ~SockaddrList() { free(); }

    bool insert(const tchar *host, ushort port, Sockaddr::Proto proto =
	Sockaddr::TCP);
    bool insert(const tchar *host, const tchar *service = NULL,
	Sockaddr::Proto proto = Sockaddr::TCP);
    void insert(const Sockaddr &addr) {
	push_back(*new ObjectListNode<Sockaddr>(addr));
    }
};

/*
 * CIDR/Network class to simplify IP range lookups
 */
class BLISTER CIDR {
public:
    explicit CIDR(const tchar *addrs = NULL) { add(addrs); }

    bool add(const tchar *addrs);
    void clear(void) { ranges.clear(); }
    bool find(const tchar *addr) const;
    bool find(uint addr) const;
    bool set(const tchar *addrs) {
	clear();
	return add(addrs);
    }

private:
    struct BLISTER Range {
	bool operator ()(const Range &a, const Range &b) const {
	    return a.rmax < b.rmin;
	}
	bool operator <(const Range &a) const {
	    return rmin < a.rmin || (rmin == a.rmin && rmax < a.rmax);
	}

	ulong rmin, rmax;
    };

    vector<Range> ranges;
};

/*
 * Berkeley/WinSock Socket class manages stream or datagram server and client
 * sockets. Deals with OS dependent behavior for non-blocking sockets and
 * readv/writev emulation for improved performance. SIGINT retries are handled
 * automatically. Object copies are also supported by using a reference counted
 * subclass.
 */
class BLISTER Socket {
public:
    explicit Socket(int type = SOCK_STREAM, socket_t sock = SOCK_INVALID):
	sbuf(new SocketBuf(type, sock, sock == SOCK_INVALID)) {}
    // cppcheck-suppress copyCtorPointerCopying
    Socket(const Socket &r): sbuf(r.sbuf) { r.sbuf->count++; }
    ~Socket() { if (--sbuf->count == 0) delete sbuf; }

    Socket &operator =(socket_t sock);
    Socket &operator =(const Socket &r);
    bool operator ==(socket_t sock) const { return sbuf->sock == sock; }
    bool operator ==(const Socket &r) const {
	return sbuf == r.sbuf || sbuf->sock == r.sbuf->sock;
    }
    bool operator !=(const Socket &r) const { return !operator ==(r); }
    bool operator !(void) const { return sbuf->sock == SOCK_INVALID; }
    operator socket_t() const { return sbuf->sock; }

    bool blocked(void) const { return ::blocked(sbuf->err); }
    bool interrupted(void) const { return ::interrupted(sbuf->err); }
    int err(void) const { return sbuf->err; }
    void err(int err) const { sbuf->err = err; }
    const tstring errstr(void) const;
    socket_t fd(void) const { return sbuf->sock; }
    bool open(void) const { return sbuf->sock != SOCK_INVALID; }

    // socket actions
    bool accept(Socket &sock);
    bool bind(const Sockaddr &sa, bool reuse = true);
    bool close(void) { return sbuf->close(); }
    bool connect(const Sockaddr &sa, uint msec = SOCK_INFINITE);
    bool listen(int queue = SOCK_BACKLOG);
    bool listen(const Sockaddr &sa, bool reuse = true, int queue =
	SOCK_BACKLOG) {
	return bind(sa, reuse) && listen(queue);
    }
    bool movehigh(void);
    bool open(int family);
    bool peername(Sockaddr &sa);
    bool proxysockname(Sockaddr &sa);
    bool sockname(Sockaddr &sa);
    bool shutdown(bool in = true, bool out = true);

    // get/set socket properties
    bool blocking(void) const { return sbuf->blck; }
    bool blocking(bool on);
    bool cloexec(void);
    bool cork(void) const;
    bool cork(bool on);
    bool linger(ushort sec = (ushort)-1);

    // get/set socket options
    template<class C> bool getsockopt(int lvl, int opt, C &val) const {
	socklen_t sz = sizeof (val);

	return check(::getsockopt(sbuf->sock, lvl, opt, (char *)&val, &sz));
    }
    int getsockopt(int lvl, int opt) const {
	int i;

	return getsockopt(lvl, opt, i) ? i : -1;
    }
    template<class C> bool setsockopt(int lvl, int opt, C &val) {
	return check(::setsockopt(sbuf->sock, lvl, opt, (char *)&val,
	    sizeof (val)));
    }
    bool setsockopt(int lvl, int opt, bool val) { // NOLINT(misc-no-recursion)
	int i = (int)val;

	return setsockopt(lvl, opt, i);
    }
    bool nodelay(void) const { return getsockopt(IPPROTO_TCP, TCP_NODELAY) != 0; }
    bool nodelay(bool on) { return setsockopt(IPPROTO_TCP, TCP_NODELAY, on); }
    bool reuseaddr(void) const { return getsockopt(SOL_SOCKET, SO_REUSEADDR) != 0; }
    bool reuseaddr(bool on) { return setsockopt(SOL_SOCKET, SO_REUSEADDR, on); }
    int type(void) const { return getsockopt(SOL_SOCKET, SO_TYPE); }
    int rbuffer(void) const { return getsockopt(SOL_SOCKET, SO_RCVBUF); }
    bool rbuffer(int size) { return setsockopt(SOL_SOCKET, SO_RCVBUF, size); }
    int wbuffer(void) const { return getsockopt(SOL_SOCKET, SO_SNDBUF); }
    bool wbuffer(int size) { return setsockopt(SOL_SOCKET, SO_SNDBUF, size); }
    int rlowater(void) const { return getsockopt(SOL_SOCKET, SO_RCVLOWAT); }
    bool rlowater(int size) { return setsockopt(SOL_SOCKET, SO_RCVLOWAT, size); }
    int wlowater( void) const { return getsockopt(SOL_SOCKET, SO_SNDLOWAT); }
    bool wlowater(int size) { return setsockopt(SOL_SOCKET, SO_SNDLOWAT, size); }
    uint rtimeout(void) const { return sbuf->rto; }
    bool rtimeout(uint msec) { sbuf->rto = msec; return true; }
    bool rtimeout(const timeval &tv) {
	if (!setsockopt(SOL_SOCKET, SO_RCVTIMEO, tv))
	    rtimeout((uint)(tv.tv_sec * 1000 + tv.tv_usec / 1000));
	return true;
    }
    uint wtimeout(void) const { return sbuf->wto; }
    bool wtimeout(uint msec) { sbuf->wto = msec; return true; }
    bool wtimeout(const timeval &tv) {
	if (!setsockopt(SOL_SOCKET, SO_SNDTIMEO, tv))
	    wtimeout((uint)(tv.tv_sec * 1000 + tv.tv_usec / 1000));
	return true;
    }

    int read(void *buf, uint len) const;
    int read(void *buf, uint len, Sockaddr &sa) const;
    template<class C> int read(C &c) const { return read(&c, sizeof (c)); }
    long readv(iovec *iov, int count) const;
    long readv(iovec *iov, int count, const Sockaddr &sa) const;
    int write(const void *buf, uint len) const;
    int write(const void *buf, uint len, const Sockaddr &sa) const;
    template<class C> int write(const C &c) const {
	return write(&c, sizeof (c));
    }
    long writev(const iovec *iov, int count) const;
    long writev(const iovec *iov, int count, const Sockaddr &sa) const;

protected:
    class BLISTER SocketBuf: nocopy {
    public:
	SocketBuf(int t, socket_t s, bool o): sock(s), count(1), err(0),
	    path(NULL), rto(SOCK_INFINITE), type(t), wto(SOCK_INFINITE),
	    blck(true), own(o) {}
	~SocketBuf() { if (own) close(); }

	bool blocked(void) const { return ::blocked(err); }
	bool check(int ret) {
	    if (ret == -1) {
		err = sockerrno();
		return false;
	    } else {
		err = 0;
		return true;
	    }
	}
	bool __no_sanitize_thread close(void) {
	    if (sock == SOCK_INVALID) {
		err = EINVAL;
	    } else {
		int ret = ::closesocket(sock);

		sock = SOCK_INVALID;
		if (path) {
		    (void)::unlink(path);
		    free(path);
		    path = NULL;
		}
		if (ret)
		    err = sockerrno();
		else
		    return true;
	    }
	    return false;
	}
	bool interrupted(void) const { return ::interrupted(err); }
	void unlink(const char *p) {
#ifdef __linux__
	    if (strchr(p, '/'))
#endif
	    path = strdup(p);
	}

    private:
	socket_t sock;
	uint count;
	mutable int err;
	char *path;
	uint rto;
	int type;
	uint wto;
	bool blck, own;

	friend class Socket;
    };

    bool check(int ret) const { return sbuf->check(ret); }
    bool rwpoll(bool rd) const;

    SocketBuf *sbuf;
};

/*
 * SocketSet manages system dependent fd_set/select() and pollfd/poll()
 * differences and is optimized for very large file descriptor sets.
 */
class BLISTER SocketSet {
public:
    explicit SocketSet(uint maxfds = 0);
    SocketSet(const SocketSet &ss): fds(NULL), maxsz(0), sz(0) { *this = ss; }
    ~SocketSet() { delete [] fds; }

    SocketSet &operator =(const SocketSet &ss);
    template<class C> socket_t operator[](C at) const {
	return SSET_FD((uint)at);
    }

    bool empty(void) const { return sz == 0; }
    bool get(socket_t fd) const;
    bool get(const Socket &sock) const { return get(sock.fd()); }
    uint size(void) const { return sz; }

    void clear(void) { sz = 0; }
    bool set(socket_t fd);
    bool set(const Socket &sock) { return set(sock.fd()); }
    bool unset(socket_t fd);
    bool unset(const Socket &sock) { return unset(sock.fd()); }
    bool ipoll(SocketSet &iset, SocketSet &eset, uint msec = SOCK_INFINITE);
    bool iopoll(SocketSet &iset, SocketSet &oset, SocketSet &eset,
	uint msec = SOCK_INFINITE);
    bool opoll(SocketSet &oset, SocketSet &eset, uint msec = SOCK_INFINITE);

    static bool iopoll(const SocketSet &rset, SocketSet &iset,
	const SocketSet &wset, SocketSet &oset, SocketSet &eset,
	uint msec = SOCK_INFINITE);

private:
#ifdef _WIN32
    fd_set *fds;
#else
    pollfd *fds;
#endif
    uint maxsz, sz;
};

inline SocketSet::SocketSet(uint maxfds): maxsz(maxfds), sz(0) {
#ifdef _WIN32
    if (!maxsz)
	maxsz = 32;
    fds = (fd_set *)new socket_t[(size_t)maxsz + 1];
#else
    fds = maxsz ? new pollfd[maxsz] : NULL;
#endif
}

inline bool SocketSet::get(socket_t fd) const {
    for (uint u = 0; u < sz; u++)
	if (SSET_FD(u) == fd)
	    return true;
    return false;
}

inline SocketSet &SocketSet::operator =(const SocketSet &ss) {
    if (&ss != this) {
	sz = ss.sz;
#ifdef _WIN32
	if (maxsz < sz) {
	    maxsz = ss.maxsz;
	    delete [] fds;
	    fds = (fd_set *)new socket_t[(size_t)maxsz + 1];
	}
	memcpy(fds, ss.fds, ((size_t)sz + 1) * sizeof (socket_t));
#else
	if (maxsz < sz) {
	    maxsz = ss.maxsz;
	    delete [] fds;
	    fds = maxsz ? new pollfd[maxsz] : NULL;
	}
	if (fds)
	    memcpy(fds, ss.fds, sz * sizeof (pollfd));
#endif
    }
    return *this;
}

inline bool SocketSet::set(socket_t fd) {
    if (!fds || sz == maxsz) {
	maxsz = maxsz ? maxsz * 2 : 32;
#ifdef _WIN32
	fd_set *p = (fd_set *)new socket_t[(size_t)maxsz + 1];

	if (!p)
	    return false;
	else if (fds)
	    memcpy(p, fds, ((size_t)sz + 1) * sizeof (socket_t));
#else
	pollfd *p = new pollfd[maxsz];

	if (!p)
	    return false;
	else if (fds)
	    memcpy(p, fds, sz * sizeof (pollfd));
#endif
	delete [] fds;
	fds = p;
    }
    SSET_FD(sz++) = fd;
    return true;
}

inline bool SocketSet::unset(socket_t fd) {
    for (uint u = 0; u < sz; u++) {
	if (SSET_FD(u) == fd) {
	    SSET_FD(u) = SSET_FD(--sz);
	    return true;
	}
    }
    return false;
}

// socket streams
typedef faststreambuf<Socket> socketbuf;

class BLISTER isockstream : public istream {
public:
    explicit isockstream(streamsize sz = SOCK_BUFSZ, char *p = NULL):
	istream(NULL), sb(sz, p) { ios::init(&sb); }
    explicit isockstream(Socket &s, streamsize sz = SOCK_BUFSZ, char *p = NULL):
	istream(NULL), sb(s, sz, p) { ios::init(&sb); }
    virtual ~isockstream() {}

    socketbuf *rdbuf(void) const { return (socketbuf *)&sb; }
    const char *str(void) const { return sb.str(); }
    void str(char *p, streamsize sz) { sb.setbuf(p, sz); }
    streamsize read(void *p, streamsize sz) { return sb.read(p, (uint)sz); }
    template<class C> streamsize read(C &c) { return sb.read(&c, sizeof (c)); }

private:
    socketbuf sb;
};

class BLISTER osockstream: public ostream {
public:
    explicit osockstream(streamsize sz = SOCK_BUFSZ, char *p = NULL):
	ostream(NULL), sb(sz, p) { ios::init(&sb); }
    explicit osockstream(Socket &s, streamsize sz = SOCK_BUFSZ, char *p = NULL):
	ostream(NULL), sb(s, sz, p) { ios::init(&sb); }
    virtual ~osockstream() {}

    socketbuf *rdbuf(void) const { return (socketbuf *)&sb; }
    const char *str(void) const { return sb.str(); }
    void str(char *p, streamsize sz) { sb.setbuf(p, sz); }
    streamsize write(const void *p, streamsize sz) {
	return sb.write(p, (uint)sz);
    }
    template<class C> streamsize write(const C &c) {
	return sb.write(&c, sizeof (c));
    }

private:
    socketbuf sb;
};

class BLISTER sockstream: public iostream {
public:
    explicit sockstream(streamsize sz = SOCK_BUFSZ, char *p = NULL):
	iostream(NULL), sb(sz, p) { ios::init(&sb); }
    explicit sockstream(Socket &s, streamsize sz = SOCK_BUFSZ, char *p = NULL):
	iostream(NULL), sb(s, sz, p) { ios::init(&sb); }
    virtual ~sockstream() {}

    socketbuf *rdbuf(void) const { return (socketbuf *)&sb; }
    const char *str(void) const { return sb.str(); }
    void str(char *p, streamsize sz) { sb.setbuf(p, sz); }
    streamsize read(void *p, streamsize sz) { return sb.read(p, (uint)sz); }
    streamsize write(const void *p, streamsize sz) {
	return sb.write(p, (uint)sz);
    }
    template<class C> streamsize read(C &c) { return sb.read(&c, sizeof (c)); }
    template<class C> streamsize write(const C &c) {
	return sb.write(&c, sizeof (c));
    }

private:
    socketbuf sb;
};

#endif	// Socket_h
