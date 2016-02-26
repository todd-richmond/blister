/*
 * Copyright 2001-2016 Todd Richmond
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
#include <winsock2.h>
#pragma warning(push)
#pragma warning(disable: 6386)
#include <ws2tcpip.h>
#pragma warning(pop)
#pragma warning(disable: 4097)

#define socklen_t	int
#define SSET_FD(i)	fds->fd_array[i]
#define SOCK_SIZE_T	int

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

#define ioctlsocket	ioctl
#define INVALID_SOCKET	-1
#define SSET_FD(i)	fds[i].fd
#define SOCK_SIZE_T	size_t
#define WSAEALREADY	EALREADY
#define WSAEINPROGRESS	EINPROGRESS
#define WSAEINTR	EINTR
#define WSAEWOULDBLOCK	EWOULDBLOCK

typedef int socket_t;

inline int closesocket(socket_t fd) { return ::close(fd); }
inline int sockerrno(void) { return errno; }
#endif

#include <errno.h>
#include <vector>
#include "Streams.h"

const int SOCK_BACKLOG = 128;
const int SOCK_BUFSZ = 3 * 1024;
const uint SOCK_INFINITE = (uint)-1;
const socket_t SOCK_INVALID = INVALID_SOCKET;

inline bool blocked(int e) {
#ifdef _WIN32
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY;
#else
    return e == EWOULDBLOCK || e == EAGAIN || e == ENOBUFS ||
	e == ENOSR || e == EINPROGRESS || e == EALREADY;
#endif
}

inline bool interrupted(int e) { return e == WSAEINTR; }

/*
 * Socket address class to wrap sockaddr structures and deal with Win32 startup
 * requirements. Currently restricted to IPV4 UDP or TCP addresses
 */
class Sockaddr {
public:
    enum Proto { TCP, UDP, TCP4, UDP4, TCP6, UDP6  };

    explicit Sockaddr(const addrinfo *ai) { set(ai); }
    Sockaddr(const tchar *host, Proto proto = TCP) { set(host, proto); }
    Sockaddr(const tchar *host, ushort port, Proto proto = TCP) {
	set(host, port, proto);
    }
    Sockaddr(const tchar *host, const tchar *service, Proto proto = TCP) {
	set(host, service, proto);
    }
    explicit Sockaddr(const hostent *h) { set(h); }
    explicit Sockaddr(Proto proto = TCP) {
	ZERO(addr);
	addr.sa.sa_family = families[(uint)proto];
    }
    explicit Sockaddr(const sockaddr &sa) { set(sa); }
    Sockaddr(const Sockaddr &sa): addr(sa.addr), name(sa.name) {}

    bool operator ==(const Sockaddr &sa) const { 
	return !memcmp(&addr, &sa.addr, sizeof (addr));
    }
    bool operator !=(const Sockaddr &sa) const { return !operator ==(sa); }
    Sockaddr &operator =(const Sockaddr &sa) {
	addr = sa.addr;
	name = sa.name;
	return *this;
    }
    operator const sockaddr *() const { return &addr.sa; }
    operator const sockaddr_in *() const { return &addr.sa4; }
    operator const sockaddr_in6 *() const { return &addr.sa6; }

    const void *address(void) const;
    void clear() { ZERO(addr); name.clear(); }
    sockaddr *data(void) { name.clear(); return &addr.sa; }
    ushort family(void) const { return addr.sa.sa_family; }
    void family(ushort fam) { addr.sa.sa_family = fam; }
    const tstring &host(void) const;
    bool host(const tchar *host, Proto proto = TCP) {
	return port() ? set(host, port(), proto) : set(host, proto);
    }
    const tstring host_port(void) const;
    bool ipv4() const { return addr.sa.sa_family == AF_INET; }
    bool ipv6() const { return addr.sa.sa_family == AF_INET6; }
    ushort port(void) const;
    void port(ushort port);
    bool service(const tchar *service, Proto proto = TCP);
    bool set(const addrinfo *h);
    bool set(const tchar *host, Proto proto = TCP);
    bool set(const tchar *host, ushort port, Proto proto = TCP);
    bool set(const tchar *host, const tchar *service, Proto proto = TCP);
    bool set(const hostent *h);
    bool set(const sockaddr &sa);
    ushort size(void) const { return size(family()); }
    const tstring str(void) const;

    static ushort families[];
    static bool dgram(Proto proto) {
	return proto == UDP || proto == UDP4 || proto == UDP6;
    }
    static const tstring &hostname(void);
    static const tstring service_name(ushort port, Proto proto = TCP);
    static ushort service_port(const tchar *service, Proto proto = TCP);
    static ushort size(ushort family);
    static bool stream(Proto proto) {
	return proto == TCP || proto == TCP4 || proto == TCP6;
    }

private:
#ifdef _WIN32
    class SockInit {
    public:
	SockInit() { WSADATA w; (void)WSAStartup(2 | (0 << 8), &w); }
	~SockInit() { WSACleanup(); }
    };

    static SockInit init;
#endif

    typedef union {
	sockaddr sa;
	sockaddr_in sa4;
	sockaddr_in6 sa6;
    } sockaddr_any;

    sockaddr_any addr;
    mutable tstring name;
};

inline tostream &operator <<(tostream &os, const Sockaddr &addr) {
    return os << addr.str();
}

/*
 * CIDR/Network class to simplify IP range lookups
 */
class CIDR {
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
    struct Range {
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
class Socket {
public:
    Socket(int type = SOCK_STREAM, socket_t sock = SOCK_INVALID):
	sbuf(new SocketBuf(type, sock, sock == SOCK_INVALID)) {}
    // cppcheck-suppress copyCtorPointerCopying
    Socket(const Socket &r) { r.sbuf->count++; sbuf = r.sbuf; }
    ~Socket() { if (--sbuf->count == 0) delete sbuf; }

    Socket &operator =(socket_t sock);
    Socket &operator =(const Socket &r);
    bool operator ==(socket_t sock) const { return sbuf->sock == sock; }
    bool operator ==(const Socket &r) const
	{ return sbuf == r.sbuf || sbuf->sock == r.sbuf->sock; }
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
    bool setsockopt(int lvl, int opt, bool val) {
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
    template<class C> int write(const C &c) const { return write(&c, sizeof (c)); }
    long writev(const iovec *iov, int count) const;
    long writev(const iovec *iov, int count, const Sockaddr &sa) const;

protected:
    class SocketBuf {
    public:
	SocketBuf(int t, socket_t s, bool o): sock(s), count(1), err(0),
	    rto(SOCK_INFINITE), type(t), wto(SOCK_INFINITE), blck(true), own(o) {}
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
	bool close(void) {
	    if (sock == SOCK_INVALID) {
		err = EINVAL;
		return false;
	    } else {
		bool b = check(::closesocket(sock));
		sock = SOCK_INVALID;
		return b;
	    }
	}
	bool interrupted(void) const { return ::interrupted(err); }

    private:
	socket_t sock;
	uint count;
	mutable int err;
	uint rto;
	int type;
	uint wto;
	bool blck, own;

	friend class Socket;
    };
    
protected:
    bool check(int ret) const { return sbuf->check(ret); }
    bool rwpoll(bool rd) const;

    SocketBuf *sbuf;
};

/*
 * SocketSet manages system dependent fd_set/select() and pollfd/poll()
 * differences and is optimized for very large file descriptor sets. 
 */
class SocketSet {
public:
    explicit SocketSet(uint maxfds = 0);
    SocketSet(const SocketSet &ss): fds(NULL), maxsz(0), sz(0) { *this = ss; }
    ~SocketSet() { delete [] fds; }
    
    SocketSet &operator =(const SocketSet &r);
    template<class C> socket_t operator [](C at) const {
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
    fds = (fd_set *)new socket_t[maxsz + 1];
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
	    fds = (fd_set *)new socket_t[maxsz + 1];
	}
	memcpy(fds, ss.fds, (sz + 1) * sizeof (socket_t));
#else
	if (maxsz < sz) {
	    maxsz = ss.maxsz;
	    delete [] fds;
	    fds = new pollfd[maxsz];
	}
	memcpy(fds, ss.fds, sz * sizeof (pollfd));
#endif
    }
    return *this;
}

inline bool SocketSet::set(socket_t fd) {
    if (sz == maxsz) {
	maxsz = maxsz ? maxsz * 2 : 32;
#ifdef _WIN32
	fd_set *p = (fd_set *)new socket_t[maxsz + 1];

	memcpy(p, fds, (sz + 1) * sizeof (socket_t));
#else
	pollfd *p = new pollfd[maxsz];

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

class isockstream : public istream {
public:
    isockstream(int sz = SOCK_BUFSZ, char *p = NULL):
	istream(NULL), sb(sz, p) { ios::init(&sb); }
    isockstream(Socket &s, int sz = SOCK_BUFSZ, char *p = NULL):
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

class osockstream: public ostream {
public:
    osockstream(int sz = SOCK_BUFSZ, char *p = NULL):
	ostream(NULL), sb(sz, p) { ios::init(&sb); }
    osockstream(Socket & s, int sz = SOCK_BUFSZ, char *p = NULL):
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

class sockstream: public iostream {
public:
    sockstream(int sz = SOCK_BUFSZ, char *p = NULL):
	iostream(NULL), sb(sz, p) { ios::init(&sb); }
    sockstream(Socket &s, int sz = SOCK_BUFSZ, char *p = NULL):
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
