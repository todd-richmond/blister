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

#ifndef Socket_h
#define Socket_h

#ifdef _WIN32
#ifdef _WIN32_WCE
#define E_ ENOTEMPTY
#undef ENOTEMPTY
#include <winsock.h>
#undef ENOTEMPTY
#define ENOTEMPTY
#undef E_
#elif !defined(_WINSOCK2API_)
#include <winsock2.h>
#endif

#pragma warning(disable: 4097)

#define socklen_t	int
#define SSET_FD(i)	fds->fd_array[i]

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

#define INVALID_SOCKET	-1
#define SSET_FD(i)	fds[i].fd
#define WSAEINTR	EINTR

typedef int socket_t;

inline int sockerrno(void) { return errno; }
inline int closesocket(socket_t fd) { return ::close(fd); }
#endif

#include <errno.h>
#include <vector>
#include "Streams.h"

const int SOCK_BACKLOG = 128;
const int SOCK_BUFSZ = 3 * 1024;
const ulong SOCK_INFINITE = (ulong)-1;
const socket_t SOCK_INVALID = INVALID_SOCKET;

inline bool blocked(int e) {
    return e && (e == EWOULDBLOCK || e == EAGAIN || e == ENOBUFS ||
	e == ENOSR || e == EINPROGRESS);
}

inline bool interrupted(int e) { return e == WSAEINTR; }

/*
 * Socket address class to wrap sockaddr structures and deal with Win32 startup
 * requirements. Currently restricted to IPV4 UDP or TCP addresses
 */
class Sockaddr: public sockaddr {
public:
    enum Proto { TCP, UDP };

    Sockaddr(const sockaddr &s);
    Sockaddr(ushort family = AF_INET) 
	{ set((const hostent *)NULL); sa_family = family; }
    Sockaddr(const tchar *hostport, Proto proto = TCP) { set(hostport, proto); }
    Sockaddr(const tchar *host, ushort port, Proto proto = TCP)
	{ set(host, port, proto); }
    Sockaddr(const tchar *host, const tchar *service, Proto proto = TCP)
	{ set(host, 0, proto); port(service, proto); }
    Sockaddr(const hostent *h) { set(h); }
    Sockaddr(const Sockaddr &s): sockaddr(s) { name = s.name; sz = s.sz; }

    bool operator ==(const Sockaddr &s) const { 
	return !memcmp((const sockaddr *)this, (const sockaddr *)&s,
	    sizeof (sockaddr));
    }
    bool operator !=(const Sockaddr &s) const { return !operator ==(s); }
    const Sockaddr &operator =(const Sockaddr &s) { name = s.name; sz = s.sz;
	memcpy((sockaddr *)this, (sockaddr *)&s, sizeof (sockaddr)); return *this; }
    operator const sockaddr *(void) const { return (sockaddr *)this; }
    operator const sockaddr_in *() const { return (sockaddr_in *)(sockaddr *)this; }

    dword addr(void) const
	{ return htonl(((sockaddr_in *)this)->sin_addr.s_addr); }
    void addr(dword addr)
	{ ((sockaddr_in *)this)->sin_addr.s_addr = htonl(addr); sz = 4;}
    ushort family(void) const { return sa_family; }
    void family(ushort fam) { sa_family = fam; }
    const tstring &host(void) const;
    bool host(const tchar *host) { return set(host, port()); }
    const tstring ip(void) const {
	return achartotstring(inet_ntoa(((const sockaddr_in *)this)->sin_addr));
    }
    const tstring str(void) const {
	tchar buf[12]; tsprintf(buf, T(":%u"), port());
	return host() + buf;
    }
    void *address(void) const;
    int size(void) const { return sz; }
    ushort port(void) const;
    bool port(ushort port);
    bool port(const tchar *service, Proto proto = TCP);
    bool set(const hostent *h);
    bool set(const tchar *host, ushort port, Proto proto = TCP);
    bool set(const tchar *hostport, Proto proto = TCP);
    
    static const tstring &hostname(void);
    static tstring service(ushort port, Proto proto = TCP);
    
private:
#ifdef _WIN32
    class SockInit {
    public:
	SockInit() { WSADATA w; WSAStartup(2 | (0 << 8), &w); }
	~SockInit() { WSACleanup(); }
    };

    static SockInit init;
#endif

    mutable tstring name;
    int sz;
    static const char *protos[];
};

inline void *Sockaddr::address() const {
    if (sa_family == AF_INET)
	return &((sockaddr_in *)(sockaddr *)this)->sin_addr;
    else
	return NULL;
}

inline tostream &operator <<(tostream &os, const Sockaddr &addr) {
    return os << addr.str();
}

/*
 * CIDR/Network class to simplify IP range lookups
 */
class CIDR {
public:
    CIDR(const tchar *addrs = NULL) { add(addrs); }

    bool add(const tchar *addrs);
    void erase(void) { ranges.erase(ranges.begin(), ranges.end()); }
    bool find(const tchar *addr) const;
    bool find(uint addr) const;
    bool set(const tchar *addrs) { erase(); return add(addrs); }

private:
    class Range {
    public:
	ulong min, max;

	bool operator ()(const Range &a, const Range &b) const {
	    return a.max < b.min;
	}
	bool operator <(const Range &a) const {
	    return min < a.min || (min == a.min && max < a.max);
	}
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
    Socket(const Socket &r) { r.sbuf->count++; sbuf = r.sbuf; }
    ~Socket() { if (--sbuf->count == 0) delete sbuf; }

    const Socket &operator =(socket_t sock);
    const Socket &operator =(const Socket &r);
    bool operator ==(socket_t sock) const { return sbuf->sock == sock; }
    bool operator ==(const Socket &r) const
	{ return sbuf == r.sbuf || sbuf->sock == r.sbuf->sock; }
    bool operator !=(const Socket &r) const { return !operator ==(r); }
    operator void *(void) const { return sbuf->sock == SOCK_INVALID ? NULL : sbuf; }
    bool operator !(void) const { return sbuf->sock == SOCK_INVALID; }
    operator socket_t() const { return sbuf->sock; }

    bool blocked(void) const { return ::blocked(sbuf->err); }
    bool interrupted(void) const { return ::interrupted(sbuf->err); }
    int err(void) const { return sbuf->err; }
    socket_t fd(void) const { return sbuf->sock; }
    bool open(void) const { return sbuf->sock != SOCK_INVALID; }

    // socket actions
    bool accept(Socket &sock);
    bool bind(const Sockaddr &addr, bool reuse = true);
    bool close(void) { return sbuf->close(); }
    bool connect(const Sockaddr &addr, ulong timeout = SOCK_INFINITE);
    bool listen(int queue = SOCK_BACKLOG);
    bool listen(const Sockaddr &addr, bool reuse = true,
	int queue = SOCK_BACKLOG) {
	return bind(addr, reuse) && listen(queue);
    }
    bool movehigh(void) {
	return (sbuf->sock = movehigh(sbuf->sock)) != SOCK_INVALID;
    }
    bool open(int family);
    bool peername(Sockaddr &addr);
    bool proxysockname(Sockaddr &addr);
    bool sockname(Sockaddr &addr);
    bool shutdown(bool in = true, bool out = true);

    // get/set socket properties
    bool blocking(void) const { return sbuf->blck; }
    bool blocking(bool on);
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
    bool nodelay(void) const { return getsockopt(IPPROTO_TCP, TCP_NODELAY); }
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
    ulong rtimeout(void) const { return sbuf->rto; }
    bool rtimeout(ulong msec) { sbuf->rto = msec; return true; }
    bool rtimeout(const timeval &tv) {
	if (!setsockopt(SOL_SOCKET, SO_RCVTIMEO, tv))
	    rtimeout(tv.tv_sec * 1000 + tv.tv_usec / 1000);
	return true;
    }
    ulong wtimeout(void) const { return sbuf->wto; }
    bool wtimeout(ulong msec) { sbuf->wto = msec; return true; }
    bool wtimeout(const timeval &tv) {
	if (!setsockopt(SOL_SOCKET, SO_SNDTIMEO, tv))
	    wtimeout(tv.tv_sec * 1000 + tv.tv_usec / 1000);
	return true;
    }
    int rwindow(void) const { return getsockopt(SOL_SOCKET, SO_RCVLOWAT); }
    bool rwindow(int size) { return setsockopt(SOL_SOCKET, SO_RCVLOWAT, size); }
    int wwindow(void) const { return getsockopt(SOL_SOCKET, SO_SNDLOWAT); }
    bool wwindow(int size) { return setsockopt(SOL_SOCKET, SO_SNDLOWAT, size); }

    int read(void *buf, size_t len) const;
    int read(void *buf, size_t len, Sockaddr &addr) const;
    template<class C> int read(C &c) const { return read(&c, sizeof (c)); }
    long readv(iovec *iov, int count) const;
    long readv(iovec *iov, int count, const Sockaddr &addr) const;
    int write(const void *buf, size_t len) const;
    int write(const void *buf, size_t len, const Sockaddr &addr) const;
    template<class C> int write(const C &c) const { return write(&c, sizeof (c)); }
    long writev(const iovec *iov, int count) const;
    long writev(const iovec *iov, int count, const Sockaddr &addr) const;

protected:
    class SocketBuf {
    public:
	SocketBuf(int t, socket_t s, bool o): blck(true), count(1), err(0),
	    own(o), sock(s), rto(SOCK_INFINITE), type(t), wto(SOCK_INFINITE) {}
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
	bool blck;
	uint count;
	mutable int err;
	bool own;
	socket_t sock;
	ulong rto;
	int type;
	ulong wto;

	friend class Socket;
    };
    
protected:
    bool check(int ret) const { return sbuf->check(ret); }
    socket_t movehigh(socket_t fd);
    bool rwpoll(bool rd) const;

    SocketBuf *sbuf;
};

/*
 * SocketSet manages system dependent fd_set/select() and pollfd/poll()
 * differences and is optimized for very large file descriptor sets. 
 */
class SocketSet {
public:
    SocketSet(uint maxfds = 0);
    SocketSet(const SocketSet &ss): fds(NULL), maxsz(0), sz(0) { *this = ss; }
    ~SocketSet() { delete [] fds; }
    
    const SocketSet &operator =(const SocketSet &r);
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
    bool iselect(SocketSet &iset, SocketSet &eset, ulong msec = SOCK_INFINITE);
    bool ioselect(SocketSet &iset, SocketSet &oset, SocketSet &eset,
	ulong msec = SOCK_INFINITE);
    bool oselect(SocketSet &oset, SocketSet &eset, ulong msec = SOCK_INFINITE);
    
    static bool ioselect(const SocketSet &rset, SocketSet &iset,
	const SocketSet &wset, SocketSet &oset, SocketSet &eset,
	ulong msec = SOCK_INFINITE);
    
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

inline const SocketSet &SocketSet::operator =(const SocketSet &ss) {
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
    streamsize read(void *p, streamsize sz) { return sb.read(p, sz); }
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
    streamsize write(const void *p, streamsize sz) { return sb.write(p, sz); }
    template<class C> streamsize write(const C &c) { return sb.write(&c, sizeof (c)); }

private:
    socketbuf sb;
};

class sockstream: public iostream {
public:
    sockstream(int sz = SOCK_BUFSZ, char *p = NULL, openmode mode = in | out):
	iostream(NULL), sb(sz, p) { ios::init(&sb); }
    sockstream(Socket &s, int sz = SOCK_BUFSZ, char *p = NULL):
	iostream(NULL), sb(s, sz, p) { ios::init(&sb); }
    virtual ~sockstream() {}

    socketbuf *rdbuf(void) const { return (socketbuf *)&sb; }
    const char *str(void) const { return sb.str(); }
    void str(char *p, streamsize sz) { sb.setbuf(p, sz); }
    streamsize read(void *p, streamsize sz) { return sb.read(p, sz); }
    streamsize write(const void *p, streamsize sz) { return sb.write(p, sz); }
    template<class C> streamsize read(C &c) { return sb.read(&c, sizeof (c)); }
    template<class C> streamsize write(const C &c) { return sb.write(&c, sizeof (c)); }

private:
    socketbuf sb;
};

#endif	// Socket_h
