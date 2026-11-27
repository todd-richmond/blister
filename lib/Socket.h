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

#ifndef Socket_h
#define Socket_h

#ifdef _WIN32
#pragma warning(push)
#pragma warning(disable: 4365 6386)
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <afunix.h>
#pragma warning(pop)
#pragma warning(disable: 4097)

#define SSET_FD(i)	fds->fd_array[i]
#define SOCK_SIZE_T	int
#define s6_addr16	u.Word
#define s6_addr32	u.Dword

using sa_family_t = ushort;
using socket_t = SOCKET;
using socklen_t = int;

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
#define WSAECONNREFUSED	ECONNREFUSED
#define WSAEINPROGRESS	EINPROGRESS
#define WSAEINTR	EINTR
#define WSAENOTSOCK	ENOTSOCK
#define WSAETIMEDOUT	ETIMEDOUT
#define WSAEWOULDBLOCK	EWOULDBLOCK

#ifdef BSD_BASE
#define s6_addr16	__u6_addr.__u6_addr16
#define s6_addr32	__u6_addr.__u6_addr32
#endif

using socket_t = int;

inline int closesocket(socket_t fd) { return ::close(fd); }
inline int sockerrno(void) { return errno; }
#endif

#include <algorithm>
#include <utility>
#include <vector>
#include "Streams.h"
#include "Thread.h"

constexpr int SOCK_BACKLOG = 128;
constexpr int SOCK_BUFSZ = 3 * 1024;
constexpr uint SOCK_INFINITE = (uint)-1;
constexpr socket_t SOCK_INVALID = INVALID_SOCKET;

constexpr bool blocked(int e) {
#ifdef _WIN32
    return e == WSAEWOULDBLOCK || e == WSAEINPROGRESS || e == WSAEALREADY;
#else
    return LIKELY(e == EAGAIN || e == EWOULDBLOCK) || e == ENOBUFS ||
	e == ENOSR || e == EINPROGRESS || e == EALREADY;
#endif
}

constexpr bool interrupted(int e) { return e == WSAEINTR; }

/*
 * sockaddr wrapper that also handles Win32 startup. Limited to IPv4/6 TCP or
 * UDP addresses and UNIX domain paths
 */
class BLISTER Sockaddr {
public:
    enum Proto { TCP, UDP, TCP4, UDP4, TCP6, UDP6, UNIX, UNSPEC };

    explicit Sockaddr(const addrinfo *ai, tstring_view reqhost = {}) {
	set(ai, reqhost);
    }
    explicit Sockaddr(const hostent *h, tstring_view reqhost = {}) {
	set(h, reqhost);
    }
    explicit Sockaddr(Proto proto = TCP): addr() { family(proto); }
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
    friend bool operator ==(const Sockaddr &a, const Sockaddr &b) {
	if (a.family() != b.family())
	    return false;
	if (a.family() == AF_INET6)
	    return a.addr.sa6.sin6_port == b.addr.sa6.sin6_port &&
		a.addr.sa6.sin6_scope_id == b.addr.sa6.sin6_scope_id &&
		!memcmp(&a.addr.sa6.sin6_addr, &b.addr.sa6.sin6_addr, // NOSONAR
		sizeof (in6_addr));
	return !memcmp(&a.addr, &b.addr, a.size());	// NOSONAR
    }
    friend tostream &operator <<(tostream &os, const Sockaddr &sa) {
	return os << sa.str();
    }
    explicit operator const in_addr *() const { return &addr.sa4.sin_addr; }
    explicit operator const in6_addr *() const { return &addr.sa6.sin6_addr; }
    explicit operator const sockaddr *() const { return &addr.sa; }
    explicit operator const sockaddr_in *() const { return &addr.sa4; }
    explicit operator const sockaddr_in6 *() const { return &addr.sa6; }
    explicit operator const sockaddr_un *() const { return &addr.sau; }

    const void *address(void) const;
    void clear(void) { ZERO(addr); name.clear(); requested.clear(); }
    sockaddr *data(void) { clear(); return &addr.sa; }
    ushort family(void) const { return addr.sa.sa_family; }
    void family(sa_family_t fam) { addr.sa.sa_family = fam; }
    void family(Proto proto) { addr.sa.sa_family = families[(uint)proto]; }
    const tstring &host(void) const;
    bool host(const tchar *host, Proto proto = TCP) {
	return port() ? set(host, port(), proto) : set(host, proto);
    }
    tstring ip(void) const;
    tstring ipstr(void) const { return str(ip()); }
    bool ipv4(void) const { return family() == AF_INET; }
    bool ipv6(void) const { return family() == AF_INET6; }
    bool localhost(void) const {
	if (proto() == UNIX) {
	    return true;
	} else if (v4mapped()) {
	    in_addr a4;

	    return v4addr(&a4) && ntohl(a4.s_addr) >> 24 == 127;
	} else if (ipv6()) {
	    return IN6_IS_ADDR_LOOPBACK((const in6_addr *)*this);
	} else if (ipv4()) {
	    return ntohl(((const in_addr *)*this)->s_addr) >> 24 == 127;
	}
	return false;
    }
    const char *path(void) const {
	return family() == AF_UNIX ? addr.sau.sun_path[0] == '\0' ?
	    addr.sau.sun_path + 1 : addr.sau.sun_path : nullptr;
    }
    ushort port(void) const;
    void port(ushort port);
    Proto proto(void) const;
    const tstring &requestedhost(void) const { return requested; }
    bool service(const tchar *service, Proto proto = TCP);
    bool set(const addrinfo *ai);
    bool set(const addrinfo *ai, tstring_view reqhost);
    bool set(const tchar *host, Proto proto = TCP);
    bool set(const tchar *host, ushort port, Proto proto = TCP);
    bool set(const tchar *host, const tchar *service, Proto proto = TCP);
    bool set(const hostent *h);
    bool set(const hostent *h, tstring_view reqhost);
    bool set(const sockaddr &sa);
    // Linux abstract names are the bytes up to the address length
    ushort size(void) const {
	return family() == AF_UNIX && !addr.sau.sun_path[0] &&
	    addr.sau.sun_path[1] ? (ushort)(offsetof(sockaddr_un, sun_path) +
	    1 + strlen(addr.sau.sun_path + 1)) : size(family());
    }
    tstring str(void) const {
	if (!requested.empty())
	    return str(requested);
	return str(!name.empty() || !(ipv4() || ipv6()) ? host() : ip());
    }
    bool v4addr(in_addr *addr4) const {
	if (!v4mapped())
	    return false;
#ifdef _WIN32
	memcpy(addr4, &addr.sa6.sin6_addr.u.Byte[12], sizeof (*addr4));
#else
	memcpy(addr4, &addr.sa6.sin6_addr.s6_addr32[3], sizeof (*addr4));
#endif
	return true;
    }
    bool v4mapped(void) const {
	return ipv6() && IN6_IS_ADDR_V4MAPPED(&addr.sa6.sin6_addr);
    }

    static bool dgram(Proto proto) {
	return proto == UDP || proto == UDP4 || proto == UDP6;
    }
    static addrinfo *getaddrinfo(const tchar *host, const tchar *service, Proto
	proto = TCP);
    static const tstring &hostname(void);
    static tstring service_name(ushort port, Proto proto = TCP);
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
	sockaddr_un sau;
    } sockaddr_any;

#ifdef _WIN32
    class BLISTER SockInit: nocopy {
    public:
	SockInit() { WSADATA w; (void)WSAStartup(MAKEWORD(2, 2), &w); }
	~SockInit() { WSACleanup(); }
    };

    static SockInit init;
#endif

    sockaddr_any addr;
    mutable tstring name;
    tstring requested;
    static constexpr sa_family_t families[] = {
	AF_UNSPEC, AF_UNSPEC, AF_INET, AF_INET, AF_INET6, AF_INET6, AF_UNIX,
	AF_UNSPEC
    };

    tstring str(const tstring &val) const;

    static Proto familyhint(const tchar *&host, Proto proto);
    static addrinfo *resolve(const tchar *host, const tchar *service,
	Proto proto, const tchar **requested);

    friend class SockaddrList;
};

// Socket address list for hosts that resolve to multiple results
class BLISTER SockaddrList: public ObjectList<ObjectListNode<Sockaddr>> {
public:
    SockaddrList() = default;
    SockaddrList(const tchar *host, ushort port, Sockaddr::Proto proto =
	Sockaddr::TCP) { insert(host, port, proto); }
    explicit SockaddrList(const tchar *host, const tchar *service = nullptr,
	Sockaddr::Proto proto = Sockaddr::TCP) { insert(host, service, proto); }
    ~SockaddrList() { free(); }

    bool insert(const tchar *host, ushort port, Sockaddr::Proto proto =
	Sockaddr::TCP);
    bool insert(const tchar *host, const tchar *service = nullptr,
	Sockaddr::Proto proto = Sockaddr::TCP);
    void insert(const Sockaddr &addr) {
	push_back(*new ObjectListNode<Sockaddr>(addr));
    }
};

// CIDR/Network class to simplify IP range lookups
class BLISTER CIDR {
public:
    explicit CIDR(const tchar *addrs = nullptr) { add(addrs); }

    bool add(const tchar *addrs);
    void clear(void) { ranges.clear(); }
    bool find(const tchar *addr) const;
    bool find(uint addr) const;
    bool set(const tchar *addrs) {
	clear();
	return add(addrs);
    }

private:
    class Range {
    public:
	auto operator <=>(const Range &) const = default;

	uint32_t rmin, rmax;
    };

    vector<Range> ranges;			// sorted and disjoint

    static bool parse_ip(const tchar *&p, uint32_t &ip);
};

class Socket;

/*
 * Stream transform such as TLS between Socket I/O and the fd. Owned by the
 * SocketBuf so every Socket copy uses it. Methods return > 0 for success or
 * bytes, 0 for EOF and -1 with the Socket err set, EAGAIN to retry
 */
class BLISTER SocketLayer: nocopy {
public:
    enum State: uint {
	Pending = 1,		// buffered input that no poll reports
	ReadWrites = 2,		// blocked read or handshake needs writability
	WriteReads = 4,		// blocked write or handshake needs readability
	Drained = 8		// the last read emptied the fd
    };

    virtual ~SocketLayer() = default;

    virtual tstring errstr(void) const = 0;
    virtual long handshake(const Socket &s) = 0;
    virtual ssize_t read(const Socket &s, void *buf, ulong len) = 0;
    // before the fd closes
    virtual void shutdown(void) = 0;
    virtual uint state(void) const = 0;
    virtual ssize_t write(const Socket &s, const iovec *iov, int count) = 0;
};

/*
 * Berkeley/WinSock stream or datagram socket with portable non-blocking I/O
 * and EINTR retries. Copies share a reference counted SocketBuf
 */
class BLISTER Socket {
public:
    explicit Socket(int type = SOCK_STREAM, socket_t sock = SOCK_INVALID):
	sbuf(new SocketBuf(type, sock, sock == SOCK_INVALID)) {}
    // cppcheck-suppress copyCtorPointerCopying
    Socket(const Socket &r): sbuf(r.sbuf) { r.sbuf->reference(); }
    Socket(Socket &&r) noexcept: sbuf(r.sbuf) {
	r.sbuf = new SocketBuf(sbuf->type, SOCK_INVALID, true);
    }
    ~Socket() { if (sbuf->release()) delete sbuf; }

    Socket &operator =(socket_t sock);
    Socket &operator =(const Socket &r);
    Socket &operator =(Socket &&r) noexcept;
    friend bool operator ==(const Socket &s, socket_t sock) {
	return s.fd() == sock;
    }
    friend bool operator ==(socket_t sock, const Socket &s) {
	return s.fd() == sock;
    }
    friend bool operator ==(const Socket &a, const Socket &b) {
	return a.sbuf == b.sbuf || (a.open() && a.fd() == b.fd());
    }
    friend bool operator !(const Socket &s) {
	return s.fd() == SOCK_INVALID;
    }
    explicit operator socket_t() const { return fd(); }

    bool __forceinline blocked(void) const { return sbuf->blocked(); }
    bool __forceinline interrupted(void) const { return sbuf->interrupted(); }
    int err(void) const { return sbuf->err; }
    void err(int err) const { sbuf->err = err; }
    tstring errstr(void) const;
    socket_t fd(void) const { return sbuf->sock; }
    // run the layer handshake: 1 done, 0 would block, -1 error
    long handshake(void) const;
    bool open(void) const { return sbuf->sock != SOCK_INVALID; }
    bool stream(void) const { return sbuf->type == SOCK_STREAM; }

    // socket actions
    bool accept(Socket &sock, bool cloexec = true, bool nonblock = false);
    bool bind(const Sockaddr &sa, bool reuse = true);
    bool close(void) { return sbuf->close(); }
    bool connect(const Sockaddr &sa, uint msec = SOCK_INFINITE);
    SocketLayer *layer(void) const { return sbuf->layer; }
    // take ownership of l, replacing any current layer
    void layer(SocketLayer *l) { sbuf->unlayer(false); sbuf->layer = l; }
    bool listen(int queue = SOCK_BACKLOG);
    bool listen(const Sockaddr &sa, bool reuse = true, int queue =
	SOCK_BACKLOG) {
	return bind(sa, reuse) && listen(queue);
    }
    bool movehigh(void);
    bool open(int family);
    bool peername(Sockaddr &sa);
#ifdef __linux__
    // NAT original destination
    bool proxysockname(Sockaddr &sa);
#endif
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
    template<class C> bool setsockopt(int lvl, int opt, const C &val) { // NOSONAR
	return check(::setsockopt(sbuf->sock, lvl, opt, (const char *)&val,
	    sizeof (val)));
    }
    bool setsockopt(int lvl, int opt, bool val) { // NOSONAR
	int i = (int)val;

	return setsockopt(lvl, opt, i);
    }
    bool loopback(void) const;
    bool loopback(bool on);
    bool nodelay(void) const {
	return getsockopt(IPPROTO_TCP, TCP_NODELAY) > 0;
    }
    bool nodelay(bool on) { return setsockopt(IPPROTO_TCP, TCP_NODELAY, on); }
    bool reuseaddr(void) const {
	return getsockopt(SOL_SOCKET, SO_REUSEADDR) > 0;
    }
    bool reuseaddr(bool on) { return setsockopt(SOL_SOCKET, SO_REUSEADDR, on); }
    int type(void) const { return getsockopt(SOL_SOCKET, SO_TYPE); }
    int rbuffer(void) const { return getsockopt(SOL_SOCKET, SO_RCVBUF); }
    bool rbuffer(int size) { return setsockopt(SOL_SOCKET, SO_RCVBUF, size); }
    int wbuffer(void) const { return getsockopt(SOL_SOCKET, SO_SNDBUF); }
    bool wbuffer(int size) { return setsockopt(SOL_SOCKET, SO_SNDBUF, size); }
    int rlowater(void) const { return getsockopt(SOL_SOCKET, SO_RCVLOWAT); }
    bool rlowater(int size) {
	return setsockopt(SOL_SOCKET, SO_RCVLOWAT, size);
    }
    int wlowater( void) const { return getsockopt(SOL_SOCKET, SO_SNDLOWAT); }
    bool wlowater(int size) {
	return setsockopt(SOL_SOCKET, SO_SNDLOWAT, size);
    }
    uint rtimeout(void) const { return sbuf->rto; }
    bool rtimeout(uint msec) { sbuf->rto = msec; return true; }
    bool rtimeout(const timeval &tv) {
	return rtimeout((uint)(tv.tv_sec * 1000 + tv.tv_usec / 1000));
    }
    uint wtimeout(void) const { return sbuf->wto; }
    bool wtimeout(uint msec) { sbuf->wto = msec; return true; }
    bool wtimeout(const timeval &tv) {
	return wtimeout((uint)(tv.tv_sec * 1000 + tv.tv_usec / 1000));
    }

    int read(void *buf, uint len) const;
    int read(void *buf, uint len, Sockaddr &sa) const;
    template<class C> requires is_trivially_copyable_v<C>
    int read(C &c) const { return read(&c, sizeof (c)); }
    ssize_t readv(iovec *iov, int count) const;
    ssize_t readv(iovec *iov, int count, Sockaddr &sa) const;
#ifndef _WIN32
    ssize_t sendmsg(const msghdr &msgh, int flags = 0) const;
#endif
    int write(const void *buf, uint len) const;
    int write(const void *buf, uint len, const Sockaddr &sa) const;
    template<class C> requires is_trivially_copyable_v<C>
    int write(const C &c) const { return write(&c, sizeof (c)); }
    ssize_t writev(const iovec *iov, int count) const;
    ssize_t writev(const iovec *iov, int count, const Sockaddr &sa) const;

protected:
    class BLISTER SocketBuf: public RefCount {
    public:
	SocketBuf(int t, socket_t s, bool o): own(o), sock(s), type(t) {}
	~SocketBuf() {
	    if (own)
		close();
	    else
		unlayer(false);
	}

	bool __forceinline blocked(void) const { return ::blocked(err); }
	bool __forceinline interrupted(void) const {
	    return ::interrupted(err);
	}
	bool __forceinline check(const ssize_t ret) const {
	    if (LIKELY(ret != -1))
		return true;
	    err = sockerrno();
	    return false;
	}
	bool __no_sanitize_thread close(void) {
	    krto = kwto = SOCK_INFINITE;
	    unlayer(sock != SOCK_INVALID);
	    if (sock == SOCK_INVALID) {
		err = EINVAL;
	    } else {
		int ret = ::closesocket(sock);

		sock = SOCK_INVALID;
		if (!path.empty()) {
		    (void)::unlink(path.c_str());
		    path.clear();
		}
		if (ret)
		    err = sockerrno();
		else
		    return true;
	    }
	    return false;
	}
	void reset(int t, socket_t s) {
	    if (own)
		close();
	    else
		unlayer(false);
	    blck = true;
	    err = 0;
	    own = false;
	    rto = wto = SOCK_INFINITE;
	    krto = kwto = SOCK_INFINITE;
	    sock = s;
	    type = t;
	    reference();
	}
	void unlink(const char *p) { path = p; }
	void unlayer(bool notify) {
	    if (UNLIKELY(layer)) {
		if (notify)
		    layer->shutdown();
		delete layer;
		layer = nullptr;
	    }
	}

    private:
	bool blck = true, own;
	mutable int err = 0;
	SocketLayer *layer = nullptr;
	string path;
	uint rto = SOCK_INFINITE, wto = SOCK_INFINITE;
	uint krto = SOCK_INFINITE, kwto = SOCK_INFINITE;
	socket_t sock;
	int type;

	friend class Socket;
    };

    bool __forceinline check(ssize_t ret) const { return sbuf->check(ret); }
    bool iowait(bool out) const;
    bool __forceinline iotimeo(bool out) const {
	return LIKELY(out ? sbuf->wto == sbuf->kwto : sbuf->rto ==
	    sbuf->krto) || ktimeo(out);
    }
    bool ktimeo(bool out) const;
    ssize_t layerread(iovec *iov, int count) const;
    ssize_t layerwrite(const iovec *iov, int count) const;
    ssize_t rdret(ssize_t in) const;
    // an expired kernel timeout is an error, not an empty read or write
    bool timedout(bool out) const {
	return (out ? sbuf->wto : sbuf->rto) != SOCK_INFINITE && sbuf->blck &&
	    sbuf->err == EAGAIN;
    }
    ssize_t wrret(ssize_t out) const {
	return UNLIKELY(out < 0 && blocked() && !timedout(true)) ? 0 : out;
    }

    SocketBuf *sbuf;

#ifndef _WIN32
private:
    static int pollone(socket_t fd, short events, uint msec);
#endif
};

/*
 * portable fd_set/select() or pollfd/poll() set optimized for very large
 * file descriptor sets
 */
class BLISTER SocketSet {
public:
    explicit SocketSet(uint maxfds = 0);
    SocketSet(const SocketSet &ss) { *this = ss; }
    SocketSet(SocketSet &&ss) noexcept: fds(std::move(ss.fds)),
	maxsz(std::exchange(ss.maxsz, 0U)), sz(std::exchange(ss.sz, 0U)) {}
    ~SocketSet() = default;

    SocketSet &operator =(const SocketSet &ss);
    SocketSet &operator =(SocketSet &&ss) noexcept {
	fds.swap(ss.fds);
	swap(maxsz, ss.maxsz);
	swap(sz, ss.sz);
	return *this;
    }
    template<class C> socket_t operator [](C at) const {
	return SSET_FD((uint)at);
    }

    bool empty(void) const { return sz == 0; }
    bool get(socket_t fd) const { return find(fd) < sz; }
    bool get(const Socket &sock) const { return get(sock.fd()); }
    uint size(void) const { return sz; }

    void clear(void) { sz = 0; }
    bool set(socket_t fd);
    bool set(const Socket &sock) { return set(sock.fd()); }
    bool unset(socket_t fd);
    bool unset(const Socket &sock) { return unset(sock.fd()); }
    // POSIX poll uses per-set scratch; serialize calls on the same set.
    bool ipoll(SocketSet &iset, SocketSet &eset,
	uint msec = SOCK_INFINITE) const;
    bool iopoll(SocketSet &iset, SocketSet &oset, SocketSet &eset,
	uint msec = SOCK_INFINITE) const;
    bool opoll(SocketSet &oset, SocketSet &eset,
	uint msec = SOCK_INFINITE) const;

    static bool iopoll(const SocketSet &rset, SocketSet &iset,
	const SocketSet &wset, SocketSet &oset, SocketSet &eset,
	uint msec = SOCK_INFINITE);

private:
#ifdef _WIN32
    struct FdFree {
	void operator ()(fd_set *p) const { delete [] (socket_t *)p; }
    };
    using fdptr = unique_ptr<fd_set, FdFree>;

    static fdptr alloc(uint n) {
	return fdptr((fd_set *)new socket_t[(size_t)n + 1]);
    }
    fd_set *fdset(void) const {		// fd_count only matters to select()
	fds->fd_count = sz;
	return fds.get();
    }
    uint find(socket_t fd) const {	// vectorized by MSVC STL
	const socket_t *p = fds->fd_array;

	return (uint)(ranges::find(p, p + sz, fd) - p);
    }
#else
    using fdptr = unique_ptr<pollfd[]>;

    static fdptr alloc(uint n) {
	return make_unique_for_overwrite<pollfd[]>(n);
    }
    uint find(socket_t fd) const {
	const pollfd *p = fds.get();

	return (uint)(ranges::find(p, p + sz, fd, &pollfd::fd) - p);
    }
#endif

    fdptr fds;
    uint maxsz = 0, sz = 0;
};

inline SocketSet::SocketSet(uint maxfds): maxsz(maxfds) {
#ifdef _WIN32
    if (!maxsz)
	maxsz = 32;
    fds = alloc(maxsz);
#else
    if (maxsz)
	fds = alloc(maxsz);
#endif
}

inline SocketSet &SocketSet::operator =(const SocketSet &ss) {
    if (&ss != this) {
	sz = ss.sz;
	if (!fds || maxsz < sz) {
	    maxsz = ss.maxsz;
	    fds = alloc(maxsz);
	}
#ifdef _WIN32
	memcpy(fds.get(), ss.fds.get(), ((size_t)sz + 1) * sizeof (socket_t));
#else
	if (sz)
	    memcpy(fds.get(), ss.fds.get(), sz * sizeof (pollfd));
#endif
    }
    return *this;
}

inline bool SocketSet::set(socket_t fd) {
    if (!fds || sz == maxsz) {
	maxsz = maxsz ? maxsz * 2 : 32;

	fdptr p = alloc(maxsz);

	if (fds)
#ifdef _WIN32
	    memcpy(p.get(), fds.get(), ((size_t)sz + 1) * sizeof (socket_t));
#else
	    memcpy(p.get(), fds.get(), sz * sizeof (pollfd));
#endif
	fds = std::move(p);
    }
    SSET_FD(sz++) = fd;
    return true;
}

inline bool SocketSet::unset(socket_t fd) {
    uint u = find(fd);

    if (u == sz)
	return false;
    SSET_FD(u) = SSET_FD(--sz);
    return true;
}

// socket streams

// NOLINTBEGIN(misc-multiple-inheritance)

using socketbuf = faststreambuf<Socket>;

class BLISTER isockstream: public istream {
public:
    explicit isockstream(streamsize sz = SOCK_BUFSZ, char *p = nullptr):
	istream(nullptr), sb(sz, p) { ios::init(&sb); }
    explicit isockstream(const Socket &s, streamsize sz = SOCK_BUFSZ, char *p =
	nullptr): istream(nullptr), sb(s, sz, p) { ios::init(&sb); }

    const char *str(void) const { return sb.str(); }
    void str(char *p, streamsize sz) { sb.setbuf(p, sz); }
    streamsize read(void *p, streamsize sz) { return sb.read(p, sz); }
    template<class C> requires is_trivially_copyable_v<C>
    streamsize read(C &c) { return sb.read(c); }

    socketbuf *rdbuf(void) { return &sb; }
    const socketbuf *rdbuf(void) const { return &sb; }

private:
    socketbuf sb;
};

class BLISTER osockstream: public ostream {
public:
    explicit osockstream(streamsize sz = SOCK_BUFSZ, char *p = nullptr):
	ostream(nullptr), sb(sz, p) { ios::init(&sb); }
    explicit osockstream(const Socket &s, streamsize sz = SOCK_BUFSZ, char *p =
	nullptr): ostream(nullptr), sb(s, sz, p) { ios::init(&sb); }

    const char *str(void) const { return sb.str(); }
    void str(char *p, streamsize sz) { sb.setbuf(p, sz); }
    streamsize write(const void *p, streamsize sz) {
	streamsize n = sb.write(p, sz);

	if (UNLIKELY(n != sz))
	    setstate(ios::badbit);
	return n;
    }
    template<class C> requires is_trivially_copyable_v<C>
    streamsize write(const C &c) { return write(&c, (streamsize)sizeof (c)); }

    socketbuf *rdbuf(void) { return &sb; }
    const socketbuf *rdbuf(void) const { return &sb; }

private:
    socketbuf sb;
};

class BLISTER sockstream: public iostream {
public:
    explicit sockstream(streamsize sz = SOCK_BUFSZ, char *p = nullptr):
	iostream(nullptr), sb(sz, p) { ios::init(&sb); }
    explicit sockstream(const Socket &s, streamsize sz = SOCK_BUFSZ, char *p =
	nullptr): iostream(nullptr), sb(s, sz, p) { ios::init(&sb); }

    const char *str(void) const { return sb.str(); }
    void str(char *p, streamsize sz) { sb.setbuf(p, sz); }
    streamsize read(void *p, streamsize sz) { return sb.read(p, sz); }
    streamsize write(const void *p, streamsize sz) {
	streamsize n = sb.write(p, sz);

	if (UNLIKELY(n != sz))
	    setstate(ios::badbit);
	return n;
    }
    template<class C> requires is_trivially_copyable_v<C>
    streamsize read(C &c) { return sb.read(c); }
    template<class C> requires is_trivially_copyable_v<C>
    streamsize write(const C &c) { return write(&c, (streamsize)sizeof (c)); }

    socketbuf *rdbuf(void) { return &sb; }
    const socketbuf *rdbuf(void) const { return &sb; }

private:
    socketbuf sb;
};

// NOLINTEND(misc-multiple-inheritance)

#endif // Socket_h
