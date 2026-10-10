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

#include "stdapi.h"
#include <fcntl.h>
#include <algorithm>
#include <unordered_map>
#include "Socket.h"

#ifdef _WIN32
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4389)

Sockaddr::SockInit Sockaddr::init;

#else

#include <sys/ioctl.h>
#include <sys/stat.h>
#ifdef __sun__
#include <sys/filio.h>
#endif

#endif

const void *Sockaddr::address(void) const {
    switch (family()) {
    case AF_INET: return &addr.sa4.sin_addr;
    case AF_INET6: return &addr.sa6.sin6_addr;
    case AF_UNIX: return &addr.sau;
    default: return &addr.sa;
    }
}

const tstring &Sockaddr::host(void) const {
    if (family() == AF_UNIX && name.empty()) {
	name = T("unix:");
	name += achartotstring(path());
    }
    if (name.empty()) {
	char buf[NI_MAXHOST];

	if (getnameinfo(&addr.sa, sizeof (addr), buf, sizeof (buf), NULL, 0,
	    NI_NAMEREQD))
	    name = ip();
	else
	    name = achartotstring(buf);
    }
    return name;
}

addrinfo *Sockaddr::getaddrinfo(const tchar *host, const tchar *service, Proto
    proto) {
    struct addrinfo *ai, hints;

    ZERO(hints);
    hints.ai_family = families[proto];
    if (!host || !*host || *host == '*' || !tstricmp(host, T("IN6ADDR_ANY"))) {
	hints.ai_family = proto == TCP || proto == TCP4 || proto == TCP6 ?
	    families[TCP6] : families[UDP6];
	hints.ai_flags = AI_PASSIVE;
	host = nullptr;
    } else if (!tstricmp(host, T("INADDR_ANY"))) {
	hints.ai_family = proto == TCP || proto == TCP4 ? families[TCP4] :
	    families[UDP4];
	hints.ai_flags = AI_PASSIVE;
	host = nullptr;
    } else if (istdigit(*host)) {
	hints.ai_flags = AI_NUMERICHOST;
    } else {
	hints.ai_flags = AI_CANONNAME | AI_ADDRCONFIG;
	if (!tstrnicmp(host, T("ipv4:"), 5)) {
	    hints.ai_family = families[TCP4];
	    host += 5;
	} else if (!tstrnicmp(host, T("ipv6:"), 5)) {
	    hints.ai_family = families[TCP6];
	    host += 5;
	}
    }
    hints.ai_flags |= AI_V4MAPPED;
    if (service && istdigit(*service))
	hints.ai_flags |= AI_NUMERICSERV;
    hints.ai_socktype = dgram(proto) ? SOCK_DGRAM : SOCK_STREAM;
    return ::getaddrinfo(host ? tchartoachar(host) : NULL, service ?
	tchartoachar(service) : NULL, &hints, &ai) ? NULL : ai;
}

const tstring &Sockaddr::hostname() {
    static const tstring hname = [] {
	char buf[NI_MAXHOST];

	if (gethostname(buf, sizeof (buf))) {
#ifdef _WIN32
	    ulong sz = sizeof (buf);

	    GetComputerName((tchar *)buf, &sz);
	    return tstring((tchar *)buf);
#else
	    return tstring(T("localhost"));
#endif
	}
	return Sockaddr(achartotstring(buf).c_str()).host();
    }();

    return hname;
}

tstring Sockaddr::ip(void) const {
    ushort fam = family();

    if (fam == AF_INET) {
	char buf[INET_ADDRSTRLEN];

	return achartotstring(inet_ntop(fam, &addr.sa4.sin_addr, buf, sizeof
	    (buf)));
    } else if (fam == AF_INET6) {
	char buf[INET6_ADDRSTRLEN];
	const char *s = inet_ntop(fam, &addr.sa6.sin6_addr, buf, sizeof (buf));

	return achartotstring(v4mapped() ? s + 7 : s);
    } else {
	return T("");
    }
}

ushort Sockaddr::port(void) const {
    switch (family()) {
    case AF_INET: return htons(addr.sa4.sin_port);
    case AF_INET6: return htons(addr.sa6.sin6_port);
    default: return 0;
    }
}

void Sockaddr::port(ushort port) {
    switch (family()) {
    case AF_INET: addr.sa4.sin_port = htons(port); break;
    case AF_INET6: addr.sa6.sin6_port = htons(port); break;
    default: break;
    }
}

Sockaddr::Proto Sockaddr::proto(void) const {
    switch (family()) {
    case AF_INET: return TCP4;
    case AF_INET6: return TCP6;
    case AF_UNIX: return UNIX;
    default: return UNSPEC;
    }
}

bool Sockaddr::service(const tchar *service, Proto proto) {
    Sockaddr sa;

    if (sa.set(nullptr, service, proto)) {
	port(sa.port());
	return true;
    } else {
	return false;
    }
}

bool Sockaddr::set(const addrinfo *ai) {
    family((sa_family_t)ai->ai_family);
    memcpy(&addr.sa, ai->ai_addr, ai->ai_addrlen);
    memset((char *)&addr.sa + ai->ai_addrlen, 0, sizeof (addr) -
	ai->ai_addrlen);
    if (ai->ai_canonname)
	name = achartotstring(ai->ai_canonname);
    else if ((family() == AF_INET && addr.sa4.sin_addr.s_addr == INADDR_ANY) ||
	(family() == AF_INET6 && !memcmp(&addr.sa6.sin6_addr,	// NOSONAR
	&in6addr_any, sizeof (in6addr_any))))
	name = T("*");
    else
	name.erase();
    return true;
}

bool Sockaddr::set(const tchar *host, Proto proto) {
    const tchar *p;
    tstring s;

    if (host && !tstrncmp(host, T("unix:"), 5))
	return set(host, (const tchar *)nullptr, proto);
    if (!host) {
	p = nullptr;
    } else if (*host == ':' && host[1] == ':') {
	if ((p = tstrchr(host + 2, ':')) != nullptr) {
	    s.assign(host, (tstring::size_type)(p - host));
	    host = s.c_str();
	}
    } else if (*host == '[') {
	if ((p = tstrchr(host, ']')) == nullptr) {
	    family(AF_UNSPEC);
	    return false;
	}
	s.assign(host + 1, (tstring::size_type)(p - host - 1));
	host = s.c_str();
	p = tstrchr(p, ':');
    } else if ((p = tstrrchr(host, ':')) != nullptr) {
	s.assign(host, (tstring::size_type)(p - host));
	if (s == T("unix"))
	    p = nullptr;
	else
	    host = s.c_str();
    }
    return set(host, p ? p + 1 : nullptr, proto);
}

bool Sockaddr::set(const tchar *host, ushort portno, Proto proto) {
    if (portno) {
	tchar portstr[8];

	to_str(portstr, portstr + 8, portno);
	return set(host, portstr, proto);
    } else {
	return set(host, (tchar *)nullptr, proto);
    }
}

bool Sockaddr::set(const tchar *host, const tchar *service, Proto proto) {
    ZERO(addr);
    family(AF_UNSPEC);
    name.erase();
    if (host && !tstrncmp(host, T("unix:"), 5)) {
	host += 5;
	proto = UNIX;
    }
    if (host && (proto == UNIX || tstrchr(host, '/'))) {
	const uint sz = sizeof (addr.sau.sun_path);
	const string path = tchartoachar(host);
#ifdef __linux__	// anonymous file support
	const uint anon = !tstrchr(host, '/');
#else
	const uint anon = 0;
#endif

	if (path.length() + anon >= sz)
	    return false;
	addr.sau.sun_family = AF_UNIX;
#ifdef BSD_BASE
	addr.sau.sun_len = (uint8_t)sizeof (addr.sau);
#endif
	strncpy(addr.sau.sun_path + anon, path.c_str(), sz - anon - 1);
	return true;
    }
    addrinfo *ai = getaddrinfo(host, service, proto);

    if (!ai)
	return false;
    set(ai);
    freeaddrinfo(ai);
    return true;
}

bool Sockaddr::set(const hostent *h) {
    ZERO(addr);
    family((sa_family_t)h->h_addrtype);
    memcpy((void *)address(), h->h_addr, (size_t)h->h_length);	// NOSONAR
    name = achartotstring(h->h_name);
    return true;
}

bool Sockaddr::set(const sockaddr &sa) {
    sockaddr_any tmp;

    ZERO(tmp);
    switch (sa.sa_family) {
    case AF_INET: tmp.sa4 = (const sockaddr_in &)sa; break;
    case AF_INET6: tmp.sa6 = (const sockaddr_in6 &)sa; break;
    case AF_UNIX: tmp.sau = (const sockaddr_un &)sa; break;
    default: tmp.sa = sa; break;
    }
    addr = tmp;
    name.clear();
    return true;
}

tstring Sockaddr::service_name(ushort port, Proto proto) {
    char buf[NI_MAXSERV];
    Sockaddr sa(nullptr, port, proto);

    if (getnameinfo(sa, sa.size(), NULL, 0, buf, sizeof (buf), dgram(proto) ?
	NI_DGRAM : 0)) {
	tchar pbuf[8];

	tsprintf(pbuf, T("%hu"), port);
	return pbuf;
    }
    return achartotstring(buf);
}

ushort Sockaddr::service_port(const tchar *svc, Proto proto) {
    Sockaddr sa;

    return sa.set(nullptr, svc, proto) ? sa.port() : (ushort)0;
}

ushort Sockaddr::size(ushort family) {
    switch (family) {
    case AF_INET: return sizeof (sockaddr_in);
    case AF_INET6: return sizeof (sockaddr_in6);
    case AF_UNIX: return sizeof (sockaddr_un);
    default: return sizeof (sockaddr_any);
    }
}

tstring Sockaddr::str(const tstring &val) const {
    tchar buf[12];
    ushort p = port();

    if (!p)
	return val;
    tsprintf(buf, T(":%hu"), p);
    if (!val.contains(':')) {
	return val + buf;
    } else {
	tstring s(T("["));

	s += val;
	s += ']';
	s += buf;
	return s;
    }
}

bool SockaddrList::insert(const tchar *host, ushort port, Sockaddr::Proto
    proto) {
    tchar buf[8];

    tsprintf(buf, T("%hu"), port);
    return insert(host, buf, proto);
}

bool SockaddrList::insert(const tchar *host, const tchar *service,
    Sockaddr::Proto proto) {
    addrinfo *ai = Sockaddr::getaddrinfo(host, service, proto);

    if (!ai)
	return false;
    for (const addrinfo *elem = ai; elem; elem = elem->ai_next)
	insert(Sockaddr(elem));
    freeaddrinfo(ai);
    return true;
}

// parse a dotted quad with up to 3 digits per octet
static bool parse_ip(const tchar *&p, uint32_t &ip) {
    uint32_t v = 0;

    for (int i = 0; i < 4; i++) {
	int n = 0;
	uint32_t o = 0;

	if (i) {
	    if (*p != '.')
		return false;
	    p++;
	}
	for (; n < 3 && istdigit(*p); n++)
	    o = o * 10 + (uint32_t)(*p++ - '0');
	if (!n || o > 255)
	    return false;
	v = v << 8 | o;
    }
    ip = v;
    return true;
}

bool CIDR::add(const tchar *addrs) {
    static constexpr tchar delims[] = T(",; \t\r\n");
    size_t sz = ranges.size();

    while (addrs && *addrs) {
	const tchar *p = addrs;
	uint32_t lo = 0, hi;
	bool ok = parse_ip(p, lo);

	hi = lo;
	if (ok && *p == '/') {
	    uint maskbits = 0;
	    int n = 0;

	    for (p++; n < 2 && istdigit(*p); n++)
		maskbits = maskbits * 10 + (uint)(*p++ - '0');
	    ok = n && maskbits >= 1 && maskbits <= 32;
	    if (ok) {
		uint32_t host = maskbits == 32 ? 0 : 0xFFFFFFFFU >> maskbits;

		hi = lo | host;
		lo &= ~host;
	    }
	} else if (ok && *p == '-') {
	    p++;
	    ok = parse_ip(p, hi) && hi >= lo;
	}
	if (ok && *p && !tstrchr(delims, *p))
	    ok = false;
	if (ok)
	    ranges.push_back({lo, hi});
	addrs += tstrcspn(addrs, delims);
	addrs += tstrspn(addrs, delims);
    }
    if (ranges.size() == sz)
	return false;
    ranges::sort(ranges);

    size_t n = 0;

    for (size_t i = 1; i < ranges.size(); i++) {
	if ((uint64_t)ranges[i].rmin <= (uint64_t)ranges[n].rmax + 1)
	    ranges[n].rmax = max(ranges[n].rmax, ranges[i].rmax);
	else
	    ranges[++n] = ranges[i];
    }
    ranges.resize(n + 1);
    return true;
}

bool CIDR::find(const tchar *addr) const {
    uint32_t ip;

    return parse_ip(addr, ip) && find(ip);
}

bool CIDR::find(uint addr) const {
    auto it = ranges::upper_bound(ranges, addr, ranges::less{}, &Range::rmin);

    return it != ranges.begin() && addr <= (--it)->rmax;
}

Socket &Socket::operator =(socket_t sock) {
    int type = sbuf->type;

    if (sbuf->release())
	sbuf->reset(type, sock);
    else
	sbuf = new SocketBuf(type, sock, false);
    return *this;
}

Socket &Socket::operator =(const Socket &r) {
    if (this == &r || sbuf == r.sbuf)
	return *this;
    if (sbuf->release())
	delete sbuf;
    sbuf = r.sbuf;
    sbuf->reference();
    return *this;
}

Socket &Socket::operator =(Socket &&r) noexcept {
    if (this == &r)
	return *this;

    SocketBuf *old = sbuf;

    sbuf = r.sbuf;
    if (old->release()) {
	old->reset(sbuf->type, SOCK_INVALID);
	old->own = true;
	r.sbuf = old;
    } else {
	r.sbuf = new SocketBuf(sbuf->type, SOCK_INVALID, true);
    }
    return *this;
}

bool Socket::accept(Socket &sock, bool _cloexec, bool nonblock) {
    sock.close();
    do {
#ifdef __linux__
	socket_t fd = ::accept4(sbuf->sock, NULL, NULL, (_cloexec ?
	    SOCK_CLOEXEC : 0) | (nonblock ? SOCK_NONBLOCK : 0));
#else
	socket_t fd = ::accept(sbuf->sock, NULL, NULL);
#endif

	sock.sbuf->sock = fd;
	if (LIKELY(check(fd == SOCK_INVALID ? -1 : 0))) {
	    sock.sbuf->type = sbuf->type;
	    sock.sbuf->own = true;
	    sock.sbuf->blck = !nonblock;
#ifdef SO_NOSIGPIPE
	    (void)sock.setsockopt(SOL_SOCKET, SO_NOSIGPIPE, true);
#endif
#ifndef __linux__
	    if (_cloexec)
		sock.cloexec();
	    if (nonblock)
		sock.blocking(false);
#endif
	    return true;
	}
    } while (interrupted());
    return false;
}

// socket file left behind by a crashed process
static bool stalesock(const char *path) {
#ifdef _WIN32
#ifndef IO_REPARSE_TAG_AF_UNIX
#define IO_REPARSE_TAG_AF_UNIX	0x80000023L
#endif
    WIN32_FIND_DATAA fd;
    HANDLE h = FindFirstFileA(path, &fd);

    if (h == INVALID_HANDLE_VALUE)
	return false;
    FindClose(h);
    return (fd.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) &&
	fd.dwReserved0 == (DWORD)IO_REPARSE_TAG_AF_UNIX;
#else
    struct stat st;

    return !::stat(path, &st) && S_ISSOCK(st.st_mode);
#endif
}

bool Socket::bind(const Sockaddr &sa, bool reuse) {
    if (!*this && !open(sa.family()))
	return false;
    if (reuse && sa.proto() != Sockaddr::UNIX && !reuseaddr(true))
	return false;
    if (sa.proto() == Sockaddr::UNIX &&
	((const sockaddr_un *)sa)->sun_path[0]) {
	// remove a stale socket file left by a crashed process
	if (stalesock(sa.path()))
	    (void)::unlink(sa.path());
	sbuf->unlink(sa.path());
    }
    return check(::bind(sbuf->sock, sa, sa.size()));
}

bool Socket::connect(const Sockaddr &sa, uint msec) {
    bool ret = false;

    if (!*this && !open(sa.family()))
	return false;

    const bool timed = msec != SOCK_INFINITE && sbuf->blck;

    if (timed)
	blocking(false);
    if (check(::connect(sbuf->sock, sa, sa.size()))) {
	ret = true;
    } else if (blocked() && msec > 0 && msec != SOCK_INFINITE) {
	SocketSet sset(1), oset(1), eset(1);

	sset.set(sbuf->sock);
	if (!sset.opoll(oset, eset, msec)) {
	    sbuf->err = sockerrno();
	} else if (oset.get(sbuf->sock) || eset.get(sbuf->sock)) {
	    int err = 0;

	    if (getsockopt(SOL_SOCKET, SO_ERROR, err)) {
		sbuf->err = err;
		ret = !err;
	    }
	} else {
	    sbuf->err = WSAETIMEDOUT;
	}
    }
    if (timed) {
	int e = sbuf->err;

	blocking(true);
	sbuf->err = e;
    }
    return ret;
}

tstring Socket::errstr(void) const {
    if (sbuf->err == EOF)
	return T("socket EOF");

#ifdef _WIN32
    tchar buf[32];

    tsprintf(buf, T("socket err %d"), sbuf->err);
    return buf;
#else
    return tstrerror(sbuf->err);
#endif
}

bool Socket::listen(int queue) {
    return check(::listen(sbuf->sock, queue));
}

bool Socket::movehigh(void) {
#ifndef _WIN32
    if (sbuf->sock > 2 && sbuf->sock < 1024) {
	int fd;

#ifdef F_DUPFD_CLOEXEC
	fd = fcntl(sbuf->sock, F_DUPFD_CLOEXEC, 1024);
#else
	fd = fcntl(sbuf->sock, F_DUPFD, 1024);
#endif
#ifdef __sun__				// Solaris stdio has lower 256 limit
	if (fd == -1)
	    fd = fcntl(sbuf->sock, F_DUPFD_CLOEXEC, 256);
#endif
	if (fd == -1) {
	    (void)fcntl(sbuf->sock, F_SETFD, FD_CLOEXEC);
	} else {
#ifndef F_DUPFD_CLOEXEC
	    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
	    ::closesocket(sbuf->sock);
	    sbuf->sock = fd;
	}
    }
#endif
    return true;
}

bool Socket::open(int family) {
    close();
    sbuf->sock = ::socket(family, sbuf->type, 0);
    sbuf->own = true;
    sbuf->blck = true;
    if (!check(sbuf->sock == SOCK_INVALID ? -1 : 0))
	return false;
#ifdef SO_NOSIGPIPE
    (void)setsockopt(SOL_SOCKET, SO_NOSIGPIPE, true);
#endif
    return true;
}

bool Socket::shutdown(bool in, bool out) {
    return check(::shutdown(sbuf->sock, in && out ? 2 : (in ? 0 : 1)));
}

bool Socket::blocking(bool on) {
    ulong mode = on ? 0 : 1;

    if (!check(ioctlsocket(sbuf->sock, FIONBIO, &mode)))
	return false;
    sbuf->blck = on;
    return true;
}

bool Socket::cloexec(void) {
#ifdef _WIN32
    return true;
#else
    return fcntl(sbuf->sock, F_SETFD, FD_CLOEXEC) != -1;
#endif
}

#ifdef TCP_CORK
#define CORK_VAL TCP_CORK
#elif defined(TCP_NOPUSH)
#define CORK_VAL TCP_NOPUSH
#endif

bool Socket::cork(void) const {
#ifdef CORK_VAL
    int i;

    return getsockopt(IPPROTO_TCP, CORK_VAL, i) && i != 0;
#else
    return true;
#endif
}

bool Socket::cork(bool on) {
#ifdef CORK_VAL
    return setsockopt(IPPROTO_TCP, CORK_VAL, on);
#else
    (void)on;
    return true;
#endif
}

bool Socket::linger(ushort sec) {
    struct linger lg;

    if (sec == (ushort)-1) {
	lg.l_onoff = 0;
	lg.l_linger = 0;
    } else {
	lg.l_onoff = 1;
	lg.l_linger = sec;
    }
    return setsockopt(SOL_SOCKET, SO_LINGER, lg);
}

bool Socket::loopback(void) const {
#ifdef SO_USELOOPBACK
    int i;

    return getsockopt(SOL_SOCKET, SO_USELOOPBACK, i) && i != 0;
#else
    return true;
#endif
}

bool Socket::loopback(bool on) {
#ifdef SO_USELOOPBACK
    return setsockopt(SOL_SOCKET, SO_USELOOPBACK, on);
#else
    (void)on;
    return true;
#endif
}

bool Socket::peername(Sockaddr &sa) {
    socklen_t sz = sa.size();

    return check(getpeername(sbuf->sock, sa.data(), &sz));
}

#ifdef __linux__
#include <linux/netfilter_ipv4.h>

bool Socket::proxysockname(Sockaddr &sa) {
    return getsockopt(SOL_IP, SO_ORIGINAL_DST, *sa.data());
}
#endif

// wait for the socket to become readable/writable within rto/wto
bool Socket::iowait(bool out) const {
    const uint msec = out ? sbuf->wto : sbuf->rto;
#ifdef _WIN32
    SocketSet sset(1), ioset(1), eset(1);

    sset.set(sbuf->sock);
    if ((out ? sset.opoll(ioset, eset, msec) : sset.ipoll(ioset, eset, msec)) &&
	!ioset.empty())
	return true;
#else
    pollfd p{sbuf->sock, (short)(out ? POLLOUT : POLLIN), 0};
    msec_t end = mticks() + msec;
    int left = (int)min(msec, (uint)INT_MAX);

    for (;;) {
	int ret = poll(&p, 1, left);

	if (ret > 0)
	    return true;
	if (ret < 0 && !::interrupted(errno)) {
	    sbuf->err = errno;
	    return false;
	}
	if (ret == 0)
	    break;

	msec_t now = mticks();

	if (now >= end)
	    break;
	left = (int)min<msec_t>(end - now, INT_MAX);
    }
#endif
    sbuf->err = WSAEWOULDBLOCK;
    return false;
}

long Socket::rdret(long in) const {
    if (LIKELY(in > 0))
	return in;
    if (in)
	return blocked() ? 0 : in;
    if (!stream())
	return 0;
    sbuf->err = EOF;
    return -1;
}

int Socket::read(void *buf, uint sz) const {
    int in;

    do {
	if (UNLIKELY(sbuf->rto != SOCK_INFINITE && blocking()) && !iowait(false))
	    return -1;
	if (check(in = (int)recv(sbuf->sock, (char *)buf, (SOCK_SIZE_T)sz, 0)))
	    break;
    } while (interrupted());
    return (int)rdret(in);
}

int Socket::read(void *buf, uint sz, Sockaddr &sa) const {
    socklen_t asz = sa.size();
    int in;

    do {
	if (UNLIKELY(sbuf->rto != SOCK_INFINITE && blocking()) && !iowait(false))
	    return -1;
	if (check(in = (int)recvfrom(sbuf->sock, (char *)buf, (SOCK_SIZE_T)sz,
	    0, sa.data(), &asz)))
	    break;
    } while (interrupted());
    return (int)rdret(in);
}

long Socket::readv(iovec *iov, int count) const {
    long in;

    do {
	if (UNLIKELY(sbuf->rto != SOCK_INFINITE && blocking()) && !iowait(false))
	    return -1;
#ifdef _WIN32
	ulong flags = 0;

	in = -1;
	if (check(WSARecv(sbuf->sock, iov, (ulong)count, (ulong *)&in, // NOSONAR
	    &flags, NULL, NULL)))
	    break;
#else
	if (check((int)(in = ::readv(sbuf->sock, iov, count))))
	    break;
#endif
    } while (interrupted());
    return rdret(in);
}

long Socket::readv(iovec *iov, int count, Sockaddr &sa) const {
    long in;

    do {
	if (UNLIKELY(sbuf->rto != SOCK_INFINITE && blocking()) && !iowait(false))
	    return -1;
#ifdef _WIN32
	ulong flags = 0;
	int asz = sa.size();

	in = -1;
	if (check(WSARecvFrom(sbuf->sock, iov, (ulong)count, // NOSONAR
	    (ulong *)&in, &flags, sa.data(), &asz, NULL, NULL)))
	    break;
#else
	msghdr msgh {};

	msgh.msg_name = sa.data();
	msgh.msg_namelen = sa.size();
	msgh.msg_iov = iov;
#ifdef BSD_BASE
	msgh.msg_iovlen = count;
#else
	msgh.msg_iovlen = (size_t)count;
#endif
	if (check((int)(in = ::recvmsg(sbuf->sock, &msgh, 0))))
	    break;
#endif
    } while (interrupted());
    return rdret(in);
}

#ifndef _WIN32
long Socket::sendmsg(const msghdr &msgh, int flags) const {
    long out;

    do {
	if (check((int)(out = ::sendmsg(sbuf->sock, &msgh, flags))))
	    break;
    } while (interrupted());
    return out <= 0 && blocked() ? 0 : out;
}
#endif

bool Socket::sockname(Sockaddr &sa) {
    socklen_t sz = sa.size();

    return check(getsockname(sbuf->sock, sa.data(), &sz));
}

int Socket::write(const void *buf, uint sz) const {
    int out;

    do {
	if (UNLIKELY(sbuf->wto != SOCK_INFINITE && blocking()) && !iowait(true))
	    return -1;
	if (check(out = (int)send(sbuf->sock, (const char *)buf,
	    (SOCK_SIZE_T)sz, 0)))
	    break;
    } while (interrupted());
    return UNLIKELY(out < 0 && blocked()) ? 0 : out;
}

int Socket::write(const void *buf, uint sz, const Sockaddr &sa) const {
    int out;

    do {
	if (UNLIKELY(sbuf->wto != SOCK_INFINITE && blocking()) && !iowait(true))
	    return -1;
	if (check(out = (int)sendto(sbuf->sock, (const char *)buf,
	    (SOCK_SIZE_T)sz, 0, sa, sa.size())))
	    break;
    } while (interrupted());
    return UNLIKELY(out < 0 && blocked()) ? 0 : out;
}

long Socket::writev(const iovec *iov, int count) const {
    long out;

#ifdef _WIN32
    out = -1;
    check(WSASend(sbuf->sock, (iovec *)iov, count, (ulong *)&out, 0, // NOSONAR
	NULL, NULL));
#else
    do {
	if (check((int)(out = ::writev(sbuf->sock, iov, count))))
	    break;
    } while (interrupted());
#endif
    return out <= 0 && blocked() ? 0 : out;
}

long Socket::writev(const iovec *iov, int count, const Sockaddr &sa) const {
#ifdef _WIN32
    long out = -1;

    check(WSASendTo(sbuf->sock, (iovec *)iov, count, (ulong *)&out, // NOSONAR
	0, sa, sa.size(), NULL, NULL));
    return out <= 0 && blocked() ? 0 : out;
#else
    msghdr msgh {};

    msgh.msg_name = (void *)(const sockaddr *)sa;	// NOSONAR
    msgh.msg_namelen = sa.size();
    msgh.msg_iov = (iovec *)iov;			// NOSONAR
#ifdef BSD_BASE
    msgh.msg_iovlen = count;
#else
    msgh.msg_iovlen = (size_t)count;
#endif
    return sendmsg(msgh, 0);
#endif
}

bool SocketSet::ipoll(SocketSet &iset, SocketSet &eset, uint msec) {
#ifdef _WIN32
    struct timeval tv = { (long)(msec / 1000), long((msec % 1000) * 1000) };

    fds->fd_count = sz;
    eset = iset = *this;
    if (select(0, iset.fds.get(), NULL, eset.fds.get(),
	msec == SOCK_INFINITE ? NULL : &tv) == -1)
	return false;
    iset.sz = iset.fds->fd_count;
    eset.sz = eset.fds->fd_count;
    return true;
#else
    int ret;
    uint u;

    for (u = 0; u < sz; u++)
	fds[u].events = POLLIN;
    iset.clear();
    eset.clear();
    ret = poll(fds.get(), sz, (int)msec);
    if (ret <= 0)
	return ret == 0 || (!msec && interrupted(sockerrno()));
    for (u = 0; u < sz; u++) {
	if (fds[u].revents & POLLIN)
	    iset.set(fds[u].fd);
	if (fds[u].revents & (POLLERR | POLLHUP))
	    eset.set(fds[u].fd);
    }
    return true;
#endif
}

bool SocketSet::opoll(SocketSet &oset, SocketSet &eset, uint msec) {
#ifdef _WIN32
    struct timeval tv = { (long)(msec / 1000), (long)((msec % 1000) * 1000) };

    fds->fd_count = sz;
    eset = oset = *this;
    if (select(0, NULL, oset.fds.get(), eset.fds.get(),
	msec == SOCK_INFINITE ? NULL : &tv) == -1)
	return false;
    oset.sz = oset.fds->fd_count;
    eset.sz = eset.fds->fd_count;
    return true;
#else
    int ret;
    uint u;

    for (u = 0; u < sz; u++)
	fds[u].events = POLLOUT;
    oset.clear();
    eset.clear();
    ret = poll(fds.get(), sz, (int)msec);
    if (ret <= 0)
	return ret == 0 || (!msec && interrupted(sockerrno()));
    for (u = 0; u < sz; u++) {
	if (fds[u].revents & POLLOUT)
	    oset.set(fds[u].fd);
	else if (fds[u].revents & (POLLERR | POLLHUP))
	    eset.set(fds[u].fd);
    }
    return true;
#endif
}

bool SocketSet::iopoll(SocketSet &iset, SocketSet &oset, SocketSet &eset,
    uint msec) {
#ifdef _WIN32
    struct timeval tv = { (long)(msec / 1000), (long)((msec % 1000) * 1000) };

    fds->fd_count = sz;
    eset = iset = oset = *this;
    if (select(0, iset.fds.get(), oset.fds.get(), eset.fds.get(),
	msec == SOCK_INFINITE ? NULL : &tv) == -1)
	return false;
    iset.sz = iset.fds->fd_count;
    oset.sz = oset.fds->fd_count;
    eset.sz = eset.fds->fd_count;
    return true;
#else
    int ret;
    uint u;

    for (u = 0; u < sz; u++)
	fds[u].events = POLLIN | POLLOUT;
    iset.clear();
    oset.clear();
    eset.clear();
    ret = poll(fds.get(), sz, (int)msec);
    if (ret <= 0)
	return ret == 0 || (!msec && interrupted(sockerrno()));
    for (u = 0; u < sz; u++) {
	if (fds[u].revents & POLLIN)
	    iset.set(fds[u].fd);
	if (fds[u].revents & POLLOUT)
	    oset.set(fds[u].fd);
	if (fds[u].revents & (POLLERR | POLLHUP))
	    eset.set(fds[u].fd);
    }
    return true;
#endif
}

bool SocketSet::iopoll(const SocketSet &rset, SocketSet &iset,
    const SocketSet &wset, SocketSet &oset, SocketSet &eset, uint msec) {
    uint u;
#ifdef _WIN32
    struct timeval tv = { (long)(msec / 1000), (long)((msec % 1000) * 1000) };

    rset.fds->fd_count = rset.sz;
    wset.fds->fd_count = wset.sz;
    eset = iset = rset;
    oset = wset;
    for (u = 0; u < oset.sz; u++) {
	if (!eset.set(oset[u]))
	    eset.set(oset[u]);
    }
    if (select(0, iset.fds.get(), oset.fds.get(), eset.fds.get(),
	msec == SOCK_INFINITE ? NULL : &tv) == -1)
	return false;
    iset.sz = iset.fds->fd_count;
    oset.sz = oset.fds->fd_count;
    eset.sz = eset.fds->fd_count;
    return true;
#else
    int ret;
    SocketSet sset;
    bool ro = true;
    const bool hashed = (size_t)rset.sz * wset.sz > 256;
    unordered_map<socket_t, uint> idx;

    if (hashed) {
	idx.reserve(rset.sz);
	for (u = 0; u < rset.sz; u++)
	    idx.emplace(rset[u], u);
    }
    for (u = 0; u < rset.sz; u++)
	rset.fds[u].events = POLLIN;
    for (u = 0; u < wset.sz; u++) {
	uint uu = rset.sz;

	if (hashed) {
	    auto it = idx.find(wset[u]);

	    if (it != idx.end())
		uu = it->second;
	} else {
	    for (uu = 0; uu < rset.sz && rset[uu] != wset[u]; uu++)
		;
	}
	if (uu < rset.sz) {
	    (ro ? rset : sset).fds[uu].events |= POLLOUT;
	} else {
	    if (ro) {
		ro = false;
		sset = rset;
	    }
	    sset.set(wset[u]);
	    sset.fds[sset.size() - 1].events = POLLOUT;
	}
    }
    iset.clear();
    oset.clear();
    eset.clear();
    ret = ro ? poll(rset.fds.get(), rset.sz, (int)msec) :
	poll(sset.fds.get(), sset.sz, (int)msec);
    if (ret <= 0)
	return ret == 0 || (!msec && interrupted(sockerrno()));
    if (ro) {
	for (u = 0; u < rset.sz; u++) {
	    if (rset.fds[u].revents & POLLIN)
		iset.set(rset.fds[u].fd);
	    if (rset.fds[u].revents & (POLLERR | POLLHUP))
		eset.set(rset.fds[u].fd);
	}
    } else {
	for (u = 0; u < sset.sz; u++) {
	    if (sset.fds[u].revents & POLLIN)
		iset.set(sset.fds[u].fd);
	    if (sset.fds[u].revents & POLLOUT)
		oset.set(sset.fds[u].fd);
	    if (sset.fds[u].revents & (POLLERR | POLLHUP))
		eset.set(sset.fds[u].fd);
	}
    }
    return true;
#endif
}

