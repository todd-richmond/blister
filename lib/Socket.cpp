/*
 * Copyright 2001-2023 Todd Richmond
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
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <algorithm>
#include "Socket.h"

#ifdef _WIN32
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma warning(disable: 4389)

Sockaddr::SockInit Sockaddr::init;

#else

#include <sys/ioctl.h>
#ifdef __sun__
#include <sys/filio.h>
#endif

#endif

sa_family_t Sockaddr::families[] = {
    AF_UNSPEC, AF_UNSPEC, AF_INET, AF_INET, AF_INET6, AF_INET6, AF_UNIX,
    AF_UNSPEC
};

const void *Sockaddr::address(void) const {
    switch (family()) {
	case AF_INET: return &addr.sa4.sin_addr;
	case AF_INET6: return &addr.sa6.sin6_addr;
#ifndef _WIN32
	case AF_UNIX: return &addr.sau;
#endif
	default: return &addr.sa;
    }
}

const tstring &Sockaddr::host(void) const {
#ifndef _WIN32
    if (family() == AF_UNIX) {
	name = "unix:";
	name += *addr.sau.sun_path ? addr.sau.sun_path : addr.sau.sun_path + 1;
    }
#endif
    if (name.empty()) {
	char buf[NI_MAXHOST];

	if (getnameinfo(&addr.sa, sizeof (addr), buf, sizeof (buf), NULL, 0,
	    NI_NAMEREQD))
	    name = ipstr();
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
	host = NULL;
    } else if (!tstricmp(host, T("INADDR_ANY"))) {
	hints.ai_family = proto == TCP || proto == TCP4 ? families[TCP4] :
	    families[UDP4];
	hints.ai_flags = AI_PASSIVE;
	host = NULL;
    } else if (istdigit(*host)) {
	hints.ai_flags = AI_NUMERICHOST;
    } else {
	hints.ai_flags = AI_CANONNAME;
	 if (!tstrnicmp(host, T("ipv4:"), 5)) {
	    hints.ai_family = families[TCP4];
	    host += 5;
	} else if (!tstrnicmp(host, T("ipv6:"), 5)) {
	    hints.ai_family = families[TCP6];
	    host += 5;
	}
    }
    hints.ai_flags |= AI_ADDRCONFIG | AI_V4MAPPED;
    if (service && istdigit(*service))
	hints.ai_flags |= AI_NUMERICSERV;
    hints.ai_socktype = dgram(proto) ? SOCK_DGRAM : SOCK_STREAM;
    return ::getaddrinfo(host ? tchartoachar(host) : NULL, service ?
	tchartoachar(service) : NULL, &hints, &ai) ? NULL : ai;
}

const tstring &Sockaddr::hostname() {
    static tstring hname;

    if (hname.empty()) {
	char buf[NI_MAXHOST];

	if (gethostname(buf, sizeof (buf))) {
#ifdef _WIN32
	    tchar cbuf[NI_MAXHOST];
	    ulong sz = sizeof (buf);

	    GetComputerName(cbuf, &sz);
	    hname = cbuf;
#else
	    hname = T("localhost");
#endif
	} else {
	    Sockaddr sa(achartotstring(buf).c_str());

	    hname = sa.host();
	}
    }
    return hname;
}

const tstring Sockaddr::ip(void) const {
    ushort fam = family();

    if (fam == AF_INET) {
	char buf[INET_ADDRSTRLEN];

	return achartotstring(inet_ntop(fam, &addr.sa4.sin_addr, buf, sizeof
	    (buf)));
    } else if (fam  == AF_INET6) {
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
    }
}

Sockaddr::Proto Sockaddr::proto(void) const {
    switch (family()) {
    case AF_INET: return TCP4;
    case AF_INET6: return TCP6;
#ifndef _WIN32
    case AF_UNIX: return UNIX;
#endif
    default: return UNSPEC;
    }
}

bool Sockaddr::service(const tchar *service, Proto proto) {
    Sockaddr sa;

    if (sa.set(NULL, service, proto)) {
	port(sa.port());
	return true;
    } else {
	return false;
    }
}

bool Sockaddr::set(const addrinfo *ai) {
    memcpy(&addr.sa, ai->ai_addr, ai->ai_addrlen);
    memset((char *)&addr.sa + ai->ai_addrlen, 0, sizeof (addr) - ai->ai_addrlen);
    if (ai->ai_canonname)
	name = achartotstring(ai->ai_canonname);
    else if ((family() == AF_INET && addr.sa4.sin_addr.s_addr == INADDR_ANY) ||
	(family() == AF_INET6 && !memcmp(&addr.sa6.sin6_addr, &in6addr_any,
	sizeof (in6addr_any))))
	name = T("*");
    else
	name.erase();
    return true;
}

bool Sockaddr::set(const tchar *host, Proto proto) {
    const tchar *p;
    tstring s;

    if (!host) {
	p = NULL;
    } else if (*host == ':' && host[1] == ':') {
	if ((p = tstrchr(host + 2, ':')) != NULL) {
	    s.assign(host, (tstring::size_type)(p - host));
	    host = s.c_str();
	}
    } else if (*host == '[') {
	if ((p = tstrchr(host, ']')) == NULL)
	    return false;
	s.assign(host + 1, (tstring::size_type)(p - host - 1));
	host = s.c_str();
	p = tstrchr(p, ':');
    } else if ((p = tstrchr(host, ':')) != NULL) {
	s.assign(host, (tstring::size_type)(p - host));
	if (s == T("unix"))
	    p = NULL;
	else
	    host = s.c_str();
    }
    return set(host, p ? p + 1 : NULL, proto);
}

bool Sockaddr::set(const tchar *host, ushort portno, Proto proto) {
    if (portno) {
	tchar portstr[8];

	tsprintf(portstr, T("%u"), portno);
	return set(host, portstr, proto);
    } else {
	return set(host, (tchar *)NULL, proto);
    }
}

bool Sockaddr::set(const tchar *host, const tchar *service, Proto proto) {
    ZERO(addr);
    name.erase();
#ifndef _WIN32
    if (host && !tstrncmp(host, "unix:", 5)) {
	host += 5;
	proto = UNIX;
    }
    if (host && (proto == UNIX || tstrchr(host, '/'))) {
	const uint sz = sizeof (addr.sau.sun_path);

	addr.sau.sun_family = AF_UNIX;
#ifdef __linux__	// anonymous file support
	if (tstrchr(host, '/')) {
	    strncpy(addr.sau.sun_path, host, sz);
	} else {
	    addr.sau.sun_path[0] = '\0';
	    strncpy(addr.sau.sun_path + 1, host, sz - 1);
	}
#else
	strncpy(addr.sau.sun_path, host, sz);
#endif
	addr.sau.sun_path[sz - 1] = '\0';
	return true;
    }
#endif
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
    memcpy((void *)address(), h->h_addr, (size_t)h->h_length);
    name = achartotstring(h->h_name);
    return true;
}

bool Sockaddr::set(const sockaddr &sa) {
    switch (sa.sa_family) {
	case AF_INET: addr.sa4 = (const sockaddr_in &)sa; break;
	case AF_INET6: addr.sa6 = (const sockaddr_in6 &)sa; break;
#ifndef _WIN32
	case AF_UNIX: addr.sau = (const sockaddr_un &)sa; break;
#endif
	default: addr.sa = sa; break;
    }
    return true;
}

const tstring Sockaddr::service_name(ushort port, Proto proto) {
    char buf[NI_MAXSERV];
    Sockaddr sa(NULL, port, proto);

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

    return sa.set(NULL, svc, proto) ? sa.port() : (ushort)0;
}

ushort Sockaddr::size(ushort family) {
    switch (family) {
    case AF_INET: return sizeof (sockaddr_in);
    case AF_INET6: return sizeof (sockaddr_in6);
#ifndef _WIN32
    case AF_UNIX: return sizeof (sockaddr_un);
#endif
    default: return sizeof (sockaddr_any);
    }
}

const tstring Sockaddr::str(const tstring &val) const {
    tchar buf[12];
    ushort p = port();

    if (!p)
	return val;
    tsprintf(buf, T(":%hu"), p);
    if (val.find(':') == val.npos) {
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
    for (addrinfo *elem = ai; elem; elem = elem->ai_next)
	insert(Sockaddr(elem));
    freeaddrinfo(ai);
    return true;
}

#define BUILD_IP(ip) ((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3])
#define VALID_IP(ip) (ip[0] < 256 && ip[1] < 256 && ip[2] < 256 && ip[3] < 256)

bool CIDR::add(const tchar *addrs) {
    size_t sz = ranges.size();

    while (addrs) {
	uint ip1[4], ip2[4];
	uint maskbits = 32;
	Range range;
	const tchar *p = addrs;

	if (tstrchr(addrs, '/') && (tsscanf(addrs, T("%3u.%3u.%3u.%3u/%2u"),
	    &ip1[0], &ip1[1], &ip1[2], &ip1[3], &maskbits) == 5) &&
	    VALID_IP(ip1) && maskbits >= 1 && maskbits <= 32) {
	    range.rmin = BUILD_IP(ip1) & (~((1UL << (32U - maskbits)) - 1U) &
		0xFFFFFFFFUL);
	    range.rmax = range.rmin | (((1UL << (32U - maskbits)) - 1U) &
		0xFFFFFFFFUL);
	    ranges.emplace_back(range);
	} else if (tstrchr(addrs, '-') && (tsscanf(addrs,
	    T("%3u.%3u.%3u.%3u-%3u.%3u.%3u.%3u"), &ip1[0], &ip1[1], &ip1[2],
	    &ip1[3], &ip2[0], &ip2[1], &ip2[2], &ip2[3]) == 8) &&
	    VALID_IP(ip1) && VALID_IP(ip2)) {
	    range.rmin = BUILD_IP(ip1);
	    range.rmax = BUILD_IP(ip2);
	    if (range.rmax >= range.rmin)
		ranges.emplace_back(range);
	} else if ((tsscanf(addrs, T("%3u.%3u.%3u.%3u"), &ip1[0], &ip1[1],
	    &ip1[2], &ip1[3]) == 4) && VALID_IP(ip1)) {
	    range.rmin = range.rmax = BUILD_IP(ip1);
	    ranges.emplace_back(range);
	}
	if ((addrs = tstrchr(p, ',')) != NULL ||
	    (addrs = tstrchr(p, ';')) != NULL ||
	    (addrs = tstrchr(p, ' ')) != NULL)
	    addrs++;
    }
    if (ranges.size() != sz) {
	sort(ranges.begin(), ranges.end());
	return true;
    } else {
	return false;
    }
}

bool CIDR::find(const tchar *addr) const {
    uint ip[4];

    return tsscanf(addr, T("%3u.%3u.%3u.%3u"), &ip[0], &ip[1], &ip[2], &ip[3])
	== 4 && VALID_IP(ip) && find(BUILD_IP(ip));
}

bool CIDR::find(uint addr) const {
    vector<Range>::const_iterator it;
    Range range;

    range.rmin = range.rmax = addr;
    for (it = lower_bound(ranges.begin(), ranges.end(), range, range);
	it != ranges.end(); ++it) {
	const Range &r = *it;

	if (r.rmin > range.rmin)
	    break;
	else if (range.rmax <= r.rmax)
	    return true;
    }
    return false;
}

Socket &Socket::operator =(socket_t sock) {
    int type = sbuf->type;

    if (--sbuf->count == 0)
	delete sbuf;
    sbuf = new SocketBuf(type, sock, false);
    return *this;
}

Socket &Socket::operator =(const Socket &r) {
    if (this == &r || sbuf == r.sbuf)
	return *this;
    if (--sbuf->count == 0)
	delete sbuf;
    sbuf = r.sbuf;
    sbuf->count++;
    return *this;
}

bool Socket::accept(Socket &sock) {
    Sockaddr sa;
    socklen_t sz = sa.size();

    sock.close();
    do {
	if (check((sock.sbuf->sock = ::accept(sbuf->sock, sa.data(), &sz)) ==
	    SOCK_INVALID ? -1 : 0)) {
	    sock.sbuf->type = sbuf->type;
	    return true;
	}
    } while (interrupted());
    return false;
}

bool Socket::bind(const Sockaddr &sa, bool reuse) {
    if (!*this && !open(sa.family()))
	return false;
    if (reuse && !reuseaddr(true))
	return false;
#ifndef _WIN32
    if (sa.proto() == Sockaddr::UNIX)
	sbuf->unlink(sa.path());
#endif
    return check(::bind(sbuf->sock, sa, sa.size()));
}

bool Socket::connect(const Sockaddr &sa, uint msec) {
    bool ret = false;

    if (!*this && !open(sa.family()))
	return false;
    if (msec != SOCK_INFINITE)
	blocking(false);
    if (check(::connect(sbuf->sock, sa, sa.size()))) {
	ret = true;
    } else if (blocked() && msec > 0 && msec != SOCK_INFINITE) {
	int err = 0;
	SocketSet sset(1), oset(1), eset(1);

	sset.set(sbuf->sock);
	ret = sset.opoll(oset, eset, msec) && oset.get(sbuf->sock);
	if (ret && check(getsockopt(SOL_SOCKET, SO_ERROR, err))) {
	    sbuf->err = err;
	    ret = !err;
	}
    }
    if (msec != SOCK_INFINITE) {
	int e = sbuf->err;

	blocking(true);
	sbuf->err = e;
    }
    return ret;
}

const tstring Socket::errstr(void) const {
    if (sbuf->err == EOF)
	return T("socket EOF");

#ifdef WIN32
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
    return check((sbuf->sock = ::socket(family, sbuf->type, 0)) ==
	SOCK_INVALID ? -1 : 0);
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

#if defined(TCP_CORK)
#define CORK_VAL TCP_CORK
#elif defined(TCP_NOPUSH)
#define CORK_VAL TCP_NOPUSH
#endif

bool Socket::cork(void) const {
#ifdef CORK_VAL
    return getsockopt(IPPROTO_TCP, CORK_VAL) != 0;
#else
    return true;
#endif
}

bool Socket::cork(bool on) {
#ifdef CORK_VAL
    return setsockopt(IPPROTO_TCP, CORK_VAL, on) != 0;
#else
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

bool Socket::peername(Sockaddr &sa) {
    socklen_t sz = sa.size();

    return check(getpeername(sbuf->sock, sa.data(), &sz));
}

#ifdef __linux__
#include <linux/netfilter_ipv4.h>

bool Socket::proxysockname(Sockaddr &sa) {
    return check(getsockopt(SOL_IP, SO_ORIGINAL_DST, *(sockaddr *)sa.data()));
}
#endif

bool Socket::rwpoll(bool rd) const {
    uint msec = rd ? sbuf->rto : sbuf->wto;

    if (msec == SOCK_INFINITE || !blocking())
	return true;

    bool ret;
    SocketSet sset(1), ioset(1), eset(1);

    sset.set(sbuf->sock);
    ret = (rd ? sset.ipoll(ioset, eset, msec) :
	sset.opoll(ioset, eset, msec)) && !ioset.empty();
    if (!ret)
	sbuf->err = WSAEWOULDBLOCK;
    return ret;
}

int Socket::read(void *buf, uint sz) const {
    int in;

    do {
	if (!rwpoll(true))
	    return -1;
#ifdef __APPLE__
	if (check(in = (int)::read(sbuf->sock, (char *)buf, (SOCK_SIZE_T)sz)))
	    break;
#else
	if (check(in = (int)recv(sbuf->sock, (char *)buf, (SOCK_SIZE_T)sz, 0)))
	    break;
#endif
    } while (interrupted());
    if (in) {
	return in <= 0 && blocked() ? 0 : in;
    } else {
	sbuf->err = EOF;
	return -1;
    }
}

int Socket::read(void *buf, uint sz, Sockaddr &sa) const {
    socklen_t asz = sa.size();
    int in;

    do {
	if (!rwpoll(true))
	    return -1;
	if (check(in = (int)recvfrom(sbuf->sock, (char *)buf, (SOCK_SIZE_T)sz,
	    0, sa.data(), &asz)))
	    break;
    } while (interrupted());
    if (in) {
	return in <= 0 && blocked() ? 0 : in;
    } else {
	sbuf->err = EOF;
	return -1;
    }
}

#ifndef _WIN32
long Socket::sendmsg(const msghdr &msgh, int flags) const {
    int out;

    do {
	if (check(out = (int)::sendmsg(sbuf->sock, &msgh, flags)))
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
	if (!rwpoll(false))
	    return -1;
#ifdef __APPLE__
	if (check(out = (int)::write(sbuf->sock, (const char *)buf,
	    (SOCK_SIZE_T)sz)))
	    break;
#else
	if (check(out = (int)send(sbuf->sock, (const char *)buf,
	    (SOCK_SIZE_T)sz, 0)))
	    break;
#endif
    } while (interrupted());
    return out <= 0 && blocked() ? 0 : out;
}

int Socket::write(const void *buf, uint sz, const Sockaddr &sa) const {
    int out;

    do {
	if (!rwpoll(false))
	    return -1;
	if (check(out = (int)sendto(sbuf->sock, (const char *)buf,
	    (SOCK_SIZE_T)sz, 0, sa, sa.size())))
	    break;
    } while (interrupted());
    return out <= 0 && blocked() ? 0 : out;
}

long Socket::writev(const iovec *iov, int count) const {
    long out;

#ifdef _WIN32
    out = -1;
    check(WSASend(sbuf->sock, (iovec *)iov, count, (ulong *)&out, 0, NULL,
	NULL));
#else
    do {
	if (check((int)(out = ::writev(sbuf->sock, iov, count))))
	    break;
    } while (interrupted());
#endif
    return out <= 0 && blocked() ? 0 : out;
}

long Socket::writev(const iovec *iov, int count, const Sockaddr &sa) const {
    long out;

#ifdef _WIN32
    out = -1;
    check(WSASendTo(sbuf->sock, (iovec *)iov, count, (ulong *)&out, 0, sa,
	sa.size(), NULL, NULL));
    return out <= 0 && blocked() ? 0 : out;
#else
    out = 0;
    for (int i = 0; i < count; i++) {
	if (iov[i].iov_len) {
	    int len = write(iov[i].iov_base, (uint)iov[i].iov_len, sa);

	    if (len != (int)iov[i].iov_len) {
		if (len > 0)
		    out += (uint)len;
		else if (!out && !blocked())
		    return -1;
		break;
	    }
	}
    }
    return out;
#endif
}

bool SocketSet::ipoll(SocketSet &iset, SocketSet &eset, uint msec) {
#ifdef _WIN32
    struct timeval tv = { (long)(msec / 1000), long((msec % 1000) * 1000) };

    fds->fd_count = sz;
    eset = iset = *this;
    if (select(0, iset.fds, NULL, eset.fds, msec == SOCK_INFINITE ? NULL :
	&tv) == -1)
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
    ret = poll(fds, sz, (int)msec);
    if (ret <= 0)
	return ret == 0 || (!msec && errno == EINTR);
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
    if (select(0, NULL, oset.fds, eset.fds, msec == SOCK_INFINITE ? NULL :
	&tv) == -1)
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
    ret = poll(fds, sz, (int)msec);
    if (ret <= 0)
	return ret == 0 || (!msec && errno == EINTR);
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
    if (select(0, iset.fds, oset.fds, eset.fds, msec == SOCK_INFINITE ? NULL :
	&tv) == -1)
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
    ret = poll(fds, sz, (int)msec);
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
    if (select(0, iset.fds, oset.fds, eset.fds, msec == SOCK_INFINITE ? NULL :
	&tv) == -1)
	return false;
    iset.sz = iset.fds->fd_count;
    oset.sz = oset.fds->fd_count;
    eset.sz = eset.fds->fd_count;
    return true;
#else
    int ret;
    SocketSet sset;
    uint uu;
    bool ro = true;

    for (u = 0; u < rset.sz; u++)
	rset.fds[u].events = POLLIN;
    for (u = 0; u < wset.sz; u++) {
	for (uu = 0; uu < rset.sz; uu++) {
	    if (ro && rset[uu] == wset[u]) {
		rset.fds[uu].events |= POLLOUT;
		break;
	    } else if (!ro && sset[uu] == wset[u]) {
		sset.fds[uu].events |= POLLOUT;
		break;
	    }
	}
	if (uu == rset.sz) {
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
    ret = ro ? poll(rset.fds, rset.sz, (int)msec) : poll(sset.fds, sset.sz,
	(int)msec);
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

