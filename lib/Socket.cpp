/*
 * Copyright 2001-2014 Todd Richmond
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

ushort Sockaddr::families[] = {
    AF_UNSPEC, AF_UNSPEC, AF_INET, AF_INET, AF_INET6, AF_INET6
};

const void *Sockaddr::address(void) const {
    if (family() == AF_INET)
	return &addr.sa4.sin_addr;
    else if (family() == AF_INET6)
	return &addr.sa6.sin6_addr;
    else
	return NULL;
}

const tstring &Sockaddr::host(void) const {
    if (name.empty()) {
	char buf[NI_MAXHOST];

	if (getnameinfo(&addr.sa, sizeof(addr), buf, sizeof (buf), NULL, 0,
	    NI_NAMEREQD))
	    name = str();
	else
	    name = achartotstring(buf);
    }
    return name;
}

const tstring Sockaddr::host_port(void) const {
    tchar buf[12];

    tsprintf(buf, T("%c%u"), ipv4() ? ':' : ';', (uint)port());
    return host() + buf;
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

ushort Sockaddr::port(void) const {
    if (family() == AF_INET)
	return htons(addr.sa4.sin_port);
    else if (family() == AF_INET6)
	return htons(addr.sa6.sin6_port);
    else
	return 0;
}

void Sockaddr::port(ushort port) {
    if (family() == AF_INET)
	addr.sa4.sin_port = htons(port);
    else if (family() == AF_INET6)
	addr.sa6.sin6_port = htons(port);
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
    const tchar *p = NULL;

    if (host && (p = tstrchr(host, ':')) != NULL) {
	const tchar *pp;
	
	if ((pp = tstrchr(p + 1, ':')) != NULL) 
	    p = tstrrchr(pp, ';');
    }
    if (p) {
	tstring s(host);

	s.erase(p - host);
	return set(s.c_str(), p + 1, proto);
    }
    return set(host, (tchar *)NULL, proto);
}

bool Sockaddr::set(const tchar *host, ushort portno, Proto proto) {
    if (portno) {
	tchar portstr[8];

	tsprintf(portstr, T("%u"), (uint)portno);
	return set(host, portstr, proto);
    } else {
	return set(host, (tchar *)NULL, proto);
    }
}

bool Sockaddr::set(const tchar *host, const tchar *service, Proto proto) {
    struct addrinfo *ai, hints;

    ZERO(addr);
    name.erase();
    ZERO(hints);
    hints.ai_family = families[proto];
    hints.ai_socktype = dgram(proto) ? SOCK_DGRAM : SOCK_STREAM;
    if (!host || !*host || *host == '*') {
	host = NULL;
	hints.ai_flags = AI_PASSIVE;
    } else if (istdigit(*host)) {
	hints.ai_flags = AI_NUMERICHOST;
    } else {
	hints.ai_flags = AI_CANONNAME;
    }
    hints.ai_flags |= AI_ADDRCONFIG | AI_V4MAPPED;
    if (getaddrinfo(host ? tchartoachar(host) : NULL, service ?
	tchartoachar(service) : NULL, &hints, &ai))
	return false;
    set(ai);
    freeaddrinfo(ai);
    return true;
}

bool Sockaddr::set(const hostent *h) {
    ZERO(addr);
    memcpy((void *)address(), h->h_addr, h->h_length);
    family(h->h_addrtype);
    name = achartotstring(h->h_name);
    return true;
}

bool Sockaddr::set(const sockaddr &sa) {
    if (sa.sa_family == AF_INET)
	addr.sa4 = (const sockaddr_in &)sa;
    else if (sa.sa_family == AF_INET6)
	addr.sa6 = (const sockaddr_in6 &)sa;
    else
	return false;
    return true;
}

const tstring Sockaddr::service_name(ushort port, Proto proto) {
    char buf[NI_MAXSERV];
    Sockaddr sa(NULL, port, proto);

    if (getnameinfo(sa, sa.size(), NULL, 0, buf, sizeof (buf), dgram(proto) ?
	NI_DGRAM : 0)) {
	tchar pbuf[8];

	tsprintf(pbuf, T("%u"), (uint)port);
	return pbuf;
    }
    return achartotstring(buf);
}

ushort Sockaddr::service_port(const tchar *svc, Proto proto) {
    Sockaddr sa;

    return sa.set(NULL, svc, proto) ? sa.port() : 0;
}

ushort Sockaddr::size(ushort family) {
    if (family == AF_INET)
	return sizeof (sockaddr_in);
    else if (family == AF_INET6)
	return sizeof (sockaddr_in6);
    else
	return sizeof (sockaddr_any);
}

const tstring Sockaddr::str(void) const {
    // XP does not implement inet_ntop so implment for all cases
    // inet_ntop(family(), address(), buf, sizeof (buf));
    if (family() == AF_INET) {
	return achartotstring(inet_ntoa(addr.sa4.sin_addr));
    } else if (family() == AF_INET6) {
	int i;
	struct { int base, len; } best, cur;
	char buf[INET6_ADDRSTRLEN + 1], *p = buf;
	const int WORDS = sizeof (addr.sa6.sin6_addr) / sizeof (ushort);
	uint words[WORDS];

	ZERO(best);
	ZERO(cur);
	ZERO(words);
	best.base = -1;
	cur.base = -1;
	for (i = 0; i < WORDS; i++) {
	    if (words[i] == 0) {
		if (cur.base == -1)
		    cur.base = i, cur.len = 1;
		else
		    cur.len++;
	    } else {
		if (cur.base != -1) {
		    if (best.base == -1 || cur.len > best.len)
			best = cur;
		    cur.base = -1;
		}
	    }
	}
	if (cur.base != -1 && (best.base == -1 || cur.len > best.len))
	    best = cur;
	if (best.base != -1 && best.len < 2)
	    best.base = -1;
	for (i = 0; i < WORDS; i++) {
	    if (best.base != -1 && i >= best.base && i < best.base + best.len) {
		if (i == best.base)
		    *p++ = ':';
		continue;
	    }
	    if (i != 0)
		*p++ = ':';
	    if (i == 6 && best.base == 0 &&
		(best.len == 6 || (best.len == 5 && words[5] == 0xffff))) {
		const uchar *u = (const uchar *)&addr.sa6.sin6_addr + 12;
		p += sprintf(p, "%u.%u.%u.%u", u[0], u[1], u[2], u[3]);
		break;
	    }
	    p += sprintf(p, "%x", words[i]);
	}
	if (best.base != -1 && (best.base + best.len) == WORDS)
	    *p++ = ':';
	*p++ = '\0';
	return achartotstring(buf);
    }
    return T("");
}


#define BUILD_IP(ip) ((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3])
#define VALID_IP(ip) (ip[0] < 256 && ip[1] < 256 && ip[2] < 256 && ip[3] < 256)

bool CIDR::add(const tchar *addrs) {
    size_t sz = ranges.size();

    while (addrs) {
	uint ip1[4], ip2[4];
	int maskbits = 32;
	Range range;
	const tchar *p = addrs;

	if (tstrchr(addrs, '/') && (tsscanf(addrs, T("%3u.%3u.%3u.%3u/%2d"),
	    &ip1[0], &ip1[1], &ip1[2], &ip1[3], &maskbits) == 5) &&
	    VALID_IP(ip1) && maskbits >= 1 && maskbits <= 32) {
	    range.rmin = BUILD_IP(ip1) & ~((1 << (32 - maskbits)) - 1);
	    range.rmax = range.rmin | ((1 << (32 - maskbits)) - 1);
	    ranges.push_back(range);
	} else if (tstrchr(addrs, '-') && (tsscanf(addrs,
	    T("%3u.%3u.%3u.%3u-%3u.%3u.%3u.%3u"), &ip1[0], &ip1[1], &ip1[2],
	    &ip1[3], &ip2[0], &ip2[1], &ip2[2], &ip2[3]) == 8) &&
	    VALID_IP(ip1) && VALID_IP(ip2)) {
	    range.rmin = BUILD_IP(ip1);
	    range.rmax = BUILD_IP(ip2);
	    if (range.rmax >= range.rmin)
		ranges.push_back(range);
	} else if ((tsscanf(addrs, T("%3u.%3u.%3u.%3u"), &ip1[0], &ip1[1],
	    &ip1[2], &ip1[3]) == 4) && VALID_IP(ip1)) {
	    range.rmin = range.rmax = BUILD_IP(ip1);
	    ranges.push_back(range);
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
    if (sbuf == r.sbuf || &r == this)
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
    return check(::bind(sbuf->sock, sa, sa.size()));
}

bool Socket::connect(const Sockaddr &sa, uint msec) {
    bool ret = false;

    if (!*this && !open(sa.family()))
	return false;
    if (msec != SOCK_INFINITE)
	blocking(false);
    if (check(::connect(sbuf->sock, (sockaddr *)(const sockaddr *)sa,
	sa.size()))) {
	ret = true;
    } else if (blocked() && msec > 0 && msec != SOCK_INFINITE) {
	SocketSet sset(1), oset(1), eset(1);

	sset.set(sbuf->sock);
	ret = sset.opoll(oset, eset, msec) && oset.get(sbuf->sock);
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
    if (sbuf->sock <= 1024) {
	int fd = fcntl(sbuf->sock, F_DUPFD_CLOEXEC, 1025);

	if (fd == -1
#ifdef __sun__				// Solaris stdio has lower 256 limit
	    || (fd = fcntl(sbuf->sock, F_DUPFD_CLOEXEC, 257)) == -1
#endif
	    ) {
	    return false;
	} else if (fd != sbuf->sock) {
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

bool Socket::cork(void) const {
#ifdef TCP_CORK
    return getsockopt(IPPROTO_TCP, TCP_CORK) != 0;
#elif defined(TCP_NOPUSH)
    return getsockopt(IPPROTO_TCP, TCP_NOPUSH) != 0;
#else
    return true;
#endif
}

bool Socket::cork(bool on) {
#ifdef TCP_CORK
    return setsockopt(IPPROTO_TCP, TCP_CORK, on) != 0;
#elif defined(TCP_NOPUSH)
    return setsockopt(IPPROTO_TCP, TCP_NOPUSH, on) != 0;
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

#ifdef linux
#include <linux/netfilter_ipv4.h>

bool Socket::proxysockname(Sockaddr &sa) {
    return check(getsockopt(SOL_IP, SO_ORIGINAL_DST, *(sockaddr *)sa.data()));
}
#endif

bool Socket::sockname(Sockaddr &sa) {
    socklen_t sz = sa.size();

    return check(getsockname(sbuf->sock, sa.data(), &sz));
}

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
    check(WSASend(sbuf->sock, (WSABUF *)iov, count, (ulong *)&out, 0, NULL,
	NULL));
#else
    do {
	if (check((int)(out = ::writev(sbuf->sock, iov, count))))
	    break;
    } while (interrupted());
#endif
    return blocked() ? 0 : out;
}

long Socket::writev(const iovec *iov, int count, const Sockaddr &sa) const {
    long out;

#ifdef _WIN32
    check(WSASendTo(sbuf->sock, (WSABUF *)iov, count, (ulong *)&out, 0, sa,
	sa.size(), NULL, NULL));
    return blocked() ? 0 : out;
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
    struct timeval tv = { msec / 1000, (msec % 1000) * 1000 };

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
    ret = poll(fds, sz, msec);
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
    struct timeval tv = { msec / 1000, (msec % 1000) * 1000 };

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
    ret = poll(fds, sz, msec);
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
    struct timeval tv = { msec / 1000, (msec % 1000) * 1000 };

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
    ret = poll(fds, sz, msec);
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
    struct timeval tv = { msec / 1000, (msec % 1000) * 1000 };

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
    ret = ro ? poll(rset.fds, rset.sz, msec) : poll(sset.fds, sset.sz, msec);
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

