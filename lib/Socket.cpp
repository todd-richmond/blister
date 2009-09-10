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

#include "stdapi.h"
#include <ctype.h>
#include <errno.h>
#ifndef _WIN32_WCE
#include <fcntl.h>
#endif
#include <algorithm>
#include "Socket.h"

#ifdef _WIN32
#ifdef _WIN32_WCE
#pragma comment(lib, "winsock.lib")
#else
#pragma comment(lib, "mswsock.lib")
#pragma comment(lib, "ws2_32.lib")
#endif
#pragma warning(disable: 4389)

#define SIZE_T int
Sockaddr::SockInit Sockaddr::init;

#else

#include <sys/ioctl.h>
#ifdef __sun__
#include <sys/filio.h>
#endif

#define SIZE_T size_t
#define ioctlsocket ioctl

#endif

ushort Sockaddr::families[] = {
    AF_UNSPEC, AF_UNSPEC, AF_INET, AF_INET, AF_INET6, AF_INET6
};

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

const tstring &Sockaddr::hostname() {
    static tstring name;

    if (name.empty()) {
	char buf[NI_MAXHOST];
	ulong sz = sizeof (buf);

	if (gethostname(buf, sz)) {
#if defined(_WIN32) && !defined(_WIN32_WCE)
	    tchar tbuf[65];

	    GetComputerName(tbuf, &sz);
	    name = tbuf;
#else
	    name = T("localhost");
#endif
	} else {
	    Sockaddr sa(achartotstring(buf).c_str());
	    
	    name = sa.host();
	}
    }
    return name;
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

bool Sockaddr::set(const addrinfo *ai) {
    static in6_addr in6_any;

    memcpy(&addr.sa, ai->ai_addr, ai->ai_addrlen);
    if (ai->ai_canonname)
	name = achartotstring(ai->ai_canonname);
    else if ((family() == AF_INET && addr.sa4.sin_addr.s_addr == INADDR_ANY) ||
	(family() == AF_INET6 && !memcmp(&addr.sa6.sin6_addr, &in6_any,
	sizeof (in6_any))))
	name = T("*");
    else
	name.erase();
    return true;
}

bool Sockaddr::set(const tchar *host, Proto proto) {
    const tchar *p, *pp;

    if ((p = tstrchr(host, ':')) != NULL) {
	if ((pp = tstrchr(p + 1, ':')) != NULL) 
	    p = tstrrchr(pp, ';');
    }
    if (p) {
	tstring s(host);

	s.erase(p - host);
	return set(s.c_str(), (ushort)tstrtoul(p + 1, NULL, 10), proto);
    }
    return set(host, (ushort)0, proto);
}

bool Sockaddr::set(const tchar *host, ushort portno, Proto proto) {
    struct addrinfo *ai, hints;
    char portstr[8];

    ZERO(addr);
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
    hints.ai_flags |= AI_V4MAPPED;
    name.erase();
    sprintf(portstr, "%u", (unsigned)portno);
    if (getaddrinfo(host ? tchartoachar(host) : NULL, portstr, &hints, &ai))
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
    uint len;

    if (sa.sa_family == AF_INET)
	len = sizeof (sockaddr_in);
    else if (sa.sa_family == AF_INET6)
	len = sizeof (sockaddr_in6);
    else
	return false;
    memcpy(&addr.sa, &sa, len);
    memset((char *)&addr.sa + len, 0, sizeof (addr) - len);
    return true;
}

bool Sockaddr::service(const tchar *service, Proto proto) {
    struct addrinfo *ai, hints;

    ZERO(hints);
    hints.ai_family = families[proto];
    hints.ai_socktype = dgram(proto) ? SOCK_DGRAM : SOCK_STREAM;
    if (getaddrinfo(NULL, tchartoachar(service), &hints, &ai))
	return false;
    family((ushort)hints.ai_family);
    if (family() == AF_INET)
	port(htons(((sockaddr_in *)ai->ai_addr)->sin_port));
    else if (family() == AF_INET6)
	port(htons(((sockaddr_in6 *)ai->ai_addr)->sin6_port));
    freeaddrinfo(ai);
    return true;
}

const tstring Sockaddr::service_name(ushort port, Proto proto) {
    char buf[NI_MAXSERV];
    Sockaddr sa(NULL, port, proto);

    if (getnameinfo(sa, sa.size(), NULL, 0, buf, sizeof (buf), dgram(proto) ?
	NI_DGRAM : 0)) {
	tchar buf[8];

	tsprintf(buf, T("%u"), (uint)port);
	return buf;
    }
    return achartotstring(buf);
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
	const uchar *u = (const uchar *)&addr.sa6.sin6_addr;
	const int WORDS = sizeof (addr.sa6.sin6_addr) / sizeof (ushort);
	uint words[WORDS];

	ZERO(best);
	ZERO(cur);
	ZERO(words);
	for (i = 0; i < (int)sizeof (addr.sa6.sin6_addr); i++)
	    words[i / 2] |= (u[i] << ((1 - (i % 2)) << 3));
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
		u = (const uchar *)&addr.sa6.sin6_addr + 12;
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
    uint ip1[4], ip2[4];
    int maskbits = 32;
    const tchar *p;
    Range range;
    size_t sz = ranges.size();

    while (addrs) {
	if (tstrchr(addrs, '/') && (tsscanf(addrs, T("%u.%u.%u.%u/%d"), &ip1[0],
	    &ip1[1], &ip1[2], &ip1[3], &maskbits) == 5) && VALID_IP(ip1) &&
	    maskbits >= 1 && maskbits <= 32) {
	    range.min = BUILD_IP(ip1) & (~((1 << (32 - maskbits)) - 1) &
		0xFFFFFFFF);
	    range.max = range.min | (((1 << (32 - maskbits)) - 1) & 0xFFFFFFFF);
	    ranges.push_back(range);
	} else if (tstrchr(addrs, '-') && (tsscanf(addrs,
	    T("%u.%u.%u.%u-%u.%u.%u.%u"), &ip1[0], &ip1[1], &ip1[2], &ip1[3],
	    &ip2[0], &ip2[1], &ip2[2], &ip2[3]) == 8) &&
	    VALID_IP(ip1) && VALID_IP(ip2)) {
	    range.min = BUILD_IP(ip1);
	    range.max = BUILD_IP(ip2);
	    if (range.max >= range.min)
		ranges.push_back(range);
	} else if ((tsscanf(addrs, T("%u.%u.%u.%u"), &ip1[0], &ip1[1], &ip1[2],
	    &ip1[3]) == 4) && VALID_IP(ip1)) {
	    range.min = range.max = BUILD_IP(ip1);
	    ranges.push_back(range);
	}
	p = addrs;
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

    return tsscanf(addr, T("%u.%u.%u.%u"), &ip[0], &ip[1], &ip[2], &ip[3]) ==
	4 && VALID_IP(ip) && find(BUILD_IP(ip));
}

bool CIDR::find(uint addr) const {
    vector<Range>::const_iterator it;
    Range range;

    range.min = range.max = addr;
    for (it = lower_bound(ranges.begin(), ranges.end(), range, range);
	it != ranges.end() && it->min <= range.min; it++) {
	if (range.max <= it->max)
	    return true;
    }
    return false;
}

const Socket &Socket::operator =(socket_t sock) {
    int type = sbuf->type;

    if (--sbuf->count == 0)
	delete sbuf;
    sbuf = new SocketBuf(type, sock, false);
    return *this;
}


const Socket &Socket::operator =(const Socket &r) {
    if (sbuf == r.sbuf)
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
	if (check((sock.sbuf->sock = movehigh(::accept(sbuf->sock, sa.data(),
	    &sz))) == SOCK_INVALID ? -1 : 0)) {
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

bool Socket::connect(const Sockaddr &sa, ulong timeout) {
    bool ret = false;

    if (!*this && !open(sa.family()))
	return false;
    if (timeout != SOCK_INFINITE)
	blocking(false);
    if (check(::connect(sbuf->sock, (sockaddr *)(const sockaddr *)sa,
	sa.size()))) {
	ret = true;
    } else if (blocked() && (timeout > 0 && timeout != SOCK_INFINITE)) {
	SocketSet sset(1), oset(1), eset(1);

	sset.set(sbuf->sock);
	ret = sset.oselect(oset, eset, timeout) && oset.get(sbuf->sock);
    }
    if (timeout != SOCK_INFINITE) {
	int e = sbuf->err;

	blocking(true);
	sbuf->err = e;
    }
    return ret;
}

const tstring Socket::errstr(void) const {
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

socket_t Socket::movehigh(socket_t fd) {
#ifndef _WIN32
    if (fd > 2 && fd < 1024) {
	int newfd = fcntl(fd, F_DUPFD, 1024);

	if (newfd >= 0) {
	    ::closesocket(fd);
	    return newfd;
#ifdef __sun__				// Solaris stdio has lower 256 limit
	} else if ((newfd = fcntl(sbuf->sock, F_DUPFD, 256)) >= 0) {
	    ::closesocket(fd);
	    return newfd;
#endif
	}
    }
#endif
    return fd;
}

bool Socket::open(int family) {
    close();
    return check((sbuf->sock = movehigh(::socket(family, sbuf->type,
	0))) == SOCK_INVALID ? -1 : 0);
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
    ulong msec = rd ? sbuf->rto : sbuf->wto;
    bool ret;

    if (msec == SOCK_INFINITE || !blocking())
	return true;

    SocketSet sset(1), ioset(1), eset(1);

    sset.set(sbuf->sock);
    ret = (rd ? sset.iselect(ioset, eset, msec) :
	sset.oselect(ioset, eset, msec)) && !ioset.empty();
    if (!ret)
	sbuf->err = EAGAIN;
    return ret;
}

int Socket::read(void *buf, size_t sz) const {
    int in;

    do {
	if (!rwpoll(true))
	    return -1;
	check(in = recv(sbuf->sock, (char *)buf, (SIZE_T)sz, 0));
    } while (interrupted());
    if (in) {
	return blocked() ? 0 : in;
    } else {
	sbuf->err = EOF;
	return -1;
    }
}

int Socket::read(void *buf, size_t sz, Sockaddr &sa) const {
    socklen_t asz = sa.size();
    int in;
    
    do {
	if (!rwpoll(true))
	    return -1;
	check(in = recvfrom(sbuf->sock, (char *)buf, (SIZE_T)sz, 0, sa.data(),
	    &asz));
    } while (interrupted());
    if (in) {
	return blocked() ? 0 : in;
    } else {
	sbuf->err = EOF;
	return -1;
    }
}

int Socket::write(const void *buf, size_t sz) const {
    int out;

    do {
	if (!rwpoll(false))
	    return -1;
	check(out = send(sbuf->sock, (const char *)buf, (SIZE_T)sz, 0));
    } while (interrupted());
    return blocked() ? 0 : out;
}

int Socket::write(const void *buf, size_t sz, const Sockaddr &sa) const {
    int out;
    
    do {
	if (!rwpoll(false))
	    return -1;
	check(out = sendto(sbuf->sock, (const char *)buf, (SIZE_T)sz, 0, sa,
	    sa.size()));
    } while (interrupted());
    return blocked() ? 0 : out;
}

long Socket::writev(const iovec *iov, int count) const {
    long out;

#ifdef _WIN32_WCE
    out = 0;
    for (int i = 0; i < count; i++) {
	if (iov[i].iov_len) {
	    long len = write(iov[i].iov_base, iov[i].iov_len);

	    if (len != iov[i].iov_len) {
		if (len > 0)
		    out += len;
		else if (!out && !blocked())
		    return -1;
		break;
	    }
	}
    }
    return out;
#elif defined(_WIN32)
    check(WSASend(sbuf->sock, (WSABUF *)iov, count, (ulong *)&out, 0, NULL,
	NULL));
    return blocked() ? 0 : out;
#else
    do {
	check(out = ::writev(sbuf->sock, iov, count));
    } while (interrupted());
    return blocked() ? 0 : out;
#endif
}

long Socket::writev(const iovec *iov, int count, const Sockaddr &sa) const {
    long out;

#if defined(_WIN32) && !defined(_WIN32_WCE)
    check(WSASendTo(sbuf->sock, (WSABUF *)iov, count, (ulong *)&out, 0, sa,
	sa.size(), NULL, NULL));
    return blocked() ? 0 : out;
#else
    out = 0;
    for (int i = 0; i < count; i++) {
	if (iov[i].iov_len) {
	    long len = write(iov[i].iov_base, iov[i].iov_len, sa);

	    if (len != (long)iov[i].iov_len) {
		if (len > 0)
		    out += len;
		else if (!out && !blocked())
		    return -1;
		break;
	    }
	}
    }
    return out;
#endif
}

bool SocketSet::iselect(SocketSet &iset, SocketSet &eset, ulong msec) {
    int ret;
#ifdef _WIN32
    struct timeval tv = { msec / 1000, (msec % 1000) * 1000 };

    fds->fd_count = sz;
    eset = iset = *this;
    if ((ret = select(0, iset.fds, NULL, eset.fds,
	msec == SOCK_INFINITE ? NULL : &tv)) == -1)
	return false;
    iset.sz = iset.fds->fd_count;
    eset.sz = eset.fds->fd_count;
    return true;
#else
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

bool SocketSet::oselect(SocketSet &oset, SocketSet &eset, ulong msec) {
    int ret;
#ifdef _WIN32
    struct timeval tv = { msec / 1000, (msec % 1000) * 1000 };

    fds->fd_count = sz;
    eset = oset = *this;
    if ((ret = select(0, NULL, oset.fds, eset.fds,
	msec == SOCK_INFINITE ? NULL : &tv)) == -1)
	return false;
    oset.sz = oset.fds->fd_count;
    eset.sz = eset.fds->fd_count;
    return true;
#else
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

bool SocketSet::ioselect(SocketSet &iset, SocketSet &oset, SocketSet &eset,
    ulong msec) {
    int ret;
#ifdef _WIN32
    struct timeval tv = { msec / 1000, (msec % 1000) * 1000 };

    fds->fd_count = sz;
    eset = iset = oset = *this;
    if ((ret = select(0, iset.fds, oset.fds, eset.fds,
	msec == SOCK_INFINITE ? NULL : &tv)) == -1)
	return false;
    iset.sz = iset.fds->fd_count;
    oset.sz = oset.fds->fd_count;
    eset.sz = eset.fds->fd_count;
    return true;
#else
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

bool SocketSet::ioselect(const SocketSet &rset, SocketSet &iset,
    const SocketSet &wset, SocketSet &oset, SocketSet &eset, ulong msec) {
    uint u;
    int ret;
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
    if ((ret = select(0, iset.fds, oset.fds, eset.fds,
	msec == SOCK_INFINITE ? NULL : &tv)) == -1)
	return false;
    iset.sz = iset.fds->fd_count;
    oset.sz = oset.fds->fd_count;
    eset.sz = eset.fds->fd_count;
    return true;
#else
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

