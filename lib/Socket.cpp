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

#ifndef HOST_NAME_MAX
#define HOST_NAME_MAX 256
#endif

const char *Sockaddr::protos[] = { "tcp", "udp" };

Sockaddr::Sockaddr(const sockaddr &s) {
    *(sockaddr *)this = s;
    name.erase();
    if (sa_family == AF_INET)
	sz = 4;
    else
	sz = 0;
}

bool Sockaddr::set(const hostent *h) {
    memset((sockaddr *)this, 0, sizeof (sockaddr));
    if (h) {
	sa_family = h->h_addrtype;
	sz = h->h_length;
	memcpy(&((sockaddr_in *)this)->sin_addr, h->h_addr, sz);
	name = achartotstring(h->h_name);
    } else {
	name.erase();
	sz = 0;
    }
    return true;
}

bool Sockaddr::set(const tchar *host, ushort portno, Proto proto) {
    hostent *h = NULL, hbuf;
    char buf[512];
    int err;
    ulong addr = (ulong)-1;
    bool ret = false;

    memset((sockaddr *)this, 0, sizeof (sockaddr));
    if (proto == TCP || proto == UDP) {
	sa_family = AF_INET;
	sz = 4;
    } else {
	sa_family = AF_UNSPEC;
	sz = 0;
    }
    name.erase();
    if (host && *host && *host != '*' && tstricmp(host, T("INADDR_ANY"))) {
	if (istdigit(*host) &&
	    (addr = inet_addr(tchartoachar(host))) != (ulong)-1) {
	    ((sockaddr_in *)this)->sin_addr.s_addr = addr;
	    ret = true;
	} else {
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__linux__)
	    gethostbyname_r(tchartoachar(host), &hbuf, buf, sizeof (buf), &h,
		&err);
#else
	    h = gethostbyname_r(tchartoachar(host), &hbuf, buf, sizeof (buf),
		&err);
#endif
	    if (h)
		ret = set(h);
	    else
		((sockaddr_in *)this)->sin_addr.s_addr = (uint)-1;
	}
    } else {
	((sockaddr_in *)this)->sin_addr.s_addr = INADDR_ANY;
	ret = true;
    }
    if (ret)
	port(portno);
    return ret;
}

bool Sockaddr::set(const tchar *hp, Proto proto) {
    const tchar *p;

    if (!hp) {
	return set(NULL, 0, proto);
    } else if ((p = tstrchr(hp, ':')) == NULL) {
	return set(hp, 0, proto);
    } else {
	tstring s(hp);

	s.erase(p - hp);
	return set(s.c_str(), (ushort)tstrtoul(p + 1, NULL, 10), proto);
    }
}

const tstring &Sockaddr::host(void) const {
    if (name.empty()) {
	if (((sockaddr_in *)this)->sin_addr.s_addr == INADDR_ANY) {
	    name = '*';
	} else {
	    char buf[512];
	    int err;
	    hostent *h = NULL, hbuf;

#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__linux__)
	    gethostbyaddr_r((const char *)&((sockaddr_in *)this)->sin_addr,
		sz, sa_family, &hbuf, buf, sizeof (buf), &h, &err);
#else
	    h = gethostbyaddr_r((const char *)&((sockaddr_in *)this)->sin_addr,
		sz, sa_family, &hbuf, buf, sizeof (buf), &err);
#endif
	    if (h)
		name = achartotstring(h->h_name);
	    else
		name = ip();
	}
    }
    return name;
}

ushort Sockaddr::port(void) const {
    if (sa_family == AF_INET)
	return htons(((const sockaddr_in *)this)->sin_port);
    else
	return (ushort)-1;
}

bool Sockaddr::port(ushort port) {
    if (sa_family == AF_INET)
	((sockaddr_in *)this)->sin_port = htons(port);
    return true;
}

bool Sockaddr::port(const tchar *service, Proto proto) {
    char buf[128];
    struct servent *s = NULL, sbuf;

    (void)buf; (void)sbuf;
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__linux__)
    getservbyname_r(service, protos[proto], &sbuf, buf, sizeof (buf), &s);
#elif !defined(_WIN32_WCE)
    s = getservbyname_r(tchartoachar(service), protos[proto], &sbuf, buf,
	sizeof (buf));
#endif
    port((ushort)(s ? s->s_port : 0));
    return s != NULL;
}

tstring Sockaddr::service(ushort port, Proto proto) {
    tchar buf[128];
    struct servent *s = NULL, sbuf;

    (void)buf; (void)sbuf;
#if defined(__OpenBSD__) || defined(__FreeBSD__) || defined(__linux__)
    getservbyport_r(port, protos[proto], &sbuf, buf, sizeof (buf), &s);
#elif !defined(_WIN32_WCE)
    s = getservbyport_r(port, protos[proto], &sbuf, buf, sizeof (buf));
#endif
    return s ? achartotstring(s->s_name) : T("");
}

const tstring &Sockaddr::hostname() {
    static tstring name;

    if (name.empty()) {
	char buf[HOST_NAME_MAX];
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
	    buf[sizeof (buf) - 1] = '\0';

	    hostent *hp = gethostbyname(buf);
	    
	    name = achartotstring(hp ? hp->h_name : buf);
	}
    }
    return name;
}

#define VALID_IP(ip) (ip[0] < 256 && ip[1] < 256 && ip[2] < 256 && ip[3] < 256)
#define BUILD_IP(ip) ((ip[0] << 24) | (ip[1] << 16) | (ip[2] << 8) | ip[3])

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

    return tsscanf(addr, T("%u.%u.%u.%u"), &ip[0], &ip[1], &ip[2], &ip[3]) == 4 &&
	VALID_IP(ip) && find(BUILD_IP(ip));
}

bool CIDR::find(uint addr) const {
    vector<Range>::const_iterator it;
    Range range;

    range.min = range.max = addr;
    for (it = lower_bound(ranges.begin(), ranges.end(), range, range);
	it != ranges.end() && (*it).min <= range.min; it++) {
	if (range.max <= (*it).max)
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
    sockaddr sa;
    socklen_t sz = sizeof (sa);

    sock.close();
    do {
	if (check((sock.sbuf->sock = movehigh(::accept(sbuf->sock, &sa,
	    &sz))) == SOCK_INVALID ? -1 : 0)) {
	    sock.sbuf->type = sbuf->type;
	    return true;
	}
    } while (interrupted());
    return false;
}

bool Socket::bind(const Sockaddr &addr, bool reuse) {
    if (!*this && !open(addr.family()))
	return false;
    if (reuse && !reuseaddr(true))
	return false;
    return check(::bind(sbuf->sock, addr, sizeof (sockaddr)));
}

bool Socket::connect(const Sockaddr &addr, ulong timeout) {
    bool ret = false;

    if (!*this && !open(addr.family()))
	return false;
    if (timeout != SOCK_INFINITE)
	blocking(false);
    if (check(::connect(sbuf->sock, (sockaddr *)(const sockaddr *)addr,
	sizeof (sockaddr)))) {
	ret = true;
    } else {
	if (blocked()) {
	    if (timeout > 0 && timeout != SOCK_INFINITE) {
		SocketSet sset(1), oset(1), eset(1);

		sset.set(sbuf->sock);
		ret = sset.oselect(oset, eset, timeout) &&
		    oset.get(sbuf->sock);
	    }
	}
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
    char buf[32];

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

bool Socket::peername(Sockaddr &addr) {
    sockaddr sa;
    socklen_t sz = sizeof (sa);

    if (check(getpeername(sbuf->sock, &sa, &sz))) {
	addr = sa;
	return true;
    } else {
	return false;
    }
}

#ifdef linux
#include <linux/netfilter_ipv4.h>

bool Socket::proxysockname(Sockaddr &addr) {
    sockaddr sa;

    if (check(getsockopt(SOL_IP, SO_ORIGINAL_DST, sa))) {
	addr = sa;
	return true;
    } else {
	return false;
    }
}
#endif

bool Socket::sockname(Sockaddr &addr) {
    sockaddr sa;
    socklen_t sz = sizeof (sa);

    if (check(getsockname(sbuf->sock, &sa, &sz))) {
	addr = sa;
	return true;
    } else {
	return false;
    }
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

int Socket::read(void *buf, size_t sz, Sockaddr &addr) const {
    socklen_t asz = sizeof (sockaddr);
    int in;
    
    do {
	if (!rwpoll(true))
	    return -1;
	check(in = recvfrom(sbuf->sock, (char *)buf, (SIZE_T)sz, 0, &addr,
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

int Socket::write(const void *buf, size_t sz, const Sockaddr &addr) const {
    int out;
    
    do {
	if (!rwpoll(false))
	    return -1;
	check(out = sendto(sbuf->sock, (const char *)buf, (SIZE_T)sz, 0,
	    &addr, sizeof (sockaddr)));
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

long Socket::writev(const iovec *iov, int count, const Sockaddr &addr) const {
    long out;

#if defined(_WIN32) && !defined(_WIN32_WCE)
    check(WSASendTo(sbuf->sock, (WSABUF *)iov, count, (ulong *)&out, 0,
	&addr, sizeof (sockaddr), NULL, NULL));
    return blocked() ? 0 : out;
#else
    out = 0;
    for (int i = 0; i < count; i++) {
	if (iov[i].iov_len) {
	    long len = write(iov[i].iov_base, iov[i].iov_len, addr);

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

