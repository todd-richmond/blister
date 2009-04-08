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
#include <time.h>
#include "HTTPClient.h"
#include "Log.h"

static const int StreamSize = 3 * 1460;

const URL &URL::operator =(const URL &url) {
    if (this != &url) {
	prot = url.prot;
	host = url.host;
	path = url.path;
	query = url.query;
	port = url.port;
    }
    return *this;
}

const tstring URL::fullpath(void) const {
    tstring s(prot + T("://") + host);

    if (port != 80) {
	tchar buf[8];

	tsprintf(buf, T(":%u"), port);
	s += buf;
    }
    return s + relpath();
}

bool URL::set(const tchar *url) {
    const tchar *p, *pp;

    query.erase();
    if (!url) {
	prot = T("http");
	host = T("localhost");
	port = 80;
	path = T("/");
	return true;
    }
    p = tstrchr(url, ':');
    if (p && p[1] == '/' && p[2] == '/') {
	prot.assign(url, p - url);
	url = p + 3;
	p = tstrchr(url, ':');
    } else if (p && !istdigit(p[1])) {
	return false;
    } else {
	prot = T("http");
    }
    pp = tstrchr(url, '/');
    if (p && (!pp || p < pp)) {
	port = (ushort)tstrtoul(p + 1, NULL, 10);
	if (!port)
	    return false;
	host.assign(url, p - url);
	p = tstrchr(p, '/');
    } else {
	port = 80;
	if (pp && pp != url)
	    host.assign(url, pp - url);
	else if (pp)
	    host = T("localhost");
	else
	    host = url;
	p = pp;
    }
    if (p) {
	pp = tstrchr(p, '?');
	if (pp) {
	    path.assign(p, pp - p);
	    query = pp + 1;
	    unescape(query);
	} else {
	    path = p;
	}
	unescape(path);
    } else {
	path = T("/");
    }
    return true;
}

void URL::unescape(tchar *str, bool plus) {
    for (tchar *p = str; *p; p++) {
	if (*p == '%') {
	    uint hex;

	    if (*++p <= '9')
		hex = *p - '0';
	    else
		hex = *p - 'A' + 10;
	    hex <<= 4;
	    if (*++p <= '9')
		hex += *p - '0';
	    else
		hex += *p - 'A' + 10;
	    *str++ = (tchar)hex;
	} else if (*p == '+' && plus) {
	    *str++ = ' ';
	} else {
	    *str++ = *p;
	}
    }
    *str = '\0';
}

void URL::unescape(tstring &str, bool plus) {
    uint i, j;

    for (i = 0, j = 0; j < str.size(); j++) {
	tchar p = str[j];

	if (p == '%') {
	    uint hex;

	    p = str[++j];
	    if (p <= '9')
		hex = p - '0';
	    else
		hex = p - 'A' + 10;
	    hex <<= 4;
	    p = str[++j];
	    if (p <= '9')
		hex += p - '0';
	    else
		hex += p - 'A' + 10;
	    str[i] = (tchar)hex;
	} else if (p == '+' && plus) {
	    str[i] = ' ';
	} else if (i != j) {
	    str[i] = p;
	}
	i++;
    }
    str.erase(i);
}

HTTPClient::HTTPClient(): ressz(0), result(0), rto(90 * 1000), wto(60 * 1000),
    sstrm(StreamSize), sts(0), sz(0) {}

bool HTTPClient::connect(const Sockaddr &sa, bool keepalive, ulong to) {
    if (sock.open() && sa == addr)
	return true;
    if (addr != sa)
	addr = sa;
    sock.close();
    ka = keepalive;
    if (!sock.connect(addr, to)) {
	dlog << Log::Info << T("mod=http cmd=connect addr=") << addr.host() <<
	    T(":") << (uint)addr.port() << T(" errno=") << sock.err() << endlog;
	sock.close();
	return false;
    }
    sock.rtimeout(rto);
    sock.wtimeout(wto);
    sstrm.rdbuf()->attach(sock);
    sstrm.rdbuf()->reset();
    sstrm.clear(sstrm.rdstate() & ~(ios::badbit | ios::eofbit | ios::failbit));
    DLOGD(T("mod=http cmd=connect addr=") << addr.host() << ':' << addr.port());
    return true;
}

bool HTTPClient::send(const tchar *op, const tchar *path, const void *data,
    long datasz) {
    char buf[16];
    bool first = true;
    streamsize in;
    iovec iov[2];
    bool keep = false;
    const char *p, *pp;
    const tchar *resp;
    bool ret = false;
    string req, s, ss, sss;
    bool sent;
    msec_t start;
    static tchar connection[] = T("Connection");
    static tchar contentlen[] = T("Content-Length");
    static tchar keep_alive[] = T("Keep-Alive");
    static tchar pragma[] = T("Pragma");

    sts = 0;
    s.reserve(128);
    reshdrs.clear();
    req = tchartoa(op);
    req += ' ';
    req += tchartoa(path);
    req += " HTTP/1.0\r\n";
    if (datasz) {
	req += "Content-Length: ";
	sprintf(buf, "%lu", datasz);
	req += buf;
	req += "\r\n";
    }
    if (ka)
	req += "Pragma: Keep-Alive\r\nConnection: Keep-Alive\r\n";
    if (hstrm.size())
	req += tchartoa(hstrm.str());
    req += "\r\n";
    iov[0].iov_base = (char *)req.c_str();
    iov[0].iov_len = req.size();
    iov[1].iov_base = (char *)data;
    iov[1].iov_len = datasz;
loop:
    if (!connect(addr, ka))
	goto done;
    start = mticks();
    if ((sent = (ulong)sock.writev(iov, 2) == (ulong)(req.size() + datasz)) ==
	false ||
	// shutdown causes huge cpu spikes on NT - not sure why
#if 0
	(!ka && !sock.shutdown(false, true)) ||
#endif
	!getline(sstrm, s)) {
	sock.close();
	if (first && ka && (!sent || rto - (mticks() - start) > 200)) {
	    dlog << Log::Debug << T("mod=http action=reconnect") << endlog;
	    sstrm.seekp(0, ios::beg);
	    first = false;
	    goto loop;
	} else {
	    dlog << Log::Note << T("mod=http action=disconnect") << endlog;
	    goto done;
	}
    }
    p = s.c_str();
    while (*p != ' ' && *p != '\t')
	p++;
    while (*p == ' ' || *p == '\t')
	p++;
    sts = atoi(p);
    dlog << Log::Debug << T("mod=http status=") << sts << endlog;
    while (getline(sstrm, s)) {		    // does not support folded hdrs
	p = s.c_str();
	while (*p == ' ' || *p == '\t')
	    p++;
	if (*p == '\r' || !*p)
	    break;
	if ((pp = strchr(p, ':')) == NULL)
	    continue;
	ss = s.substr(p - s.c_str(), pp - p);
	do {
	    pp++;
	} while (*pp && (*pp == '\r' || *pp == ' ' || *pp == '\t'));
	sss.assign(pp, strlen(pp) - 1);
	
	pair<tstring, tstring> pr(atotstring(ss.c_str()), atotstring(sss.c_str()));

	reshdrs.insert(pr);
    }
    if (!sstrm)
	goto done;
    if (ka) {
	if ((resp = response(connection)) != NULL &&
	    !tstrnicmp(resp, keep_alive, sizeof (keep_alive) - 1))
	    keep = true;
	else if ((resp = response(pragma)) != NULL &&
	    !tstrnicmp(resp, keep_alive, sizeof (keep_alive) - 1))
	    keep = true;
    }
    if ((resp = response(contentlen)) == NULL)
	ressz = (ulong)-1;
    else
	ressz = tstrtoul(resp, NULL, 10);
    if (keep && !sz && ressz != (ulong)-1)
	sock.nagle(false);
    if (ressz && ressz != (ulong)-1) {
	if (ressz > sz) {
	    delete [] result;
	    sz = ressz;
	    result = new char[sz + 1];
	}
	ret = (ulong)sstrm.read(result, ressz) == ressz;
    } else if (ressz) {
	char *newres;
	ulong room = sz;

	keep = false;
	ressz = 0;
	for (;;) {
	    if (!room) {
		room = ressz ? ressz : 12 * 1024;
		sz = ressz + room;
		newres = new char[sz + 1];
		memcpy(newres, result, ressz);
		delete [] result;
		result = newres;
	    }
	    if ((in = sstrm.read(result + ressz, room)) > 0) {
		ressz += in;
		ret = true;
	    }
	    if (in == -1 || (ulong)in < room)
		break;
	    room -= in;
	}
    } else {
	ret = true;
    }
done:
    if (!keep || !ret)
	sock.close();
    if (ret && result)
	result[ressz] = '\0';
    hstrm.reset();
    return ret;
}

ostream &HTTPClient::operator <<(ostream &os) {
    attrmap::const_iterator it;

    os << sts << endl;
    for (it = reshdrs.begin(); it != reshdrs.end(); it++)
	os << tstringtoa(it->first) << ": " << tstringtoa(it->second) << endl;
    os.write(result, ressz);
    os << endl;
    return os;
}
