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

#include "stdapi.h"
#include <ctype.h>
#include <time.h>
#include "HTTPClient.h"
#include "Log.h"

static const int StreamSize = 3 * 1460;

URL &URL::operator =(const URL &url) {
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
    tstring s(prot + T("://"));

    if (port && port != 80) {
	tchar buf[8];

	tsprintf(buf, T(":%u"), port);
	s += host;
	s += buf;
    } else if (!port && (prot == T("http+unix") || prot == T("https+unix"))) {
	for (tstring::const_iterator it = host.begin(); it != host.end(); ++it) {
	    if (*it == '/')
		s += T("%2F");
	    else
		s += *it;
	}
    } else {
	s += host;
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
	prot.assign(url, (tstring::size_type)(p - url));
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
	host.assign(url, (tstring::size_type)(p - url));
	p = tstrchr(p, '/');
    } else {
	if (pp && pp != url)
	    host.assign(url, (tstring::size_type)(pp - url));
	else if (pp)
	    host = T("localhost");
	else
	    host = url;
	if (prot == T("http+unix") || prot == T("https+unix")) {
	    unescape(host);
	    port = 0;
	} else {
	    port = 80;
	}
	p = pp;
    }
    if (p) {
	pp = tstrchr(p, '?');
	if (pp) {
	    path.assign(p, (tstring::size_type)(pp - p));
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
		hex = (uint)(*p - '0');
	    else
		hex = (uint)(*p - 'A' + 10);
	    hex <<= 4;
	    if (*++p <= '9')
		hex += (uint)(*p - '0');
	    else
		hex += (uint)(*p - 'A' + 10);
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
		hex = (uint)(p - '0');
	    else
		hex = (uint)(p - 'A' + 10);
	    hex <<= 4;
	    p = str[++j];
	    if (p <= '9')
		hex += (uint)(p - '0');
	    else
		hex += (uint)(p - 'A' + 10);
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

HTTPClient::HTTPClient(): ka(true), ressz(0), result(0), rto(90 * 1000),
    wto(60 * 1000), sstrm(StreamSize), sts(0), sz(0) {}

bool HTTPClient::connect(const Sockaddr &sa, bool keepalive, uint to) {
    if (sock.open() && sa == addr)
	return true;
    if (addr != sa)
	addr = sa;
    sock.close();
    ka = keepalive;
    if (!sock.connect(addr, to)) {
	dlogi(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	    addr.str()), Log::error(sock.errstr()));
	sock.close();
	return false;
    }
    sock.rtimeout(rto);
    sock.wtimeout(wto);
    sstrm.rdbuf()->attach(sock);
    sstrm.rdbuf()->reset();
    sstrm.clear(sstrm.rdstate() & ~(ios::badbit | ios::eofbit | ios::failbit));
    dlogd(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	addr.ipstr()));
    return true;
}

bool HTTPClient::send(const tchar *op, const tchar *path, const void *data,
    ulong datasz) {
    char buf[64];
    bool first = true;
    iovec iov[2];
    bool keep = false;
    const char *p, *pp;
    const tchar *resp;
    bool ret = false;
    string req, s, ss, sss;
    bool sent;
    msec_t start;
    static const tchar connection[] = T("Connection");
    static const tchar contentlen[] = T("Content-Length");
    static const tchar keep_alive[] = T("Keep-Alive");
    static const tchar pragma[] = T("Pragma");

    sts = 0;
    s.reserve(128);
    reshdrs.clear();
    req = tchartoachar(op);
    req += ' ';
    req += tchartoachar(path);
    req += " HTTP/1.1\r\nHost: ";
    req += tstringtoastring(addr.host());
    if (addr.port() != 80) {
	sprintf(buf, ":%u", addr.port());
	req += buf;
    }
    req += "\r\n";
    if (datasz) {
	sprintf(buf, "Content-Length: %lu\r\n", (ulong)datasz);
	req += buf;
    }
    if (ka)
	req += "Pragma: Keep-Alive\r\nConnection: Keep-Alive\r\n";
    if (hstrm.size())
	req += tchartoachar(hstrm.str());
    req += "\r\n";
    iov[0].iov_base = (char *)req.c_str();
    iov[0].iov_len = (iovlen_t)req.size();
    iov[1].iov_base = (char *)data;
    iov[1].iov_len = datasz;
loop:
    if (!connect(addr, ka))
	goto done;
    start = mticks();
    if ((sent = ((ulong)sock.writev(iov, 2) == (ulong)(req.size() +
	datasz))) == false ||
	// shutdown causes huge cpu spikes on NT - not sure why
#if 0
	(!ka && !sock.shutdown(false, true)) ||
#endif
	!getline(sstrm, s)) {
	sock.close();
	if (first && ka && (!sent || rto > (mticks() - start) + 200)) {
	    dlogd(Log::mod(T("http")), Log::cmd(T("reconnect")));
	    sstrm.seekp(0, ios::beg);
	    first = false;
	    goto loop;
	} else {
	    dlogn(Log::mod(T("http")), Log::cmd(T("disconnect")));
	    iov[0].iov_base = (char *)NULL;
	    goto done;
	}
    }
    iov[0].iov_base = (char *)NULL;
    p = s.c_str();
    while (*p && *p != ' ' && *p != '\t')
	p++;
    while (*p == ' ' || *p == '\t')
	p++;
    sts = (uint)atoi(p);
    dlogd(Log::mod(T("http")), Log::kv(T("status"), sts));
    while (getline(sstrm, s)) {		    // does not support folded hdrs
	p = s.c_str();
	while (*p == ' ' || *p == '\t')
	    p++;
	if (*p == '\r' || !*p)
	    break;
	if ((pp = strchr(p, ':')) == NULL)
	    continue;
	ss = s.substr((string::size_type)(p - s.c_str()), (string::size_type)
	    (pp - p));
	do {
	    pp++;
	} while (*pp && (*pp == '\r' || *pp == ' ' || *pp == '\t'));
	sss.assign(pp, *pp ? strlen(pp) - 1 : 0);

	pair<tstring, tstring> pr(astringtotstring(ss), astringtotstring(sss));

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
    if (sts == 204 || sts == 304)
	ressz = 0;
    else if ((resp = response(contentlen)) != NULL)
	ressz = tstrtoul(resp, NULL, 10);
    else
	ressz = (ulong)-1;
    if (keep && !sz && ressz != (ulong)-1)
	sock.nodelay(true);
    if (ressz && ressz != (ulong)-1) {
	if (ressz > sz) {
	    delete [] result;
	    sz = ressz;
	    result = new char[(size_t)sz + 1];
	}
	ret = (ulong)sstrm.read(result, (streamsize)ressz) == ressz;
    } else if (ressz) {
	streamsize in;
	char *newres;
	ulong room = sz;

	keep = false;
	ressz = 0;
	for (;;) {
	    if (!room) {
		room = ressz ? ressz : 12 * 1024;
		sz = ressz + room;
		newres = new char[(size_t)sz + 1];
		memcpy(newres, result, ressz);
		delete [] result;
		result = newres;
	    }
	    if ((in = sstrm.read(result + ressz, (streamsize)room)) > 0) {
		ressz += (ulong)in;
		ret = true;
	    }
	    if (in == -1 || (ulong)in < room)
		break;
	    room -= (ulong)in;
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

tostream &HTTPClient::operator <<(tostream &os) const {
    attrmap::const_iterator it;

    os << sts << endl;
    for (it = reshdrs.begin(); it != reshdrs.end(); ++it)
	os << it->first << ": " << it->second << endl;
    os.write(achartotchar(result), (streamsize)ressz);
    os << endl;
    return os;
}
