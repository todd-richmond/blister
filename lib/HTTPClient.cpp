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
#include <ctype.h>
#include <time.h>
#include "HTTPClient.h"
#include "Log.h"

static constexpr int StreamSize = 3 * 1460;

// Hex lookup table for fast parsing
static constexpr uchar hex_lut[256] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 0, 0, 0, 0,
    0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 10, 11, 12, 13, 14, 15, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

tstring URL::fullpath(void) const {
    tstring s;
    s.reserve(prot.length() + host.length() + relpath().length() + 20);

    s += prot;
    s += T("://");

    if (port && port != 80) {
	tchar buf[8];

	buf[0] = ':';
	to_str(buf + 1, buf + 8, port);
	s += host;
	s += buf;
    } else if (!port && (prot == T("http+unix") || prot == T("https+unix"))) {
	s.reserve(s.capacity() + host.length() * 3); // Worst case for URL encoding
	for (tchar c : host) {
	    if (c == '/')
		s += T("%2F");
	    else
		s += c;
	}
    } else {
	s += host;
    }
    s += relpath();
    return s;
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
	port = atoi<ushort>(p + 1);
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
    for (const tuchar *p = (const tuchar *)str; *p; p++) {
	if (*p == '%' && *(p + 1) && *(p + 2)) {
	    tuchar hex;
	    tuchar hex_val1 = hex_lut[*++p];
	    tuchar hex_val2 = hex_lut[*++p];

	    if (hex_val1 == 0 || hex_val2 == 0) {
		// Invalid hex digit
		*str++ = '%';
		*str++ = (tchar)*(p - 1);
		if (hex_val1 != 0)
		    *str++ = (tchar)*p;
		continue;
	    }
	    hex = (tuchar)((hex_val1 << 4) | hex_val2);
	    *str++ = (tchar)hex;
	} else if (*p == '+' && plus) {
	    *str++ = ' ';
	} else {
	    *str++ = (tchar)*p;
	}
    }
    *str = '\0';
}

void URL::unescape(tstring &str, bool plus) {
    uint i, j;

    for (i = 0, j = 0; j < str.size(); j++) {
	tchar p = str[j];

	if (p == '%') {
	    uchar hex;

	    if (j + 2 >= str.size()) {
		// Invalid % sequence
		str[i] = p;
		i++;
		break;
	    }

	    uchar hex_val1 = hex_lut[(uchar)str[++j]];
	    uchar hex_val2 = hex_lut[(uchar)str[++j]];

	    if (hex_val1 == 0 || hex_val2 == 0) {
		// Invalid hex digit
		str[i] = '%';
		if (hex_val1 == 0) {
		    str[++i] = str[j-1];
		} else {
		    str[++i] = str[j-1];
		    str[++i] = str[j];
		}
		i++;
		break;
	    }

	    hex = (uchar)((hex_val1 << 4) | hex_val2);
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
    addr = sa;
    sock.close();
    ka = keepalive;
    if (!sock.connect(addr, to)) {
	dlogi(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	    addr.str()), Log::error(sock.errstr()));
	sock.close();
	return false;
    }
    sock.nodelay(true);
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
    iovec iov[2]{};
    bool keep = false;
    const char *p, *pp;
    const tchar *resp;
    bool ret = false;
    string req, s, ss, sss;
    bool sent;
    msec_t start;
    static constexpr tchar connection[] = T("Connection");
    static constexpr tchar contentlen[] = T("Content-Length");
    static constexpr tchar keep_alive[] = T("Keep-Alive");
    static constexpr tchar pragma[] = T("Pragma");

    sts = 0;
    s.reserve(128);
    reshdrs.clear();
    req = tchartoachar(op);
    req += ' ';
    req += tchartoachar(path);
    req += " HTTP/1.1\r\nHost: ";
    req += tstringtoastring(addr.host());
    if (addr.port() != 80) {
	snprintf(buf, sizeof(buf), ":%u", addr.port());
	req += buf;
    }
    req += "\r\n";
    if (datasz) {
	snprintf(buf, sizeof (buf), "Content-Length: %lu\r\n", (ulong)datasz);
	req += buf;
    }
    if (ka)
	req += "Pragma: Keep-Alive\r\nConnection: Keep-Alive\r\n";
    if (hstrm.size())
	req += tchartoachar(hstrm.str());
    req += "\r\n";
    iov[0].iov_base = (char *)req.c_str();	// NOSONAR
    iov[0].iov_len = (iovlen_t)req.size();
    iov[1].iov_base = (char *)data;		// NOSONAR
    iov[1].iov_len = datasz;
loop:
    if (!connect(addr, ka))
	goto done;
    start = mticks();
    sent = (ulong)sock.writev(iov, 2) == (ulong)(req.size() + datasz);
    if (!sent ||
	// shutdown causes huge cpu spikes on NT - not sure why
	// (!ka && !sock.shutdown(false, true)) ||
	!getline(sstrm, s)) {
	sock.close();
	if (first && ka && (!sent || rto > (mticks() - start) + 200)) {
	    dlogd(Log::mod(T("http")), Log::cmd(T("reconnect")),
		Log::kv(T("addr"), addr.ipstr()));
	    sstrm.seekp(0, ios::beg);
	    first = false;
	    goto loop;
	} else {
	    dlogn(Log::mod(T("http")), Log::cmd(T("disconnect")),
		Log::kv(T("addr"), addr.ipstr()));
	    iov[0].iov_base = (char *)nullptr;
	    goto done;
	}
    }
    iov[0].iov_base = (char *)nullptr;
    p = s.c_str();
    while (*p && *p != ' ' && *p != '\t')
	p++;
    while (*p == ' ' || *p == '\t')
	p++;
    sts = (uint)strtoul(p, NULL, 10);
    dlogd(Log::mod(T("http")), Log::kv(T("addr"), addr.ipstr()),
	Log::kv(T("path"), path), Log::kv(T("sts"), sts));
    while (getline(sstrm, s)) {		    // does not support folded hdrs
	p = s.c_str();
	while (*p == ' ' || *p == '\t')
	    p++;
	if (*p == '\r' || !*p)
	    break;
	if ((pp = strchr(p, ':')) == nullptr)
	    continue;

	// Use string_view-like approach to avoid substr allocations
	size_t name_len = (size_t)(pp - p);
	const char *val_end;
	size_t val_len = 0;

	pp++;
	while (*pp && (*pp == '\r' || *pp == ' ' || *pp == '\t'))
	    pp++;
	val_end = strchr(pp, '\r');
	if (!val_end)
	    val_end = pp + strlen(pp);
	val_len = (size_t)(val_end - pp);

	// Create strings directly without intermediate substr
	tstring header_name(p, name_len);
	tstring header_val(pp, val_len);

	reshdrs.emplace(header_name, header_val);
    }
    if (!sstrm)
	goto done;
    if (ka) {
	if ((resp = response(connection)) != nullptr &&
	    !tstrnicmp(resp, keep_alive, sizeof (keep_alive) - 1))
	    keep = true;
	else if ((resp = response(pragma)) != nullptr &&
	    !tstrnicmp(resp, keep_alive, sizeof (keep_alive) - 1))
	    keep = true;
    }
    if (sts == 204 || sts == 304)
	ressz = 0;
    else if ((resp = response(contentlen)) != nullptr)
	ressz = atoi<ulong>(resp);
    else
	ressz = (ulong)-1;
    if (ressz && ressz != (ulong)-1) {
	if (ressz > sz) {
	    char *new_result = new char[(size_t)ressz + 1];

	    delete [] result;
	    result = new_result;
	    sz = ressz;
	}
	ret = (ulong)sstrm.read(result, (streamsize)ressz) == ressz;
    } else if (ressz) {
	ulong room = sz;

	keep = false;
	ressz = 0;
	for (;;) {
	    streamsize in;
	    char *newres;

	    if (!room) {
		// Use exponential growth to reduce reallocations
		ulong new_size = ressz ? ressz * 2 : 12UL * 1024;

		if (new_size < 12UL * 1024)
		    new_size = 12UL * 1024;
		room = new_size - ressz;
		sz = new_size;
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

