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
#include <array>
#include <ctype.h>
#include <time.h>
#include "HTTPClient.h"
#include "Log.h"

static constexpr int StreamSize = 3 * 1460;
static constexpr size_t MaxHdrs = 64 * 1024;		// status + header bytes
static constexpr ulong MaxBody = 256UL * 1024 * 1024;

static constexpr auto hex_lut = [] {
    array<uchar, 256> t{};

    t.fill(255);
    for (size_t i = 0; i < 10; i++)
	t['0' + i] = (uchar)i;
    for (size_t i = 0; i < 6; i++)
	t['a' + i] = t['A' + i] = (uchar)(10 + i);
    return t;
}();

static constexpr uchar hexval(tuchar c) {
    return c < hex_lut.size() ? hex_lut[c] : (uchar)255;
}

static constexpr int hexbyte(tuchar hi, tuchar lo) {
    const uchar h = hexval(hi), l = hexval(lo);

    return (h | l) > 15 ? -1 : (h << 4) | l;
}

static tstring totstring(string_view sv) {
#ifdef UNICODE
    return achartotstring(string(sv).c_str());
#else
    return tstring(sv);
#endif
}

static bool readline(streambuf *sb, string &s, size_t &left) {
    s.clear();
    for (int c; (c = sb->sbumpc()) != EOF; ) {
	if (c == '\n') {
	    if (!s.empty() && s.back() == '\r')
		s.pop_back();
	    return true;
	}
	if (!left)
	    return false;
	left--;
	s += (char)c;
    }
    return false;
}

static bool hastoken(tstring_view list, tstring_view token) {
    while (!list.empty()) {
	size_t pos = list.find(T(','));
	tstring_view v = list.substr(0, pos);

	list = pos == tstring_view::npos ? tstring_view() :
	    list.substr(pos + 1);
	while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
	    v.remove_prefix(1);
	while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
	    v.remove_suffix(1);
	if (stringieq(v, token))
	    return true;
    }
    return false;
}

static bool parsestatus(string_view line, uint &sts, bool &http11) {
    size_t pos = line.find(' ');
    auto digit = [&](size_t i) { return (uchar)(line[i] - '0') < 10; };

    if (!line.starts_with("HTTP/") || pos == string_view::npos ||
	(pos = line.find_first_not_of(" \t", pos)) == string_view::npos ||
	line.size() < pos + 3 || !digit(pos) || !digit(pos + 1) ||
	!digit(pos + 2))
	return false;
    http11 = line.compare(5, 3, "1.1") == 0;
    sts = (uint)(line[pos] - '0') * 100 + (uint)(line[pos + 1] - '0') * 10 +
	(uint)(line[pos + 2] - '0');
    return sts != 0;
}

static void addhdr(HTTPClient::attrmap &hdrs, string_view hdr) {
    size_t colon = hdr.find(':');

    // folded headers are not supported
    if (!colon || colon == string_view::npos || hdr[0] == ' ' || hdr[0] == '\t')
	return;

    string_view name = hdr.substr(0, colon);
    string_view val = hdr.substr(colon + 1);

    while (!name.empty() && (name.back() == ' ' || name.back() == '\t'))
	name.remove_suffix(1);
    while (!val.empty() && (val.front() == ' ' || val.front() == '\t'))
	val.remove_prefix(1);
    while (!val.empty() && (val.back() == ' ' || val.back() == '\t'))
	val.remove_suffix(1);
    hdrs.emplace(totstring(name), totstring(val));
}

static bool parsenum(string_view s, ulong &n, bool hex) {
    const ulong base = hex ? 16 : 10;

    n = 0;
    if (s.empty())
	return false;
    for (char c : s) {
	const ulong d = hex ? hexval((tuchar)c) : (ulong)(c - '0');

	if (d >= base || n > (MaxBody - d) / base)
	    return false;
	n = n * base + d;
    }
    return true;
}

// request line injection protection
static bool badtoken(const tchar *s) {
    if (!*s)
	return true;
    for (; *s; s++) {
	if ((tuchar)*s <= ' ' || *s == 0x7f)
	    return true;
    }
    return false;
}

static string buildreq(const tchar *op, const tchar *path, const Sockaddr &addr,
    bool ka, ulong datasz, tstring_view hdrs) {
    char buf[24];
    tstring host = addr.str();		// never does a reverse DNS lookup
    string req;

    req.reserve(256 + hdrs.size());
    req = tchartoachar(op);
    req += ' ';
    req += tchartoachar(path);
    req += " HTTP/1.1\r\nHost: ";
    if (addr.proto() == Sockaddr::UNIX)
	host = T("localhost");
    else if (addr.port() == 80)
	host.resize(host.size() - 3);	// strip ":80"
    req += tstringtoastring(host);
    req += "\r\n";
    if (datasz || !tstrcmp(op, T("POST")) || !tstrcmp(op, T("PUT"))) {
	req += "Content-Length: ";
	req.append(buf, to_chars(buf, buf + sizeof (buf), datasz).ptr);
	req += "\r\n";
    }
    req += ka ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
    if (!hdrs.empty())
	req.append(tchartoachar(hdrs.data()), hdrs.size());
    req += "\r\n";
    return req;
}

tstring URL::fullpath(void) const {
    tstring s(prot);

    s.reserve(prot.length() + host.length() + rpath.length() +
	rquery.length() + 16);
    s += T("://");
    if (!port) {
	for (tchar c : host) {		// unix socket path
	    if (c == '/')
		s += T("%2F");
	    else
		s += c;
	}
    } else {
	const bool v6 = host.contains(':');

	if (v6)
	    s += '[';
	s += host;
	if (v6)
	    s += ']';
	if (port != (prot == T("https") ? 443 : 80)) {
	    tchar buf[8];

	    buf[0] = ':';
	    to_str(buf + 1, buf + 8, port);
	    s += buf;
	}
    }
    s += rpath;
    if (!rquery.empty()) {
	s += '?';
	s += rquery;
    }
    return s;
}

bool URL::set(const tchar *url) {
    if (!url) {
	prot = T("http");
	host = T("localhost");
	port = 80;
	rpath = T("/");
	rquery.erase();
	return true;
    }

    tstring_view u(url), auth, rest;
    tstring p(T("http")), h;
    size_t pos = u.find(T("://"));
    ushort pt;

    if (pos != tstring_view::npos && pos < u.find_first_of(T("/?#"))) {
	if (!pos)
	    return false;
	p.assign(u.substr(0, pos));
	for (tchar &c : p)
	    c = (tchar)totlower(c);
	u.remove_prefix(pos + 3);
    }
    pos = u.find_first_of(T("/?#"));
    auth = u.substr(0, pos);
    rest = pos == tstring_view::npos ? tstring_view() : u.substr(pos);
    if (p == T("http+unix") || p == T("https+unix")) {
	h.assign(auth);
	unescape(h, false);
	pt = 0;
    } else {
	tstring_view portstr;

	pt = p == T("https") ? 443 : 80;
	if (!auth.empty() && auth.front() == '[') {
	    pos = auth.find(']');
	    if (pos == tstring_view::npos)
		return false;
	    h.assign(auth.substr(1, pos - 1));
	    portstr = auth.substr(pos + 1);
	} else {
	    pos = auth.find(':');
	    h.assign(auth.substr(0, pos));
	    portstr = pos == tstring_view::npos ? tstring_view() :
		auth.substr(pos);
	}
	if (!portstr.empty()) {
	    uint n = 0;

	    if (portstr.front() != ':')
		return false;
	    portstr.remove_prefix(1);
	    if (portstr.empty() || portstr.size() > 5)
		return false;
	    for (tchar c : portstr) {
		if (!istdigit(c))
		    return false;
		n = n * 10 + (uint)(c - '0');
	    }
	    if (!n || n > 65535)
		return false;
	    pt = (ushort)n;
	}
	if (h.empty())
	    h = T("localhost");
    }
    if (pos = rest.find('#'); pos != tstring_view::npos)
	rest = rest.substr(0, pos);
    pos = rest.find('?');
    prot = std::move(p);
    host = std::move(h);
    port = pt;
    rpath.assign(rest.substr(0, pos));
    if (rpath.empty())
	rpath = T("/");
    rquery.assign(pos == tstring_view::npos ? tstring_view() :
	rest.substr(pos + 1));
    return true;
}

void URL::unescape(tchar *str, bool plus) {
    tchar *d = str;

    for (const tuchar *p = (const tuchar *)str; *p; p++) {
	int v;

	if (*p == '%' && p[1] && p[2] && (v = hexbyte(p[1], p[2])) >= 0) {
	    *d++ = (tchar)v;
	    p += 2;
	} else if (*p == '+' && plus) {
	    *d++ = ' ';
	} else {
	    *d++ = (tchar)*p;
	}
    }
    *d = '\0';
}

void URL::unescape(tstring &str, bool plus) {
    size_t i = 0;

    for (size_t j = 0; j < str.size(); j++, i++) {
	tchar c = str[j];
	int v;

	if (c == '%' && j + 2 < str.size() &&
	    (v = hexbyte((tuchar)str[j + 1], (tuchar)str[j + 2])) >= 0) {
	    c = (tchar)v;
	    j += 2;
	} else if (c == '+' && plus) {
	    c = ' ';
	}
	str[i] = c;
    }
    str.erase(i);
}

HTTPClient::HTTPClient(): sstrm(StreamSize) {}

void HTTPClient::setup(void) {
    sock.nodelay(true);
    sock.rtimeout(rto);
    sock.wtimeout(wto);
    sstrm.rdbuf()->attach(sock);
    sstrm.rdbuf()->reset();
    sstrm.clear(sstrm.rdstate() & ~(ios::badbit | ios::eofbit | ios::failbit));
}

bool HTTPClient::connect(Socket &s, bool keepalive) {
    Sockaddr sa(Sockaddr::UNSPEC);

    if (!s.open() || !s.peername(sa))
	return false;
    ka = keepalive;
    addr = sa;
    sock = s;
    setup();
    dlogd(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("fd"),
	s.fd()));
    return true;
}

bool HTTPClient::connect(const Sockaddr &sa, bool keepalive, uint to) {
    ka = keepalive;
    if (sock.open() && sa == addr)
	return true;
    addr = sa;
    sock.close();
    if (!sock.connect(addr, to)) {
	dlogi(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	    addr.str()), Log::error(sock.errstr()));
	sock.close();
	return false;
    }
    setup();
    dlogd(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	addr.ipstr()));
    return true;
}

void HTTPClient::grow(ulong need) {
    if (need <= sz)
	return;
    need = max(need, min(sz * 2, MaxBody));

    auto p = make_unique_for_overwrite<char[]>((size_t)need + 1);

    if (ressz)
	memcpy(p.get(), result.get(), ressz);
    result = std::move(p);
    sz = need;
}

bool HTTPClient::readhdrs(string &line, bool &http11) {
    size_t left = MaxHdrs - line.size();

    if (!parsestatus(line, sts, http11))
	return false;
    for (;;) {
	if (!readline(sstrm.rdbuf(), line, left))
	    return false;
	if (line.empty())
	    return true;
	addhdr(reshdrs, line);
    }
}

bool HTTPClient::readchunked(void) {
    string line;
    size_t left;

    for (;;) {
	ulong n;

	left = 1024;
	if (!readline(sstrm.rdbuf(), line, left) ||
	    !parsenum(string_view(line).substr(0, line.find_first_of("; \t")),
	    n, true) || n > MaxBody - ressz)
	    return false;
	if (!n)
	    break;
	grow(ressz + n);

	streamsize in = sstrm.read(result.get() + ressz, (streamsize)n);

	if (in > 0)
	    ressz += (ulong)in;
	left = 2;
	if ((ulong)in != n || !readline(sstrm.rdbuf(), line, left) ||
	    !line.empty())
	    return false;
    }
    left = MaxHdrs;				// discard trailers
    while (readline(sstrm.rdbuf(), line, left)) {
	if (line.empty())
	    return true;
    }
    return false;
}

bool HTTPClient::readbody(bool head, bool &keep) {
    const tchar *resp;

    if (head || sts == 204 || sts == 304 || sts / 100 == 1)
	return true;
    if ((resp = response(T("Transfer-Encoding"))) != nullptr &&
	hastoken(resp, T("chunked")))
	return readchunked();
    if ((resp = response(T("Content-Length"))) != nullptr) {
	ulong len;

	if (!parsenum(tchartoachar(resp), len, false))
	    return false;
	if (len) {
	    grow(len);

	    streamsize in = sstrm.read(result.get(), (streamsize)len);

	    if (in > 0)
		ressz = (ulong)in;
	    return (ulong)in == len;
	}
	return true;
    }

    keep = false;
    for (;;) {
	if (ressz == sz) {
	    if (sz >= MaxBody)
		return false;
	    grow(max(sz + 1, 12UL * 1024));
	}

	streamsize room = (streamsize)(sz - ressz);
	streamsize in = sstrm.read(result.get() + ressz, room);

	if (in > 0)
	    ressz += (ulong)in;
	if (in < room)
	    return sock.err() == EOF;
    }
}

bool HTTPClient::transmit(const string &req, const void *data, ulong datasz,
    msghdr *msgh) {
    const streamsize rsz = (streamsize)req.size();
    streamsize off = 0;

    if (msgh) {
#ifndef _WIN32
	iovec iov[2] = { { (void *)req.data(), req.size() },
	    { (void *)data, datasz } };

	msgh->msg_iov = iov;
	msgh->msg_iovlen = datasz ? 2 : 1;
	off = (streamsize)sock.sendmsg(*msgh, MSG_NOSIGNAL);
	if (off <= 0)
	    return false;
	// ancillary data is sent with the first byte so only finish the stream
	if (off == rsz + (streamsize)datasz)
	    return true;
#else
	return false;
#endif
    }
    if (off < rsz && sstrm.write(req.data() + off, rsz - off) != rsz - off)
	return false;
    if (datasz) {
	const streamsize doff = off > rsz ? off - rsz : 0;

	if (sstrm.write((const char *)data + doff, (streamsize)datasz - doff) !=
	    (streamsize)datasz - doff)
	    return false;
    }
    return bool(sstrm.flush());
}

bool HTTPClient::send(const tchar *op, const tchar *path, const void *data,
    ulong datasz, msghdr *msgh) {
    bool keep = false;
    bool ret = false;

    sts = 0;
    ressz = 0;
    reshdrs.clear();
    if (!badtoken(op) && !badtoken(path)) {
	const bool head = !tstrcmp(op, T("HEAD"));
	string line;
	const string req = buildreq(op, path, addr, ka, datasz,
	    tstring_view(hstrm.str(), (size_t)hstrm.size()));

	for (bool first = true; msgh ? sock.open() : connect(addr, ka);
	    first = false) {
	    size_t left = MaxHdrs;
	    const msec_t start = mticks();
	    const bool sent = transmit(req, data, datasz, msgh);

	    if (sent && readline(sstrm.rdbuf(), line, left)) {
		bool http11 = false;

		if (readhdrs(line, http11)) {
		    const tchar *resp = response(T("Connection"));

		    dlogd(Log::mod(T("http")), Log::kv(T("addr"), addr.ipstr()),
			Log::kv(T("path"), path), Log::kv(T("sts"), sts));
		    keep = ka && !(resp && hastoken(resp, T("close"))) &&
			(http11 || (resp && hastoken(resp, T("keep-alive"))));
		    ret = readbody(head, keep);
		}
		break;
	    }
	    sock.close();
	    // retry once if a stale keep-alive connection failed quickly
	    if (first && ka && !msgh &&
		(!sent || rto > (mticks() - start) + 200)) {
		dlogd(Log::mod(T("http")), Log::cmd(T("reconnect")),
		    Log::kv(T("addr"), addr.ipstr()));
		continue;
	    }
	    dlogn(Log::mod(T("http")), Log::cmd(T("disconnect")),
		Log::kv(T("addr"), addr.ipstr()));
	    break;
	}
    }
    if ((!keep && !msgh) || !ret)
	sock.close();
    if (result)
	result[ressz] = '\0';
    hstrm.reset();
    return ret;
}

time_t parse_date(const tchar *hdr, int adjhr, int adjmin) {
    static constexpr tstring_view months =
	T("janfebmaraprmayjunjulaugsepoctnovdec");
    static constexpr struct { tstring_view name; int hour; } zones[] = {
	{ T("EDT"), -4 }, { T("EST"), -5 }, { T("CDT"), -5 }, { T("CST"), -6 },
	{ T("MDT"), -6 }, { T("MST"), -7 }, { T("PDT"), -7 }, { T("PST"), -8 }
    };
    int day = 0, mon = 0, year = -1, hour = 12, min = 0, sec = 0, off = 0;
    bool timed = false;
    auto num = [](const tchar *&p) {
	int n = 0;

	for (; istdigit(*p); ++p)
	    n = n < 100000 ? n * 10 + *p - '0' : n;
	return n;
    };

    // accept RFC 1123/822, RFC 850 and asctime dates: fields are recognized
    // by type so day names, commas, dashes and comments are simply skipped
    for (const tchar *p = hdr; *p; ) {
	const tchar *s = p;

	if (istdigit(*p)) {
	    int n = num(p);
	    size_t len = (size_t)(p - s);

	    if (*p == ':' && !timed) {
		timed = true;
		hour = n;
		min = num(++p);
		if (*p == ':')
		    sec = num(++p);
	    } else if (!day) {
		day = n;
	    } else if (year < 0) {
		year = len >= 4 ? n : len == 3 || n >= 70 ? n + 1900 : n + 2000;
	    }
	} else if (istalpha(*p)) {
	    while (istalpha(*p))
		++p;

	    size_t len = (size_t)(p - s);
	    if (!mon && len >= 3) {
		for (size_t i = 0; i < months.size(); i += 3) {
		    if (!tstrnicmp(s, months.data() + i, 3)) {
			mon = (int)i / 3 + 1;
			break;
		    }
		}
	    }
	    if (!timed)
		continue;
	    if (len == 2 && (!tstrnicmp(s, T("AM"), 2) ||
		!tstrnicmp(s, T("PM"), 2))) {
		if (hour <= 12)
		    hour = hour % 12 + (totupper(*s) == 'P' ? 12 : 0);
	    } else if (len == 1) {
		// military zone
		tchar z = (tchar)totupper(*s);

		off = (z < 'J' ? z - 'A' + 1 : z < 'N' ? z - 'A' : z < 'Z' ?
		    'M' - z : 0) * 60;
	    } else {
		for (const auto &z : zones) {
		    if (len == 3 && !tstrnicmp(s, z.name.data(), 3))
			off = z.hour * 60;
		}
	    }
	} else if (timed && (*p == '+' || *p == '-') && istdigit(p[1])) {
	    bool neg = *p++ == '-';

	    s = p;
	    off = num(p);
	    off = p - s <= 2 ? off * 60 : off / 100 * 60 + off % 100;
	    if (neg)
		off = -off;
	} else if (*p == '(') {
	    // skip nested comment
	    for (int depth = 0; *p; ) {
		if (*p == '(')
		    ++depth;
		else if (*p == ')')
		    --depth;
		++p;
		if (!depth)
		    break;
	    }
	} else {
	    ++p;
	}
    }
    if (!day || !mon || year < 0 || year > 9999 || hour > 23 || min > 59 ||
	sec > 60)
	return 0;

    namespace chr = std::chrono;
    chr::year_month_day ymd(chr::year(year) / chr::month((uint)mon) /
	chr::day((uint)day));

    if (!ymd.ok())
	return 0;
    return (chr::sys_days(ymd) + chr::hours(hour + adjhr) +
	chr::minutes(min - off + adjmin) + chr::seconds(sec)).
	time_since_epoch().count();
}
