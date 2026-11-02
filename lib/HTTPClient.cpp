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

static constexpr ulong MaxBody = 256UL * 1024 * 1024;
static constexpr size_t MaxCopy = 4UL * 1024;		// request with small body
static constexpr size_t MaxHdrs = 64UL * 1024;		// status + header bytes
static constexpr size_t MaxPipeline = 16;
static constexpr size_t MinRead = 512;
static constexpr ulong MaxKeep = 64UL * 1024;	// reused response buffer

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
    if constexpr (sizeof (tuchar) > 1) {
	if (c >= hex_lut.size())
	    return 255;
    }
    return hex_lut[c];
}

static constexpr int hexbyte(tuchar hi, tuchar lo) {
    const uchar h = hexval(hi), l = hexval(lo);

    return (h | l) > 15 ? -1 : (h << 4) | l;
}

tstring URL::fullpath(void) const {
    tstring s(protstr);

    s.reserve(protstr.length() + hoststr.length() + rpath.length() +
	rquery.length() + 16);
    s += T("://");
    if (!portnum) {
	for (tchar c : hoststr) {		// unix socket path
	    if (c == '/')
		s += T("%2F");
	    else
		s += c;
	}
    } else {
	const bool v6 = hoststr.contains(':');

	if (v6)
	    s += '[';
	s += hoststr;
	if (v6)
	    s += ']';
	if (portnum != (protstr == T("https") ? 443 : 80)) {
	    tchar buf[8];

	    buf[0] = ':';
	    to_str(buf + 1, buf + 8, portnum);
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
	protstr = T("http");
	hoststr = T("localhost");
	portnum = 80;
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
    rest = rest.substr(0, rest.find('#'));
    pos = rest.find('?');
    protstr = std::move(p);
    hoststr = std::move(h);
    portnum = pt;
    rpath.assign(rest.substr(0, pos));
    if (rpath.empty())
	rpath = T("/");
    rquery.assign(pos == tstring_view::npos ? tstring_view() :
	rest.substr(pos + 1));
    return true;
}

// skip to each escape with vectorized strcspn
size_t URL::unescape(tchar *str, bool plus) {
    const tchar *set = plus ? T("%+") : T("%");
    tchar *d = str + tstrcspn(str, set);

    for (const tuchar *p = (const tuchar *)d; *p; ) {
	size_t n;
	int v;

	if (*p == '%' && p[1] && p[2] && (v = hexbyte(p[1], p[2])) >= 0) {
	    *d++ = (tchar)v;
	    p += 3;
	} else {
	    *d++ = *p == '+' ? ' ' : (tchar)*p;
	    p++;
	}
	// adjacent escapes are common in dense input: avoid the scan
	if (*p == '%' || (plus && *p == '+'))
	    continue;
	n = tstrcspn((const tchar *)p, set);
	if (d != (const tchar *)p)
	    memmove(d, p, n * sizeof (tchar));
	d += n;
	p += n;
    }
    *d = '\0';
    return (size_t)(d - str);
}

void URL::unescape(tstring &str, bool plus) {
    str.resize(unescape(str.data(), plus));
}

void HTTPClient::Headers::add(string_view hdr) {
    size_t colon = hdr.find(':');

    // folded headers are not supported
    if (!colon || colon == string_view::npos || hdr[0] == ' ' || hdr[0] == '\t')
	return;

    string_view name = hdr.substr(0, hdr.find_last_not_of(" \t", colon - 1) +
	1);
    string_view val = hdr.substr(colon + 1);

    val.remove_prefix(min(val.find_first_not_of(" \t"), val.size()));
    val = val.substr(0, val.find_last_not_of(" \t") + 1);

    Hdr h{(uint)buf.size(), 0, 0};

    tappend(buf, name);
    h.nlen = (uint)buf.size() - h.name;
    h.val = (uint)buf.size();
    tappend(buf, val);
    buf.push_back('\0');
    hdrs.push_back(h);
}

// false if op or path could inject into the request line. A small body is
// appended, zeroing datasz, since a copy is cheaper than a second iovec
bool HTTPClient::buildreq(string &out, const tchar *op, const tchar *path,
    string_view host, bool keep, tstring_view hdrs, const void *data,
    ulong &datasz) {
    auto bad = [](const tchar *s) {
	for (const tchar *p = s; *p; p++) {
	    if ((tuchar)*p <= ' ' || *p == 0x7f)
		return true;
	}
	return !*s;
    };

    if (bad(op) || bad(path))
	return false;
    out.reserve(max(MaxCopy, 256 + hdrs.size()));
    out = tchartoachar(op);
    out += ' ';
    out += tchartoachar(path);
    out += " HTTP/1.1\r\n";
    if (!hashost(hdrs)) {
	out += "Host: ";
	out += host;
	out += "\r\n";
    }
    if (datasz || !tstrcmp(op, T("POST")) || !tstrcmp(op, T("PUT"))) {
	char buf[24];

	out += "Content-Length: ";
	out.append(buf, to_chars(buf, buf + sizeof (buf), datasz).ptr);
	out += "\r\n";
    }
    out += keep ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
    if (!hdrs.empty())
	out.append(tchartoachar(hdrs.data()), hdrs.size());
    out += "\r\n";
    if (data && datasz && out.size() + datasz <= MaxCopy) {
	out.append((const char *)data, datasz);
	datasz = 0;
    }
    return true;
}

bool HTTPClient::connect(Socket &s, bool keepalive) {
    Sockaddr sa(Sockaddr::UNSPEC);

    if (!s.open() || !s.peername(sa))
	return false;
    ka = keepalive;
    addr = sa;
    hostval = hosthdr(addr);
    sock = s;
    setup();
    dlogd(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("fd"),
	s.fd()));
    return true;
}

bool HTTPClient::connect(const Sockaddr &sa, bool keepalive, uint to) {
    ka = keepalive;
    cto = to;
    if (sock.open() && sa == addr)
	return true;
    addr = sa;
    hostval = hosthdr(addr);
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

// RFC 9112 6.3 body length. keep is whether the server allows reuse
HTTPClient::Body HTTPClient::framing(const Headers &hdrs, uint sts, bool head,
    bool http11, bool &keep, ulong &len) {
    const tchar *p = hdrs.find(T("Connection"));
    const tchar *te = hdrs.find(T("Transfer-Encoding"));

    keep = sts != 101 && !(p && hastoken(p, T("close"))) && (http11 || (p &&
	hastoken(p, T("keep-alive"))));
    len = 0;
    if (head || sts == 204 || sts == 304 || sts / 100 == 1)
	return Body::None;
    if (te) {
	const tstring_view v(te);
	const size_t pos = v.rfind(',');

	// only a final chunked coding delimits the body
	if (hastoken(pos == v.npos ? v : v.substr(pos + 1), T("chunked")))
	    return Body::Chunked;
    } else if ((p = hdrs.find(T("Content-Length"))) != nullptr) {
	if (!parsenum(tchartoachar(p), len, false))
	    return Body::Bad;
	return len ? Body::Length : Body::None;
    }
    keep = false;
    return Body::Eof;
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

// a caller supplied Host replaces the default
bool HTTPClient::hashost(tstring_view hdrs) {
    for (;;) {
	if (hdrs.size() >= 5 && stringieq(hdrs.substr(0, 5), T("Host:")))
	    return true;

	const size_t pos = hdrs.find('\n');

	if (pos == hdrs.npos)
	    return false;
	hdrs.remove_prefix(pos + 1);
    }
}

string HTTPClient::hosthdr(const Sockaddr &sa) {
    tstring host = sa.str();		// never does a reverse DNS lookup

    if (sa.proto() == Sockaddr::UNIX)
	host = T("localhost");
    else if (sa.port() == 80)
	host.resize(host.size() - 3);	// strip ":80"
    return tstringtoastring(host);
}

// RFC 9112 9.3.1: only these may be retried after being sent
bool HTTPClient::idempotent(const tchar *op) {
    static constexpr const tchar *ops[] = {
	T("GET"), T("HEAD"), T("PUT"), T("DELETE"), T("OPTIONS"), T("TRACE")
    };

    return ranges::any_of(ops, [op](const tchar *m) { return
	!tstrcmp(op, m); });
}

bool HTTPClient::parsenum(string_view s, ulong &n, bool hex) {
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

bool HTTPClient::parsestatus(string_view str, uint &code, bool &http11) {
    size_t pos = str.find(' ');
    auto digit = [&](size_t i) { return (uchar)(str[i] - '0') < 10; };

    if (!str.starts_with("HTTP/") || pos == string_view::npos ||
	(pos = str.find_first_not_of(" \t", pos)) == string_view::npos ||
	str.size() < pos + 3 || !digit(pos) || !digit(pos + 1) ||
	!digit(pos + 2))
	return false;
    http11 = str.compare(5, 3, "1.1") == 0;
    code = (uint)(str[pos] - '0') * 100 + (uint)(str[pos + 1] - '0') * 10 +
	(uint)(str[pos + 2] - '0');
    return code != 0;
}

bool HTTPClient::readbody(bool head, bool http11, bool &keep) {
    streamsize in;
    ulong len;

    switch (framing(reshdrs, sts, head, http11, keep, len)) {
    case Body::Bad:
	return false;
    case Body::None:
	return true;
    case Body::Chunked:
	return readchunked();
    case Body::Length:
	grow(len);
	in = sstrm.read(result.get(), (streamsize)len);
	if (in > 0)
	    ressz = (ulong)in;
	return (ulong)in == len;
    case Body::Eof:
	break;
    }
    for (;;) {
	if (ressz == sz) {
	    if (sz >= MaxBody)
		return false;
	    grow(max(sz + 1, 12UL * 1024));
	}

	const auto room = (streamsize)(sz - ressz);

	in = sstrm.read(result.get() + ressz, room);
	if (in > 0)
	    ressz += (ulong)in;
	if (in < room)
	    return sock.err() == EOF;
    }
}

bool HTTPClient::readchunked(void) {
    size_t left;

    for (;;) {
	streamsize in;
	ulong n;

	left = 1024;
	if (!readline(sstrm.rdbuf(), line, left) ||
	    !parsenum(string_view(line).substr(0, line.find_first_of("; \t")),
	    n, true) || n > MaxBody - ressz)
	    return false;
	if (!n)
	    break;
	grow(ressz + n);
	in = sstrm.read(result.get() + ressz, (streamsize)n);
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

bool HTTPClient::readhdrs(bool &http11) {
    size_t left = MaxHdrs - line.size();

    for (;;) {
	if (!parsestatus(line, sts, http11))
	    return false;
	for (;;) {
	    if (!readline(sstrm.rdbuf(), line, left))
		return false;
	    if (line.empty())
		break;
	    reshdrs.add(line);
	}
	// skip interim responses
	if (sts / 100 != 1 || sts == 101)
	    return true;
	reshdrs.clear();
	if (!readline(sstrm.rdbuf(), line, left))
	    return false;
    }
}

bool HTTPClient::readline(socketbuf *sb, string &s, size_t &left) {
    s.clear();
    while (sb->sgetc() != EOF) {
	const string_view v = sb->avail();
	const size_t pos = v.find('\n');
	const size_t len = pos == string_view::npos ? v.size() : pos;

	if (len > left)
	    return false;
	left -= len;
	s.append(v.data(), len);
	if (pos != string_view::npos) {
	    sb->consume(len + 1);
	    if (!s.empty() && s.back() == '\r')
		s.pop_back();
	    return true;
	}
	sb->consume(len);
    }
    return false;
}

bool HTTPClient::send(const tchar *op, const tchar *path, const void *data,
    // cppcheck-suppress constParameterPointer
    ulong datasz, msghdr *msgh) {
    bool keep = false;
    bool ret = false;

    sts = 0;
    ressz = 0;
    reshdrs.clear();
    if (buildreq(req, op, path, hostval, ka, tstring_view(hstrm.str(),
	(size_t)hstrm.size()), msgh ? nullptr : data, datasz)) {
	const bool head = !tstrcmp(op, T("HEAD"));
	const streamsize total = (streamsize)(req.size() + datasz);
#ifndef _WIN32
	iovec iov[2] = { { (void *)req.data(), req.size() },
	    { (void *)data, datasz } };

	if (msgh) {
	    msgh->msg_iov = iov;
	    msgh->msg_iovlen = datasz ? 2 : 1;
	}
#endif

	for (bool first = true; sock.open() || (!msgh && connect(addr, ka,
	    cto)); first = false) {
	    size_t left = MaxHdrs;
	    const msec_t start = mticks();
	    streamsize off = 0;
	    bool sent = true;

	    if (msgh) {
#ifdef _WIN32
		sent = false;
#else
		off = (streamsize)sock.sendmsg(*msgh, MSG_NOSIGNAL);
		sent = off > 0;
#endif
	    }
	    // ancillary data goes with the first byte so only finish the rest
	    if (sent && off < total)
		sent = sendall(sock, req, data, datasz, (ulong)off);
	    if (sent && readline(sstrm.rdbuf(), line, left)) {
		bool http11 = false;

		if (readhdrs(http11)) {
		    dlogd(Log::mod(T("http")), Log::kv(T("addr"), addr.ipstr()),
			Log::kv(T("path"), path), Log::kv(T("sts"), sts));
		    ret = readbody(head, http11, keep);
		    keep = keep && ka;
		}
		break;
	    }
	    sock.close();
	    // retry once if a stale keep-alive connection failed quickly
	    if (first && ka && !msgh && (!sent || (idempotent(op) &&
		rto > (mticks() - start) + 200))) {
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

// write hdr then data after skipping the off bytes already sent
bool HTTPClient::sendall(const Socket &s, string_view hdr, const void *data,
    ulong datasz, ulong off) {
    iovec iov[2];
    int i = 0;

    iov[0].iov_base = (char *)hdr.data();	// NOSONAR
    iov[0].iov_len = (iovlen_t)hdr.size();
    iov[1].iov_base = (char *)data;		// NOSONAR
    iov[1].iov_len = (iovlen_t)datasz;
    for (;;) {
	long n;

	while (i < 2 && off >= (ulong)iov[i].iov_len)
	    off -= (ulong)iov[i++].iov_len;
	if (i == 2)
	    return true;
	iov[i].iov_base = (char *)iov[i].iov_base + off;
	iov[i].iov_len -= (iovlen_t)off;
	if ((n = s.writev(iov + i, 2 - i)) <= 0)
	    return false;
	off = (ulong)n;
    }
}

void HTTPClient::setup(void) {
    sock.nodelay(true);
    sock.rtimeout(rto);
    sock.wtimeout(wto);
    sstrm.rdbuf()->attach(sock);
    sstrm.rdbuf()->reset();
    sstrm.clear();
}

void HTTPClient::tappend(tstring &s, string_view sv) {
#ifdef UNICODE
    s += achartotstring(string(sv).c_str());
#else
    s += sv;
#endif
}

void AsyncHTTPClient::Request::reset(void) {
    if (cap > MaxKeep) {
	free(result);
	result = nullptr;
	cap = 0;
    } else if (result) {
	*result = '\0';
    }
    reshdrs.clear();
    sz = 0;
    sockerr = 0;
    sts = 0;
}

void AsyncHTTPClient::Request::result_grow(DispatchObjCB cb, DispatchObj &co,
    char *old, uint, uint newsize) {
    char *p = (char *)realloc(old, newsize);

    if (!p)
	free(old);
    result = p;
    cb(&co);
}

void AsyncHTTPClient::Request::rewind(void) {
    reset();
    phase = Status;
    hdrleft = MaxHdrs;
    remain = written = 0;
}

void AsyncHTTPClient::Request::send(DispatchObjCB cb, DispatchObj &co,
    AsyncHTTPClient &c, const tchar *op, const tchar *path, const void *data,
    ulong len) {
    if (!setup(cb, co, c, op, path, data, len))
	return;
    c.acquire();
    c.submit(*this);
}

bool AsyncHTTPClient::Request::setup(DispatchObjCB cb, DispatchObj &co,
    AsyncHTTPClient &c, const tchar *op, const tchar *path, const void *data,
    ulong len) {
    done = cb;
    caller = &co;
    client = &c;
    datap = data;
    datasz = len;
    attempts = 0;
    rewind();
    if (!HTTPClient::buildreq(req, op, path, c.host, true,
	tstring_view(hstrm.str(), (size_t)hstrm.size()), data, datasz)) {
	sockerr = EINVAL;
	hstrm.reset();
	caller = nullptr;
	co.ready(cb);
	return false;
    }
    head = !tstrcmp(op, T("HEAD"));
    idem = HTTPClient::idempotent(op);
    hstrm.reset();
    return true;
}

AsyncHTTPClient::AsyncHTTPClient(IOSocket *s, const Sockaddr &sa, Timing *tm):
    addr(sa), host(HTTPClient::hosthdr(sa)), intake(*new Intake(*s, *this)),
    sock(*s), timing(tm) {
    if (timing) {
	const tstring ip(addr.ipstr());

	ckey = T("conn:") + ip;
	rkey = T("read:") + ip;
	wkey = T("write:") + ip;
    }
}

AsyncHTTPClient::Flow AsyncHTTPClient::advance(Request &r) {
    Flow f;
    size_t left;
    string_view line;
    long n;

    for (;;) {
	switch (r.phase) {
	case Request::Status:
	    if ((f = nextline(line, r.hdrleft)) != Flow::Ok)
		return f;
	    if (!HTTPClient::parsestatus(line, r.sts, r.http11))
		return bad(EPROTO);
	    r.phase = Request::Headers;
	    break;
	case Request::Headers:
	    if ((f = nextline(line, r.hdrleft)) != Flow::Ok)
		return f;
	    if (!line.empty())
		r.reshdrs.add(line);
	    else if ((f = endhdrs(r)) != Flow::Ok)
		return f;
	    break;
	case Request::Length:
	case Request::ChunkData:
	    while (r.remain) {
		if ((n = take(r, r.remain)) < 0)
		    return broke(sock.err());
		if (!n)
		    return Flow::Wait;
		r.remain -= (ulong)n;
	    }
	    r.phase = r.phase == Request::Length ? Request::Done :
		Request::ChunkEnd;
	    break;
	case Request::Eof:
	    for (;;) {
		if (r.sz + 1 >= r.cap) {
		    if (r.sz >= MaxBody)
			return bad(EFBIG);
		    if ((f = reserve(r, r.sz + 1)) != Flow::Ok)
			return f;
		}
		if ((n = take(r, r.cap - 1 - r.sz)) > 0)
		    continue;
		if (!n)
		    return Flow::Wait;
		if (sock.err() != EOF)
		    return broke(sock.err());
		break;
	    }
	    r.phase = Request::Done;
	    break;
	case Request::ChunkSize: {
	    ulong len;

	    left = 1024;
	    if ((f = nextline(line, left)) != Flow::Ok)
		return f;
	    if (!HTTPClient::parsenum(line.substr(0,
		line.find_first_of("; \t")), len, true) || len > MaxBody - r.sz)
		return bad(EPROTO);
	    if (len) {
		r.remain = len;
		r.phase = Request::ChunkData;
		if ((f = reserve(r, r.sz + len)) != Flow::Ok)
		    return f;
	    } else {
		r.hdrleft = MaxHdrs;
		r.phase = Request::Trailers;
	    }
	    break;
	}
	case Request::ChunkEnd:
	    left = 2;
	    if ((f = nextline(line, left)) != Flow::Ok)
		return f;
	    if (!line.empty())
		return bad(EPROTO);
	    r.phase = Request::ChunkSize;
	    break;
	case Request::Trailers:
	    if ((f = nextline(line, r.hdrleft)) != Flow::Ok)
		return f;
	    if (line.empty())
		r.phase = Request::Done;
	    break;
	case Request::Done:
	    return finish(r);
	}
    }
}

AsyncHTTPClient::Flow AsyncHTTPClient::bad(int err) {
    Request &r = *rq.front();

    dlogi(Log::mod(T("http")), Log::cmd(T("response")), Log::kv(T("addr"),
	addr.ipstr()), Log::error(err == EOF ? tstring(T("EOF")) :
	tstring(tstrerror(err))));
    rq.pop_front();
    down(err, Down::Resend);
    complete(r, err);
    return Flow::Stop;
}

// the Request can be reused or destroyed as soon as it has been completed
void AsyncHTTPClient::complete(Request &r, int err) {
    release();
    r.sockerr = err;
    if (r.resend())
	return;

    DispatchObj *co = r.caller;
    const auto cb = r.done;

    r.caller = nullptr;
    r.done = nullptr;
    if (!co->grouped(sock)) {
	co->ready(cb);
	return;
    }
    // a caller in this group runs now and its resubmit skips the intake
    incall = co;
    cb(co);
    incall = nullptr;
}

void AsyncHTTPClient::connect(void) {
    state = Connecting;
    connects++;
    if (timing)
	cstart = Timing::now();
    sock.connect(addr, cto);
}

void AsyncHTTPClient::connected(void) {
    int e = 0;

    if (state != Connecting)
	return;
    if (timing)
	timing->record(ckey, cstart);
    if (sock.reason() == DispatchTimeout) {
	e = ETIMEDOUT;
    } else {
	if (!sock.getsockopt(SOL_SOCKET, SO_ERROR, e))
	    e = sock.err();
	if (!e && sock.error())
	    e = sock.err() ? sock.err() : ECONNRESET;
    }
    if (e) {
	dlogi(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	    addr.str()), Log::error(e == ETIMEDOUT ? tstring(T("timeout")) :
	    tstring(tstrerror(e))));
	down(e, Down::Fail);
	return;
    }
    (void)sock.nodelay(true);
    (void)sock.setsockopt(SOL_SOCKET, SO_KEEPALIVE, true);
    state = Open;
    idle = false;
    rdpos = rdend = 0;
    dlogd(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	addr.ipstr()));
    io();
}

void AsyncHTTPClient::down(int err, Down how) {
    deque<Request *> all(rq), dead;
    const size_t nrq = rq.size();

    all.insert(all.end(), wq.begin(), wq.end());
    rq.clear();
    wq.clear();
    sock.cancel();
    (void)sock.close();
    state = Closed;
    growing = idle = false;
    rdpos = rdend = 0;
    for (size_t i = 0; i < all.size(); i++) {
	Request *r = all[i];
	// only the oldest request can have broken the connection so it gets
	// one retry and the requests behind it are resent without penalty
	const bool sent = how == Down::Retry && i == 0 && r->written;

	// a fully sent non-idempotent request may have been applied
	if (how == Down::Fail || (sent && r->attempts) || (i < nrq &&
	    !r->idem)) {
	    dead.push_back(r);
	} else {
	    r->attempts += sent;
	    r->rewind();
	    wq.push_back(r);
	}
    }
    count();
    if (!wq.empty())
	connect();
    for (Request *r : dead)
	complete(*r, err);
}

void AsyncHTTPClient::drain(void) {
    inlock.lock();
    batch.swap(inbox);
    inlock.unlock();
    for (Request *r : batch)
	enqueue(*r);
    if (!batch.empty() && state == Open && !growing)
	io(false);
    batch.clear();
    if (!pending)
	delete this;
}

AsyncHTTPClient::Flow AsyncHTTPClient::endhdrs(Request &r) {
    using enum HTTPClient::Body;

    // skip interim responses
    if (r.sts / 100 == 1 && r.sts != 101) {
	r.reshdrs.clear();
	r.phase = Request::Status;
	return Flow::Ok;
    }
    switch (HTTPClient::framing(r.reshdrs, r.sts, r.head, r.http11, r.keep,
	r.remain)) {
    case Bad:
	return bad(EPROTO);
    case None:
	r.phase = Request::Done;
	break;
    case Length:
	r.phase = Request::Length;
	return reserve(r, r.remain);
    case Chunked:
	r.phase = Request::ChunkSize;
	break;
    case Eof:
	r.phase = Request::Eof;
	break;
    }
    return Flow::Ok;
}

void AsyncHTTPClient::enqueue(Request &r) {
    requests++;
    if (timing)
	r.start = Timing::now();
    wq.push_back(&r);
    count();
    if (state == Closed)
	connect();
}

int AsyncHTTPClient::fill(void) {
    // a write cannot make data readable so skip a read that must fail
    if (idle || sock.drained())
	return 0;
    if (rdpos == rdend) {
	rdpos = rdend = 0;
    } else if (rdpos && rdcap - rdend < MinRead) {
	memmove(rdbuf.get(), rdbuf.get() + rdpos, rdend - rdpos);
	rdend -= rdpos;
	rdpos = 0;
    }
    if (rdcap - rdend < MinRead) {
	const size_t cap = max(rdcap * 2, (size_t)4096);
	auto p = make_unique_for_overwrite<char[]>(cap);

	if (rdend)
	    memcpy(p.get(), rdbuf.get(), rdend);
	rdbuf = std::move(p);
	rdcap = cap;
    }

    const int n = sock.read(rdbuf.get() + rdend, (uint)(rdcap - rdend));

    if (n > 0)
	rdend += (size_t)n;
    idle = n >= 0 && sock.drained();
    return n;
}

AsyncHTTPClient::Flow AsyncHTTPClient::finish(Request &r) {
    const bool keep = r.keep;

    if (r.result)
	r.result[r.sz] = '\0';
    rq.pop_front();
    count();
    if (timing) {
	const timing_t now = timing->record(rkey, r.start);

	if (!rq.empty())
	    rq.front()->start = now;
    }
    complete(r, 0);
    if (keep)
	return Flow::Ok;
    // the server will not answer any pipelined requests
    down(EOF, Down::Resend);
    return Flow::Stop;
}

void AsyncHTTPClient::grown(void) {
    if (!growing)
	return;
    growing = false;
    if (inreserve)
	return;
    if (Request &r = *rq.front(); !r.result) {
	r.sz = r.cap = 0;
	(void)bad(ENOMEM);
    } else {
	io();
    }
}

void AsyncHTTPClient::io(bool event) {
    using enum Flow;
    Flow w;

    if (state != Open || growing)
	return;
    if (event && sock.reason() == DispatchTimeout) {
	dlogi(Log::mod(T("http")), Log::cmd(T("timeout")), Log::kv(T("addr"),
	    addr.ipstr()));
	down(ETIMEDOUT, Down::Fail);
	return;
    }
    // only a poll event can add data to a drained socket
    if (event && sock.reason() != DispatchNone)
	idle = false;
    for (;;) {
	const size_t pipelined = rq.size();

	if ((w = writeall()) == Stop || readall() == Stop ||
	    growing)
	    return;
	if (wq.empty() || w == Wait || rq.size() >= pipelined)
	    break;
    }

    const ulong tmt = rq.empty() && wq.empty() ? DispatchTimer::DSP_NEVER :
	rto.load();

    if (w == Wait)
	sock.rwable(IOSocket::onio, tmt);
    else
	sock.readable(IOSocket::onio, tmt);
}

AsyncHTTPClient::Flow AsyncHTTPClient::nextline(string_view &line,
    size_t &left) {
    for (;;) {
	const char *b = rdbuf.get() + rdpos;
	const size_t avail = rdend - rdpos;
	const char *nl = avail ? (const char *)memchr(b, '\n', avail) : nullptr;

	if (nl) {
	    size_t len = (size_t)(nl - b);

	    if (len >= left)
		return bad(EMSGSIZE);
	    left -= len + 1;
	    rdpos += len + 1;
	    if (len && b[len - 1] == '\r')
		len--;
	    line = string_view(b, len);
	    return Flow::Ok;
	}
	if (avail >= left)
	    return bad(EMSGSIZE);

	const int n = fill();

	if (n < 0)
	    return broke(sock.err());
	if (!n)
	    return Flow::Wait;
    }
}

AsyncHTTPClient::Flow AsyncHTTPClient::readall(void) {
    using enum Flow;

    while (!rq.empty()) {
	if (const Flow f = advance(*rq.front()); f != Ok)
	    return f;
    }
    // idle: unsolicited data is an error and a read error means it closed
    const int n = rdpos == rdend ? fill() : 1;

    if (n)
	down(n > 0 ? EPROTO : sock.err(), Down::Resend);
    return n ? Stop : Wait;
}

AsyncHTTPClient::Flow AsyncHTTPClient::reserve(Request &r, ulong need) {
    ulong cap = need + 1;

    if (r.result && r.cap >= cap)
	return Flow::Ok;
    if (r.phase != Request::Length)
	cap = (max)({ cap, min(r.cap * 2, MaxBody + 1), 12UL * 1024 });
    r.cap = cap;
    growing = inreserve = true;
    r.result_grow(IOSocket::ongrown, sock, r.result, (uint)r.sz, (uint)cap);
    inreserve = false;
    // cppcheck-suppress knownConditionTrueFalse
    if (growing)
	return Flow::Wait;			// subclass is allocating
    if (r.result)
	return Flow::Ok;
    r.sz = r.cap = 0;
    return bad(ENOMEM);
}

void AsyncHTTPClient::status(tostream &out, uint indent) const {
    const tstring pad(indent, T(' '));
    static constexpr const tchar *names[] = {
	T("Closed"), T("Connecting"), T("Open")
    };

    out << pad << T("<state>") << names[state.load()] << T("</state>\n") <<
	pad << T("<writequeue>") << wcnt.load() << T("</writequeue>\n") <<
	pad << T("<readqueue>") << rcnt.load() << T("</readqueue>\n") <<
	pad << T("<requests>") << requests.load() << T("</requests>\n") <<
	pad << T("<connects>") << connects.load() << T("</connects>\n");
}

void AsyncHTTPClient::submit(Request &r) {
    bool wake;

    if (r.caller == incall) {
	enqueue(r);
	return;
    }
    inlock.lock();
    wake = inbox.empty();
    inbox.push_back(&r);
    inlock.unlock();
    if (wake)
	intake.ready(Intake::drain);
}

long AsyncHTTPClient::take(Request &r, ulong want) {
    long n;

    if (rdpos < rdend) {
	n = (long)min((ulong)(rdend - rdpos), want);
	memcpy(r.result + r.sz, rdbuf.get() + rdpos, (size_t)n);
	rdpos += (size_t)n;
    } else if (sock.drained() && r.phase != Request::Eof) {
	return 0;	// only a read can see the end of an Eof body
    } else if ((n = sock.read(r.result + r.sz, (uint)min(want,
	(ulong)INT_MAX))) <= 0) {
	return n;
    }
    r.sz += (ulong)n;
    return n;
}

AsyncHTTPClient::Flow AsyncHTTPClient::writeall(void) {
    iovec iov[2 * MaxPipeline];

    // limit the requests that must be resent if the server closes
    while (!wq.empty() && rq.size() < MaxPipeline) {
	const size_t room = MaxPipeline - rq.size();
	int cnt = 0;
	ulong total = 0;
	auto add = [&](const void *p, size_t len) {
	    iov[cnt].iov_base = (char *)p;	// NOSONAR
	    iov[cnt++].iov_len = (iovlen_t)len;
	    total += len;
	};

	for (size_t i = 0; i < min(wq.size(), room); i++) {
	    const Request &r = *wq[i];
	    ulong off = r.written;

	    // RFC 9112 9.3.2: a non-idempotent request is not pipelined
	    if (!r.idem && (i || !rq.empty()))
		break;
	    if (off < r.req.size()) {
		add(r.req.data() + off, r.req.size() - off);
		off = 0;
	    } else {
		off -= r.req.size();
	    }
	    if (r.datasz > off)
		add((const char *)r.datap + off, r.datasz - off);
	    if (!r.idem)
		break;
	}
	if (!cnt)
	    break;

	long n = sock.writev(iov, cnt);

	if (n < 0)
	    return broke(sock.err());
	for (ulong left = (ulong)n; left; ) {
	    Request &r = *wq.front();
	    const ulong len = r.req.size() + r.datasz - r.written;

	    if (left < len) {
		r.written += left;
		break;
	    }
	    left -= len;
	    r.written += len;
	    wq.pop_front();
	    rq.push_back(&r);
	    if (timing)
		r.start = timing->record(wkey, r.start);
	}
	count();
	if ((ulong)n < total)
	    return Flow::Wait;
    }
    return Flow::Ok;
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
