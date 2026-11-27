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
static constexpr size_t MaxCopy = size_t{4} * 1024; // request with small body
static constexpr size_t MaxHdrs = size_t{64} * 1024;	// status + header bytes
static constexpr size_t MaxPipeline = 16;
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

	// %00 stays literal: decoded strings never hold a NUL
	if (*p == '%' && p[1] && p[2] && (v = hexbyte(p[1], p[2])) > 0) {
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

void HTTPHeaders::tappend(tstring &s, string_view sv) {
#ifdef UNICODE
    s += achartotstring(sv);
#else
    s += sv;
#endif
}

bool HTTPResponse::parsenum(string_view s, ulong &n, bool hex) {
    const char *end = s.data() + s.size();
    auto [p, ec] = from_chars(s.data(), end, n, hex ? 16 : 10);

    return ec == errc() && p == end && n <= MaxBody;
}

bool HTTPResponse::parsestatus(string_view str, uint &code, bool &http11) {
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
    return code >= 100 && (str.size() == pos + 3 || str[pos + 3] == ' ');
}

// a caller supplied Host replaces the default
bool HTTPResponse::hashost(tstring_view hdrs) {
    for (;;) {
	if (hdrs.size() >= 5 && stringieq(hdrs.substr(0, 5), T("Host:")))
	    return true;

	const size_t pos = hdrs.find('\n');

	if (pos == hdrs.npos)
	    return false;
	hdrs.remove_prefix(pos + 1);
    }
}

string HTTPResponse::hosthdr(const Sockaddr &sa) {
    tstring host = sa.str();		// never does a reverse DNS lookup

    if (sa.proto() == Sockaddr::UNIX)
	host = T("localhost");
    else if (sa.port() == 80)
	host.resize(host.size() - 3);	// strip ":80"
    return tstringtoastring(host);
}

// RFC 9112 9.3.1: only these may be retried after being sent
bool HTTPResponse::idempotent(const tchar *op) {
    static constexpr const tchar *ops[] = {
	T("GET"), T("HEAD"), T("PUT"), T("DELETE"), T("OPTIONS"), T("TRACE")
    };

    return ranges::any_of(ops, [op](const tchar *m) { return
	!tstrcmp(op, m); });
}

// a small body is appended, zeroing datasz, since a copy is cheaper than a
// second iovec
bool HTTPResponse::buildreq(string &out, const tchar *op, const tchar *path,
    string_view host, bool keep, const void *data, ulong &datasz) {
    const tstring_view hdrs(hstrm.str(), (size_t)hstrm.size());
    const tstring_view method(op), target(path);
    auto bad = [](tstring_view v) {
	for (tchar c : v) {
	    if ((tuchar)c <= ' ' || c == 0x7f)
		return true;
	}
	return v.empty();
    };

    if (bad(method) || bad(target)) {
	hstrm.reset();
	sockerr = EINVAL;
	return false;
    }

#ifdef UNICODE
    const string wireop = wchartoastring(method), wirepath =
	wchartoastring(target), wirehdrs = wchartoastring(hdrs);
#else
    const string_view wireop = method, wirepath = target, wirehdrs = hdrs;
#endif
    const bool defhost = !hashost(hdrs);
    const size_t need = 128 + wireop.size() + wirepath.size() + wirehdrs.size() +
	(defhost ? host.size() : 0);

    out.clear();
    out.reserve(need + (data && need <= MaxCopy && datasz <= MaxCopy - need ?
	datasz : 0));
    out += wireop;
    out += ' ';
    out += wirepath;
    out += " HTTP/1.1\r\n";
    if (defhost) {
	out += "Host: ";
	out += host;
	out += "\r\n";
    }
    if (datasz == Unknown) {
	out += "Transfer-Encoding: chunked\r\n";
	datasz = 0;
    } else if (datasz || !tstrcmp(op, T("POST")) ||
	!tstrcmp(op, T("PUT")) || !tstrcmp(op, T("PATCH"))) {
	char buf[24];

	out += "Content-Length: ";
	out.append(buf, to_chars(buf, buf + sizeof (buf), datasz).ptr);
	out += "\r\n";
    }
    out += keep ? "Connection: keep-alive\r\n" : "Connection: close\r\n";
    out += wirehdrs;
    out += "\r\n";
    hstrm.reset();
    if (data && datasz && out.size() <= MaxCopy &&
	datasz <= MaxCopy - out.size()) {
	out.append((const char *)data, datasz);
	datasz = 0;
    }
    return true;
}

// RFC 9112 6.3 body length. keep is whether the server allows reuse
HTTPResponse::Body HTTPResponse::framing(const HTTPHeaders &hdrs, uint sts,
    bool head, bool http11, bool &keep, ulong &len) {
    using enum Body;
    const bool nobody = head || sts == 204 || sts == 304 || sts / 100 == 1;
    bool close = false, keepalive = false, length = false;
    bool encoding = false, chunked = false, seenchunked = false;
    auto trim = [](tstring_view v) {
	v.remove_prefix(min(v.find_first_not_of(T(" \t")), v.size()));
	return v.substr(0, v.find_last_not_of(T(" \t")) + 1);
    };

    len = 0;
    for (const auto &h : hdrs.hdrs) {
	const tstring_view name(hdrs.buf.data() + h.name, h.val - h.name);
	tstring_view v(hdrs.buf.data() + h.val, h.vlen);

	if (stringieq(name, T("Connection"))) {
	    close |= hastoken(v, T("close"));
	    keepalive |= hastoken(v, T("keep-alive"));
	} else if (!nobody && stringieq(name, T("Content-Length"))) {
	    for (;;) {
		const size_t comma = v.find(',');
		const auto nstr = trim(v.substr(0, comma));
		ulong n;

#ifdef UNICODE
		const string bytes = wchartoastring(nstr);
#else
		const string_view bytes = nstr;
#endif
		if (!parsenum(bytes, n, false) || (length && len != n))
		    return Bad;
		len = n;
		length = true;
		if (comma == v.npos)
		    break;
		v.remove_prefix(comma + 1);
	    }
	} else if (!nobody && stringieq(name, T("Transfer-Encoding"))) {
	    for (;;) {
		size_t i = 0;
		bool quoted = false;

		for (; i < v.size() && (quoted || v[i] != ','); ++i) {
		    if (quoted && v[i] == '\\' && i + 1 < v.size())
			++i;
		    else if (v[i] == '"')
			quoted = !quoted;
		}
		const auto coding = trim(v.substr(0, i));
		const size_t semi = coding.find(';');

		if (quoted || coding.empty())
		    return Bad;
		encoding = true;
		chunked = stringieq(trim(coding.substr(0, semi)), T("chunked"));
		if (chunked) {
		    if (seenchunked || semi != coding.npos)
			return Bad;
		    seenchunked = true;
		}
		if (i == v.size())
		    break;
		v.remove_prefix(i + 1);
	    }
	}
    }
    keep = sts != 101 && !close && (http11 || keepalive);
    if (nobody)
	return None;
    if (encoding) {
	if (chunked) {
	    keep &= !length;
	    return Chunked;
	}
    } else if (length) {
	return len ? Length : None;
    }
    keep = false;
    return Eof;
}

void HTTPHeaders::add(string_view hdr) {
    size_t colon = hdr.find(':');

    // folded headers are not supported
    if (!colon || colon == string_view::npos || hdr[0] == ' ' || hdr[0] == '\t')
	return;

    string_view name = hdr.substr(0, hdr.find_last_not_of(" \t", colon - 1) +
	1);
    string_view val = hdr.substr(colon + 1);

    val.remove_prefix(min(val.find_first_not_of(" \t"), val.size()));
    val = val.substr(0, val.find_last_not_of(" \t") + 1);

    Hdr h;

    h.name = (uint)buf.size();
    tappend(buf, name);
    h.val = (uint)buf.size();
    tappend(buf, val);
    h.vlen = (uint)buf.size() - h.val;
    buf.push_back('\0');
    hdrs.push_back(h);
}

ulong HTTPResponse::capfor(ulong need, bool exact) const {
    const ulong n = need + 1;

    return exact ? n : (max)({ n, min(cap * 2, MaxBody + 1), 12UL * 1024 });
}

void HTTPResponse::reset(void) {
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

bool HTTPResponse::resize(ulong newcap) {
    char *p = (char *)realloc(result, (size_t)newcap);

    if (!p) {
	free(result);
	sz = 0;
    }
    result = p;
    cap = p ? newcap : 0;
    return p;
}

template<class S> template<class G>
HTTPParser<S>::Step HTTPParser<S>::advance(HTTPResponse &r, bool head,
    G grow) {
    Step s;
    string_view v;
    long n;

    for (;;) {
	switch (phase) {
	case Status:
	    if ((s = nextline(v)) != Step::Done)
		return s;
	    if (!HTTPResponse::parsestatus(v, r.sts, http11))
		return fail(EPROTO);
	    phase = Headers;
	    break;
	case Headers:
	    if ((s = nextline(v)) != Step::Done)
		return s;
	    if (!v.empty()) {
		r.reshdrs.add(v);
	    } else if (r.sts / 100 == 1 && r.sts != 101) {
		r.reshdrs.clear();		// skip interim responses
		phase = Status;
	    } else {
		switch (HTTPResponse::framing(r.reshdrs, r.sts, head, http11,
		    reuse, remain)) {
		case HTTPResponse::Body::Bad:
		    return fail(EPROTO);
		case HTTPResponse::Body::None:
		    phase = Complete;
		    break;
		case HTTPResponse::Body::Length:
		    phase = Length;
		    if ((s = reserve(r, remain, grow)) != Step::Done)
			return s;
		    break;
		case HTTPResponse::Body::Chunked:
		    start(ChunkSize, 1024);
		    break;
		case HTTPResponse::Body::Eof:
		    phase = Eof;
		    break;
		}
	    }
	    break;
	case Length:
	case ChunkData:
	    while (remain) {
		if ((n = take(r, remain)) < 0)
		    return sockfail();
		if (!n)
		    return Step::Wait;
		remain -= (ulong)n;
	    }
	    if (phase == Length)
		phase = Complete;
	    else
		start(ChunkEnd, 2);
	    break;
	case Eof:
	    for (;;) {
		if (r.sz + 1 >= r.cap) {
		    if (r.sz >= MaxBody)
			return fail(EFBIG);
		    if ((s = reserve(r, r.sz + 1, grow)) != Step::Done)
			return s;
		}
		if ((n = take(r, r.cap - 1 - r.sz)) > 0)
		    continue;
		if (!n)
		    return Step::Wait;
		if (sock.err() != EOF)
		    return sockfail();
		break;
	    }
	    phase = Complete;
	    break;
	case ChunkSize: {
	    ulong len;

	    if ((s = nextline(v)) != Step::Done)
		return s;
	    v = v.substr(0, v.find_first_of("; \t"));	// drop extensions
	    if (!HTTPResponse::parsenum(v, len, true) || len > MaxBody - r.sz)
		return fail(EPROTO);
	    if (len) {
		remain = len;
		phase = ChunkData;
		if ((s = reserve(r, r.sz + len, grow)) != Step::Done)
		    return s;
	    } else {
		start(Trailers, MaxHdrs);
	    }
	    break;
	}
	case ChunkEnd:
	    if ((s = nextline(v)) != Step::Done)
		return s;
	    if (!v.empty())
		return fail(EPROTO);
	    start(ChunkSize, 1024);
	    break;
	case Trailers:
	    if ((s = nextline(v)) != Step::Done)
		return s;
	    if (v.empty())
		phase = Complete;
	    break;
	case Complete:
	    start(Status, MaxHdrs);
	    return Step::Done;
	}
    }
}

template<class S>
int HTTPParser<S>::fill(void) {
    // a write cannot make data readable so skip a read that must fail
    if (idle || emptied())
	return 0;

    const bool ok = sb.sgetc() != EOF;

    idle = emptied();
    return ok ? 1 : idle ? 0 : -1;
}

// a line without its terminator: in the buffer unless it spans reads
template<class S>
HTTPParser<S>::Step HTTPParser<S>::nextline(string_view &out) {
    if (!partial)
	line.clear();
    for (;;) {
	const string_view v = sb.avail();
	const size_t pos = v.find('\n');
	const size_t n = pos == v.npos ? v.size() : pos;

	if (n >= left)
	    return fail(EMSGSIZE);
	if (pos != v.npos) {
	    left -= n + 1;
	    if (partial) {
		line.append(v.data(), n);
		out = line;
		partial = false;
	    } else {
		out = v.substr(0, n);
	    }
	    sb.consume(n + 1);
	    if (!out.empty() && out.back() == '\r')
		out.remove_suffix(1);
	    return Step::Done;
	}
	line.append(v.data(), n);
	left -= n;
	sb.consume(n);
	partial = true;

	const int rc = fill();

	if (rc <= 0)
	    return rc ? sockfail() : Step::Wait;
    }
}

template<class S> template<class G>
HTTPParser<S>::Step HTTPParser<S>::reserve(const HTTPResponse &r, ulong need,
    G &grow) {
    if (r.result && r.cap > need)
	return Step::Done;

    const Step s = grow(r.capfor(need, phase == Length));

    if (s == Step::Proto)
	ecode = ENOMEM;
    return s;
}

template<class S>
void HTTPParser<S>::reset(void) {
    sb.reset();
    idle = partial = false;
    line.clear();
    start(Status, MaxHdrs);
}

// body bytes are read straight into the result once the buffer is empty
template<class S>
long HTTPParser<S>::take(HTTPResponse &r, ulong want) {
    const string_view v = sb.avail();
    long n;

    if (!v.empty()) {
	n = (long)min((ulong)v.size(), want);
	memcpy(r.result + r.sz, v.data(), (size_t)n);
	sb.consume((size_t)n);
    } else if (emptied() && phase != Eof) {
	return 0;	// only a read can see the end of an Eof body
    } else if ((n = sock.read(r.result + r.sz, (uint)min(want,
	(ulong)INT_MAX))) <= 0) {
	return n;
    }
    r.sz += (ulong)n;
    r.result[r.sz] = '\0';		// reserve() left room
    return n;
}

HTTPClient::~HTTPClient() {
    parser.reset();
}

bool HTTPClient::close(void) {
    streaming = false;
    parser.reset();
    return sock.close();
}

bool HTTPClient::connect(Socket &s, bool keepalive) {
    Sockaddr sa(Sockaddr::UNSPEC);

    if (!s.open() || !s.peername(sa))
	return false;
    ka = keepalive;
    addr = sa;
    hostval = hosthdr(addr);
    shared = true;
    sock = s;
    setup();
    dlogd(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("fd"),
	s.fd()));
    return true;
}

bool HTTPClient::connect(const Sockaddr &sa, bool keepalive, uint to) {
    const bool same = sa == addr && sa.requestedhost() == addr.requestedhost();

    ka = keepalive;
    cto = to;
    if (same && sock.open())
	return true;
    if (!same || hostval.empty()) {
	addr = sa;
	hostval = hosthdr(addr);
    }
    if (shared) {
	sock = SOCK_INVALID;
	shared = false;
    } else {
	sock.close();
    }
    if (!sock.connect(addr, to)) {
	sockerr = sock.err();
	dlogi(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	    addr.str()), Log::error(sock.errstr()));
	close();
	return false;
    }
    setup();
    if (!onconnect()) {
	sockerr = sock.err() ? sock.err() : EPROTO;
	dlogi(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	    addr.str()), Log::error(sock.errstr()));
	close();
	return false;
    }
    dlogd(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	addr.ipstr()));
    return true;
}

HTTPClient::Step HTTPClient::receive(bool head, bool &keep) {
    const Step s = parser.advance(*this, head, [this](ulong newcap) {
	return resize(newcap) ? Step::Done : Step::Proto;
    });

    if (s == Step::Done)
	keep = parser.keep() && ka && !parser.buffered();
    else
	sockerr = parser.err();
    return s;
}

WARN_PUSH_DISABLE(26461)
bool HTTPClient::send(const tchar *op, const tchar *path, const void *data,
    // cppcheck-suppress constParameterPointer
    ulong datasz, msghdr *msgh) {
    bool keep = false;
    bool ret = false;

    if (streaming)
	close();
    reset();
    if (!buildreq(req, op, path, hostval, ka, msgh ? nullptr : data,
	datasz))
	return false;

    const bool head = !tstrcmp(op, T("HEAD"));
    if (datasz > SIZE_MAX - req.size()) {
	sockerr = EOVERFLOW;
	return false;
    }
    for (bool first = true; sock.open() || (!msgh && connect(addr, ka,
	cto)); first = false) {
	const bool retry = first && ka && !msgh;
	const bool idem = retry && idempotent(op);
	const bool timed = idem && rto > 200;
	const msec_t start = timed ? mticks() : 0;
	size_t off = 0;
	bool sent = true;

	if (msgh) {
#ifdef _WIN32
	    sent = false;
	    sock.err(EOPNOTSUPP);
#else
	    iovec iov[2] = { { (void *)req.data(), req.size() },
		{ (void *)data, datasz } };
	    msghdr msg = *msgh;

	    msg.msg_iov = iov;
	    msg.msg_iovlen = datasz ? 2 : 1;
	    const ssize_t n = sock.sendmsg(msg, sock.layer() ? 0 : MSG_NOSIGNAL);

	    sent = n > 0;
	    off = sent ? (size_t)n : 0;
#endif
	}
	if (sent)
	    sent = transmit(data, datasz, off);
	if (sent) {
	    const Step step = receive(head, keep);

	    ret = step == Step::Done;
	    if (step != Step::Sock || sts)
		break;
	} else {
	    sockerr = sock.err();
	}
	// TLS can send bytes before reporting any write progress.
	const bool again = retry && (sent ? timed && mticks() - start <
	    rto - 200 : idem || (!off && !sock.layer()));

	close();
	if (again) {
	    dlogd(Log::mod(T("http")), Log::cmd(T("reconnect")),
		Log::kv(T("addr"), addr.ipstr()));
	    continue;
	}
	dlogn(Log::mod(T("http")), Log::cmd(T("disconnect")),
	    Log::kv(T("addr"), addr.ipstr()));
	break;
    }
    if (sts)
	dlogd(Log::mod(T("http")), Log::kv(T("addr"), addr.ipstr()),
	    Log::kv(T("path"), path), Log::kv(T("sts"), sts));
    if (ret)
	sockerr = 0;
    else if (!sockerr)
	sockerr = sock.err();
    if ((!keep && !msgh) || !ret)
	close();
    return ret;
}
WARN_POP()

bool HTTPClient::sendbegin(const tchar *op, const tchar *path) {
    ulong len = Unknown;

    if (streaming)
	close();
    reset();
    if (!buildreq(req, op, path, hostval, ka, nullptr, len))
	return false;
    if (!sock.open() && !connect(addr, ka, cto))
	return false;
    streaming = parser.buf().write(req.data(), (streamsize)req.size()) ==
	(streamsize)req.size();
    if (!streaming)
	close();
    return streaming;
}

bool HTTPClient::sendchunk(const iovec *iov, int cnt) {
    auto &sb = parser.buf();
    char hdr[24];
    ulong total = 0;

    if (!streaming)
	return false;
    for (int i = 0; i < cnt; i++)
	total += (ulong)iov[i].iov_len;
    if (!total)		// would end the body
	return true;

    char *p = to_chars(hdr, hdr + sizeof (hdr) - 2, total, 16).ptr;
    bool ok;

    *p++ = '\r';
    *p++ = '\n';
    ok = sb.write(hdr, p - hdr) == p - hdr;
    for (int i = 0; ok && i < cnt; i++) {
	const auto n = (streamsize)iov[i].iov_len;

	ok = sb.write(iov[i].iov_base, n) == n;
    }
    if (ok && sb.write("\r\n", 2) == 2 && !sb.sync())
	return true;
    sendfail();
    return false;
}

// keep an early server response, else the write error
void HTTPClient::sendfail(void) {
    const int e = sock.err();
    bool keep;

    streaming = false;
    parser.buf().reset();	// a read needs the put area empty
    if ((e == EPIPE || e == ECONNRESET) && receive(false, keep) == Step::Done) {
	sockerr = 0;
    } else {
	sockerr = e;
	sts = 0;
    }
    sock.close();
}

bool HTTPClient::sendend(void) {
    auto &sb = parser.buf();
    bool keep = false;

    if (!streaming)
	return sts && !sockerr;
    if (sb.write("0\r\n\r\n", 5) != 5 || sb.sync()) {
	sendfail();
	return sts && !sockerr;
    }
    streaming = false;
    if (receive(false, keep) == Step::Done) {
	sockerr = 0;
	if (!keep)
	    sock.close();
    } else {
	sock.close();
    }
    return !sockerr;
}

void HTTPClient::setup(void) {
    streaming = false;
    sock.nodelay(true);
    sock.rtimeout(rto);
    sock.wtimeout(wto);
    parser.reset();
}

bool HTTPClient::transmit(const void *data, ulong datasz, size_t &off) {
    const size_t hsz = req.size();
    const size_t total = hsz + datasz;

    while (off < total) {
	const size_t h = off < hsz ? min(hsz - off, (size_t)INT_MAX) : 0;
	ssize_t n;

	if (h && datasz && h == hsz - off && h < (size_t)INT_MAX) {
	    iovec iov[2];

	    iov[0].iov_base = req.data() + off;
	    iov[0].iov_len = (iovlen_t)h;
	    iov[1].iov_base = (char *)data;
	    iov[1].iov_len = (iovlen_t)min((size_t)datasz, (size_t)INT_MAX - h);
	    n = sock.writev(iov, 2);
	} else if (h) {
	    n = sock.write(req.data() + off, (uint)h);
	} else {
	    const size_t done = off - hsz;

	    n = sock.write((const char *)data + done,
		(uint)min(datasz - (ulong)done, (ulong)INT_MAX));
	}
	if (n <= 0)
	    return false;
	off += (size_t)n;
    }
    return true;
}

void AsyncHTTPClient::Request::result_grow(DispatchObjCB cb, DispatchObj &co,
    char *, uint, uint newsize) {
    resize(newsize);
    cb(&co);
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
    uncertain = false;
    written = 0;
    reset();
    if (!buildreq(req, op, path, c.host, true, data, datasz)) {
	caller = nullptr;
	co.ready(cb);
	return false;
    }
    head = !tstrcmp(op, T("HEAD"));
    idem = idempotent(op);
    return true;
}

AsyncHTTPClient::AsyncHTTPClient(IOSocket *s, const Sockaddr &sa, Timing *tm):
    addr(sa), host(HTTPResponse::hosthdr(sa)), intake(*new Intake(*s, *this)),
    parser(*s), sock(*s), timing(tm) {
    if (timing) {
	const tstring ip(addr.ipstr());

	ckey = T("conn:") + ip;
	rkey = T("read:") + ip;
	wkey = T("write:") + ip;
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
    if (!onconnect(sock)) {
	dlogi(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	    addr.str()), Log::error(sock.errstr()));
	down(EPROTO, Down::Fail);
    } else if (sock.layer()) {
	shake();
    } else {
	opened();
    }
}

void AsyncHTTPClient::opened(void) {
    state = Open;
    parser.reset();
    dlogd(Log::mod(T("http")), Log::cmd(T("connect")), Log::kv(T("addr"),
	addr.ipstr()));
    io();
}

void AsyncHTTPClient::shake(void) {
    int e;

    if (state != Connecting)
	return;
    if (sock.reason() == DispatchTimeout) {
	e = ETIMEDOUT;
    } else if (sock.error()) {
	e = sock.err() ? sock.err() : ECONNRESET;
    } else {
	const int ret = sock.handshake(IOSocket::onshake, cto);

	if (ret > 0)
	    opened();
	if (ret >= 0)
	    return;
	e = sock.err() ? sock.err() : EPROTO;
    }
    dlogi(Log::mod(T("http")), Log::cmd(T("handshake")), Log::kv(T("addr"),
	addr.str()), Log::error(e == ETIMEDOUT ? tstring(T("timeout")) :
	sock.errstr()));
    down(e, Down::Fail);
}

void AsyncHTTPClient::down(int err, Down how) {
    deque<Request *> all(rq), dead;

    all.insert(all.end(), wq.begin(), wq.end());
    rq.clear();
    wq.clear();
    sock.cancel();
    (void)sock.close();
    state = Closed;
    growing = false;
    parser.reset();
    for (size_t i = 0; i < all.size(); i++) {
	Request *r = all[i];
	const bool retry = how == Down::Retry && i == 0;

	if (how == Down::Fail || (retry && r->attempts) || !r->replayable()) {
	    dead.push_back(r);
	} else {
	    if (retry)
		++r->attempts;
	    r->reset();
	    r->written = 0;
	    wq.push_back(r);
	}
    }
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

void AsyncHTTPClient::enqueue(Request &r) {
    requests++;
    if (timing)
	r.start = Timing::now();
    wq.push_back(&r);
    if (state == Closed)
	connect();
}

AsyncHTTPClient::Flow AsyncHTTPClient::finish(Request &r) {
    const bool keep = parser.keep();

    rq.pop_front();
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
    if (event && sock.reason() != DispatchNone)
	parser.wake();
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

AsyncHTTPClient::Flow AsyncHTTPClient::readall(void) {
    using enum Flow;
    Flow f;

    while (!rq.empty()) {
	Request &r = *rq.front();

	switch (parser.advance(r, r.head, [this, &r](ulong newcap) {
	    return reserve(r, newcap); })) {
	case Step::Done:
	    if ((f = finish(r)) != Ok)
		return f;
	    break;
	case Step::Wait:
	    return Wait;
	case Step::Proto:
	    return bad(parser.err());
	case Step::Sock:
	    down(parser.err(), Down::Retry);
	    return Stop;
	}
    }
    // idle: unsolicited data is an error and a read error means it closed
    const int n = parser.buffered() ? 1 : parser.fill();

    if (n)
	down(n > 0 ? EPROTO : sock.err(), Down::Retry);
    return n ? Stop : Wait;
}

AsyncHTTPClient::Step AsyncHTTPClient::reserve(Request &r, ulong newcap) {
    using enum Step;

    r.cap = newcap;
    growing = inreserve = true;
    r.result_grow(IOSocket::ongrown, sock, r.result, (uint)r.sz, (uint)newcap);
    inreserve = false;
    // cppcheck-suppress knownConditionTrueFalse
    if (growing)
	return Wait;				// subclass is allocating
    if (r.result)
	return Done;
    r.sz = r.cap = 0;
    return Proto;
}

void AsyncHTTPClient::status(tostream &out, uint indent) const {
    const tstring pad(indent, T(' '));
    static constexpr const tchar *names[] = {
	T("Closed"), T("Connecting"), T("Open")
    };

    out << pad << T("<state>") << names[state.load()] << T("</state>\n") <<
	pad << T("<pending>") << numPending() << T("</pending>\n") <<
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

AsyncHTTPClient::Flow AsyncHTTPClient::writeall(void) {
    iovec iov[2 * MaxPipeline];

    // limit the requests that must be resent if the server closes
    while (!wq.empty() && rq.size() < MaxPipeline) {
	Request &oldest = *wq.front();
	const size_t room = MaxPipeline - rq.size();
	int cnt = 0;
	size_t total = 0;
	auto add = [&](const void *p, size_t len) {
	    iov[cnt].iov_base = (char *)p;	// NOSONAR
	    iov[cnt++].iov_len = (iovlen_t)len;
	    total += len;
	};

	for (size_t i = 0, count = min(wq.size(), room); i < count; i++) {
	    const Request &r = *wq[i];
	    ulong off = r.written;

	    // RFC 9112 9.3.2: a non-idempotent request is not pipelined
	    if (!r.idem && (i || !rq.empty()))
		break;
	    if (off < r.req.size()) {
		add(r.req.data() + off, r.req.size() - off);
		off = 0;
	    } else {
		off -= (ulong)r.req.size();
	    }
	    if (r.datasz > off)
		add((const char *)r.datap + off, r.datasz - (size_t)off);
	    if (!r.idem)
		break;
	}
	if (!cnt)
	    break;

	// A TLS write can send bytes before reporting progress.
	if (!oldest.idem && sock.layer())
	    oldest.uncertain = true;

	const ssize_t n = sock.writev(iov, cnt);

	if (n < 0) {
	    down(sock.err(), Down::Retry);
	    return Flow::Stop;
	}
	for (size_t left = (size_t)n; left; ) {
	    Request &r = *wq.front();
	    const size_t len = r.req.size() + r.datasz - r.written;

	    if (left < len) {
		r.written += (ulong)left;
		break;
	    }
	    left -= len;
	    r.written += (ulong)len;
	    wq.pop_front();
	    rq.push_back(&r);
	    if (timing)
		r.start = timing->record(wkey, r.start);
	}
	if ((size_t)n < total)
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
