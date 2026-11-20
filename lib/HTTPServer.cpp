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
#include <algorithm>
#include <ctime>
#include <format>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif
#include "HTTPClient.h"
#include "HTTPServer.h"
#include "Log.h"
#include "Timing.h"

static constexpr ulong MaxHdrs = 64UL * 1024;	// request + header bytes
static constexpr size_t MaxHdrCount = 100;
static constexpr ulong MaxBody = 256UL * 1024 * 1024;
static constexpr ulong MaxRead = 64UL * 1024;	// larger files are mmapped
static constexpr char CRLF[] = "\r\n";

bool HTTPServerSocket::date;
string HTTPServerSocket::docroot;
atomic_bool HTTPServerSocket::paused;

// Prometheus default buckets
static constexpr double DurationBounds[] = {
    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10
};

static struct {
    atomic<ulong> accepted, conns;
    atomic<ulong> codes[5];
    atomic<ulong> durations[std::size(DurationBounds) + 1];
    atomic<usec_t> duration;
    atomic<ullong> rxbytes, txbytes;
} stats;

const char *HTTPServerSocket::statusmsg(uint sts) {
    switch (sts) {
    case 200: return "OK";
    case 201: return "Created";
    case 202: return "Accepted";
    case 203: return "Non-Authoritative Information";
    case 204: return "No Content";
    case 205: return "Reset Content";
    case 206: return "Partial Content";
    case 300: return "Multiple Choices";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 305: return "Use Proxy";
    case 306: return "Reserved";
    case 307: return "Temporary Redirect";
    case 308: return "Permanent Redirect";
    case 400: return "Bad Request";
    case 401: return "Unauthorized";
    case 402: return "Payment Required";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 407: return "Proxy Authentication Required";
    case 408: return "Request Timeout";
    case 409: return "Conflict";
    case 410: return "Gone";
    case 411: return "Length Required";
    case 412: return "Precondition Failed";
    case 413: return "Request Entity Too Large";
    case 414: return "Request-URI Too Long";
    case 415: return "Unsupported Media Type";
    case 416: return "Requested Range Not Satisfiable";
    case 417: return "Expectation Failed";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    case 504: return "Gateway Timeout";
    case 505: return "HTTP Version Not Supported";
    default: return sts < 300 ? "OK" : "HTTP error";
    }
}

// RFC 9110 5.6.7 IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
const char *HTTPServerSocket::httpdate(time_t t, char (&buf)[30]) {
    static constexpr char days[] = "SunMonTueWedThuFriSat";
    static constexpr char mons[] = "JanFebMarAprMayJunJulAugSepOctNovDec";
    struct tm tm = {};
    auto two = [&buf](int pos, int n) {
	buf[pos] = (char)('0' + n / 10);
	buf[pos + 1] = (char)('0' + n % 10);
    };

    gmtime_r(&t, &tm);
    memcpy(buf, days + 3 * (size_t)tm.tm_wday, 3);
    memcpy(buf + 3, ", ", 2);
    two(5, tm.tm_mday);
    buf[7] = ' ';
    memcpy(buf + 8, mons + 3 * (size_t)tm.tm_mon, 3);
    buf[11] = ' ';
    two(12, (tm.tm_year + 1900) / 100);
    two(14, (tm.tm_year + 1900) % 100);
    buf[16] = ' ';
    two(17, tm.tm_hour);
    buf[19] = ':';
    two(20, tm.tm_min);
    buf[22] = ':';
    two(23, tm.tm_sec);
    memcpy(buf + 25, " GMT", 5);
    return buf;
}

// read exactly len bytes: a single read() is short for large or slow files
bool HTTPServerSocket::readfull(int fd, char *buf, size_t len) {
    while (len) {
	long n = (long)::read(fd, buf, (uint)min(len, (size_t)1 << 30));

	if (n > 0) {
	    buf += n;
	    len -= (size_t)n;
	} else if (n == 0 || errno != EINTR) {
	    return false;
	}
    }
    return true;
}

HTTPServerSocket::HTTPServerSocket(Dispatcher &d, const Socket &sock):
    DispatchServerSocket(d, sock) {
    static const bool configured = (configure(d.config()), true);

    (void)configured;
    stats.accepted.fetch_add(1, memory_order_relaxed);
    stats.conns.fetch_add(1, memory_order_relaxed);
}

HTTPServerSocket::~HTTPServerSocket(void) {
    stats.conns.fetch_sub(1, memory_order_relaxed);
    free(data);
    unmap();
    if (postdatasz)
	delete [] postdata;
}

void HTTPServerSocket::unmap(void) {
    if (fmap) {
#ifdef _WIN32
	UnmapViewOfFile(fmap);
#else
	munmap(fmap, fmapsz);
#endif
	fmap = nullptr;
    }
}

void HTTPServerSocket::postdata_grow(DispatchObjCB cb, ulong keepsize, ulong
    newsize) {
    char *old = postdata;

    postdata = new char[newsize];
    memcpy(postdata, old, keepsize);
    if (postdatasz)
	delete [] old;
    ready(cb);
}

void HTTPServerSocket::readhdrs() {
    uint in;
    uint room = (uint)(sz - datasz);

    if (error()) {
	disconnect();
	return;
    }
    if (room <= 1) {
	char *p;

	if (sz > MaxHdrs) {
	    cmd = "BADCMD";
	    path = "/";
	    prot = "HTTP/1.0";
	    error(431, true);
	    return;
	}

	sz = min(sz < 1000 ? 1000UL : sz * 2, MaxHdrs + 1);
	room = (uint)(sz - datasz);
	if ((p = (char *)realloc(data, sz)) == nullptr) {
	    disconnect();
	    return;
	}
	data = p;
    }
    // - 1 to leave room for savechar logic
    in = (uint)read(data + datasz, room - 1);
    if (in == (uint)-1) {
	disconnect();
	return;
    }
    if (datasz + in > 3) {
	ulong oldsz = datasz;

	room = datasz < 3 ? (uint)datasz : 3;
	datasz += in;
	// coverity[string_null : FALSE ]
	scan(data + oldsz - room, in + room);
    } else {
	datasz += in;
	readable(readhdrs, rto);
    }
}

void HTTPServerSocket::readpost() {
    ulong in = 0;
    // chunked: size unknown so always use own buffer
    bool chunky = postsz == (ulong)-1;
    bool eof = false;
    ulong room = postdatasz ? postdatasz - postin : chunky ? 0 : sz - datasz;
    ulong left = chunky ? room : postsz - postin;

    if (msg == DispatchTimeout) {
	disconnect();
	return;
    }
    if (msg != DispatchClose && (chunky ? room <= 100 : !postdatasz && room <
	left + 1)) {
	if (chunky) {
	    in = postin < 8UL * 1024 ? 16UL * 1024 : postin * 2;
	    if (in > MaxBody)
		in = MaxBody;
	    if (in <= postin + 100) {
		error(413, true);
		return;
	    }
	} else {
	    in = postsz;
	}
	postdata_grow(readpost, postin, in + 1);
	postdatasz = in;
	return;
    }
    if (msg == DispatchClose || (in = (ulong)read(postdata + postin,
	(uint)left)) == (ulong)-1) {
	// a half closed client may have already sent the whole chunked body
	if (!chunky || !postdatasz) {
	    disconnect();
	    return;
	}
	eof = true;
	in = 0;
    }
    if (!postdatasz)
	datasz += in;
    postin += in;
    left -= in;
    // decode chunks in place: [0, chunkin) is decoded body
    while (postchunking && chunkin < postin) {
	ulong chunksize = 0;
	ulong pos = chunkin;

	// skip over terminating CRLF of previous chunk
	if (chunkin && !chunktrailer) {
	    if (postin < chunkin + 2)
		break;
	    if (postdata[chunkin] != '\r' || postdata[chunkin + 1] != '\n') {
		error(400, true);
		return;
	    }
	    pos += 2;
	}
	if (postin <= pos)
	    break;

	const char *lf = (const char *)memchr(postdata + pos, '\n', postin -
	    pos);

	if (!lf)
	    break;
	if (chunktrailer) {
	    if (postdata[pos] == '\r' || postdata[pos] == '\n') {
		// final CRLF
		postsz = chunkin;
		left = 0;
	    }
	} else {
	    const char *b = postdata + pos;
	    auto [e, ec] = from_chars(b, lf, chunksize, 16);

	    if (ec == errc::result_out_of_range) {
		error(413, true);
		return;
	    }
	    if (ec != errc() ||
		(e < lf && !string_view("\r; \t").contains(*e))) {
		error(400, true);
		return;
	    }
	    if (chunksize > MaxBody - chunkin) {
		error(413, true);
		return;
	    }
	}
	++lf;

	ulong used = (ulong)(lf - (postdata + chunkin));

	memmove(postdata + chunkin, lf, (size_t)(postdata + postin - lf));
	postin -= used;
	if (postsz != (ulong)-1)
	    break;
	else if (chunksize == 0)
	    chunktrailer = true;
	else
	    chunkin += chunksize;
    }
    if (left || postsz == (ulong)-1) {
	if (eof)
	    disconnect();
	else
	    readable(readpost, rto);
    } else {
	savechar = postdata[postsz];
	postdata[postsz] = '\0';
	begin = uticks();		// exclude the upload from the timing
	exec();
    }
}

void HTTPServerSocket::scan(char *buf, ulong len, bool append) {
    size_t pos = string_view(buf, len).find("\r\n\r\n");

    if (pos == string_view::npos) {
	readable(readhdrs, rto);
	return;
    }
    buf += pos;
    postdata = buf + 4;
    buf[1] = '\0';
    if (append)
	ready(parse);
    else
	parse();
}

#pragma warning(disable: 26430)
void HTTPServerSocket::parse(void) {
    char *p, *pp, *end;
    char *buf = data;
    const char *val;
    bool noprot;

    begin = uticks();
    path = "/";
    prot = "HTTP/1.0";
    postsz = 0;
    // scan() ended the header block with a NUL, so any earlier one is injected
    if (strlen(data) != (size_t)(postdata - 3 - data)) {
	cmd = "BADCMD";
	error(400, true);
	return;
    }
    // RFC 9112 2.2: ignore empty lines before the request line
    buf += strspn(buf, " \t\r\n");
    cmd = buf;
    p = buf + strcspn(buf, " \t\r");
    // a bare LF would be a line end to a lenient peer
    if (p == buf || (*p != ' ' && *p != '\t') ||
	memchr(buf, '\n', strcspn(buf, "\r"))) {
	cmd = "BADCMD";
	error(400, true);
	return;
    }
    *p++ = '\0';
    p += strspn(p, " \t");
    path = pp = p;
    p += strcspn(p, " \t\r");
    noprot = (*p == '\r');
    *p++ = '\0';
    // RFC 9112 3.2.2: absolute-form target so drop the scheme and authority
    if (*pp != '/' && (!strnicmp(pp, "http://", 7) ||
	!strnicmp(pp, "https://", 8))) {
	char *s = strchr(pp, ':') + 3;

	s += strcspn(s, "/?");
	if (*s != '/')
	    *--s = '/';
	path = pp = s;
    }
    postargs.clear();
    if ((pp = strchr(pp, '?')) == nullptr) {
	argdata.clear();
	args.clear();
    } else {
	*pp++ = '\0';
	argdata = pp;
	urldecode(pp, args);
    }
    if (!noprot) {
	p += strspn(p, " \t");
	prot = p;
	p += strcspn(p, " \t\r");
	// trailing blanks must not hide the headers
	while (*p == ' ' || *p == '\t')
	    *p++ = '\0';
	if (*p != '\r') {
	    prot = "HTTP/1.0";
	    error(400, true);
	    return;
	}
	*p++ = '\0';
    }
    if (strnicmp(prot, "HTTP/", 5) != 0 || (uchar)(prot[5] - '0') > 9 ||
	prot[6] != '.' || (uchar)(prot[7] - '0') > 9 || prot[8]) {
	prot = "HTTP/1.0";
	error(400, true);
	return;
    } else if (prot[5] != '1') {
	prot = "HTTP/1.1";
	error(505, true);
	return;
    } else if (prot[7] > '1') {
	prot = "HTTP/1.1";
    }
    if (*p == '\n')
	p++;
    buf = p;
    attrs.clear();
    while (*buf) {
	bool crlf = true;

	if ((end = strchr(buf, '\r')) == nullptr) {
	    end = buf + strlen(buf);
	    crlf = false;
	} else if (end[1] != '\n') {
	    // only the final CR is followed by the NUL scan() inserted
	    if (end[1]) {
		error(400, true);
		return;
	    }
	    crlf = false;
	}
	// a bare LF would be a line end to a lenient peer
	if (memchr(buf, '\n', (size_t)(end - buf))) {
	    error(400, true);
	    return;
	}
	// obsolete line folding is a request smuggling vector
	if (crlf && (end[2] == ' ' || end[2] == '\t')) {
	    error(400, true);
	    return;
	}
	p = end;
	while (p > buf && (p[-1] == ' ' || p[-1] == '\t'))
	    p--;
	*p = '\0';
	if (p == buf) {
	    // a blank line ends the headers but a blank-looking one is bogus
	    if (end != buf) {
		error(400, true);
		return;
	    }
	    break;
	}
	// RFC 9112 5.1: reject whitespace in or around a field name
	if ((p = strchr(buf, ':')) == nullptr || p == buf ||
	    strcspn(buf, " \t") < (size_t)(p - buf)) {
	    error(400, true);
	    return;
	}
	*p++ = '\0';
	p += strspn(p, " \t");
	if (attrs.size() >= MaxHdrCount) {
	    error(431, true);
	    return;
	}

	auto [it, added] = attrs.try_emplace(buf, p);

	if (!added) {
	    if (stringieq(buf, "content-length") ||
		stringieq(buf, "host") ||
		stringieq(buf, "transfer-encoding")) {
		error(400, true);
		return;
	    }
	    it->second = p;
	}
	if (!crlf || !end[1])
	    break;
	buf = end + 2;
    }
    // RFC 9112 3.2: HTTP/1.1 requires a Host
    if (prot[7] == '1' && !attr("host")) {
	error(400, true);
	return;
    }
    val = attr("transfer-encoding");
    postchunking = false;
    if (val) {
	if (attr("content-length")) {
	    error(400, true);
	    return;
	}
	// bare chunked only
	if (!stringieq(val, "chunked")) {
	    error(501, true);
	    return;
	}
	postchunking = true;
	chunktrailer = false;
	chunkin = 0;
	postsz = (ulong)-1;
    } else if ((val = attr("content-length")) != nullptr) {
	auto [e, ec] = from_chars(val, val + strlen(val), postsz);

	if (ec == errc::result_out_of_range || (ec == errc() && postsz >
	    MaxBody)) {
	    error(413, true);
	    return;
	}
	if (ec != errc() || *e) {
	    error(400, true);
	    return;
	}
    }
    postin = min(datasz - (ulong)(postdata - data), postsz);
    if (postin < postsz) {
	if (prot[7] == '1' && (val = attr("expect")) != nullptr &&
	    stringieq(val, "100-continue")) {
	    static constexpr char cont[] = "HTTP/1.1 100 Continue\r\n\r\n";

	    // best effort: the client sends the body after a timeout anyway
	    (void)write(cont, (uint)sizeof (cont) - 1);
	}
	postpre(readpost);
    } else {
	savechar = postdata[postsz];
	postdata[postsz] = '\0';
	exec();
    }
}

void HTTPServerSocket::exec(void) {
    if (paused.load(memory_order_relaxed)) {
	error(503);
    } else if (LIKELY(stringieq(cmd, "GET"))) {
	get(false);
    } else if (stringieq(cmd, "HEAD")) {
	get(true);
    } else if (stringieq(cmd, "POST")) {
	const char *val = attr("content-type");

	if (val != nullptr &&
	    stringieq(val, "application/x-www-form-urlencoded"))
	    urldecode(postdata, postargs);
	post();
    } else if (stringieq(cmd, "PUT")) {
	put();
    } else if (stringieq(cmd, "DELETE")) {
	del();
    } else {
	error(501);
    }
}

void HTTPServerSocket::unescape(char *s) {
#ifdef UNICODE
    tstring t(achartotchar(s));

    URL::unescape(t);
    strcpy(s, tstringtoachar(t));
#else
    URL::unescape(s);
#endif
}

void HTTPServerSocket::urldecode(char *buf, attrmap &amap) const {
    amap.clear();
    while (buf) {
	char *rest = strchr(buf, '&');
	char *eq;

	if (rest)
	    *rest++ = '\0';
	buf += strspn(buf, " \t");
	if (*buf) {
	    // split before unescaping so an encoded '=' stays in its field
	    if ((eq = strchr(buf, '=')) != nullptr)
		*eq++ = '\0';
	    unescape(buf);
	    if (eq)
		unescape(eq);
	    amap[buf] = eq ? eq : "";
	}
	buf = rest;
    }
}

void HTTPServerSocket::configure(const Config &cfg) {
    tstring dir(cfg.get(T("installdir")));

    docroot = tstringtoastring(cfg.get(T("docroot"), dir.empty() ?
	tstring(T("htdocs")) : dir + T("/htdocs"), section()));
}

void HTTPServerSocket::keepalive(void) {
    const char *val = attr("Pragma");

    ka = prot[7] == '1';		// HTTP 1.1
    if (val != nullptr && stringieq(val, "keep-alive")) {
	ka = true;
    } else if ((val = attr("Connection")) != nullptr) {
	if (hastoken(val, "close"))
	    ka = false;
	else if (hastoken(val, "keep-alive"))
	    ka = true;
    }
    if (ka)
	hdrs.write("Connection: keep-alive\r\n");
    else if (prot[7] == '1')
	hdrs.write("Connection: close\r\n");
}

void HTTPServerSocket::send(void) {
    ulong out;

    if (error()) {
	disconnect();
	return;
    }
    if (ka && nagleon) {
	nodelay(true);
	nagleon = false;
    }
    out = (ulong)writev(iov, 3);
    if (out != (ulong)-1) {
	bool more = false;

	for (auto &v : iov) {
	    ulong n = min(out, (ulong)v.iov_len);

	    v.iov_len -= (iovlen_t)n;
	    v.iov_base = (char *)v.iov_base + n;
	    out -= n;
	    more |= v.iov_len != 0;
	}
	if (more) {
	    writeable(send, wto);
	    return;
	}
    }
    unmap();
    if (ka && out != (ulong)-1) {
	// own body buffer may hold pipelined bytes read past a chunked body
	datasz = postdatasz ? postin - postsz : datasz - postsz -
	    (ulong)(postdata - data);
	replydone(senddone);
    } else {
	disconnect();
    }
}

void HTTPServerSocket::senddone() {
    _status = 0;
    postdata[postsz] = savechar;
    if (postdatasz) {
	// move pipelined bytes from the body buffer to the header buffer
	if (datasz >= sz) {
	    free(data);
	    sz = datasz + 1000;
	    if ((data = (char *)malloc(sz)) == nullptr) {
		disconnect();
		return;
	    }
	}
	memcpy(data, postdata + postsz, datasz);
	postdata_free();
	postdatasz = 0;
    } else if (datasz) {
	memmove(data, postdata + postsz, datasz);
    }
    if (datasz)
	scan(data, datasz, true);
    else
	readable(readhdrs, rto);
}

// REST resource: the first segment or api/[vN/]resource
string_view HTTPServerSocket::resource(string_view p) {
    size_t end;

    if (p.starts_with('/'))
	p.remove_prefix(1);
    end = p.find('/');
    if (end != p.npos && p.substr(0, end) == "api") {
	size_t next = p.find('/', end + 1);

	if (next != p.npos && p[end + 1] == 'v' && isdigit((uchar)p[end + 2]))
	    next = p.find('/', next + 1);
	end = next;
    }
    return p.substr(0, end);
}

void HTTPServerSocket::reply(const char *p, ulong len) {
    char key[64];
    char *k = key;
    char *const last = key + sizeof (key) - 1;
    // RFC 9110 6.4.1: these have no body and 204/304 no length either
    const bool nolen = _status == 204 || _status == 304;
    const bool nobody = nolen || stringieq(cmd, "HEAD");
    const usec_t elapsed = uticks() - begin;

    if (len == (ulong)-1)
	len = p ? (ulong)strlen(p) : 0;
    if (!nolen) {
	hdrs.writev("Content-Length: ", (ulong)ss.size() + len, CRLF);
    }
    hdrs.write(CRLF);
    iov[0].iov_base = (char *)hdrs.str();	// NOSONAR
    iov[0].iov_len = (iovlen_t)hdrs.size();
    iov[1].iov_base = (char *)ss.str();		// NOSONAR
    iov[1].iov_len = nobody ? 0 : (iovlen_t)ss.size();
    iov[2].iov_base = (char *)p;		// NOSONAR
    iov[2].iov_len = nobody ? 0 : (iovlen_t)len;
    if (_status >= 100 && _status < 600)
	stats.codes[_status / 100 - 1].fetch_add(1, memory_order_relaxed);
    stats.durations[ranges::lower_bound(DurationBounds, (double)elapsed /
	1e6) - DurationBounds].fetch_add(1, memory_order_relaxed);
    stats.duration.fetch_add(elapsed, memory_order_relaxed);
    if (postsz != (ulong)-1)
	stats.rxbytes.fetch_add(postsz, memory_order_relaxed);
    stats.txbytes.fetch_add(iov[0].iov_len + iov[1].iov_len + iov[2].iov_len,
	memory_order_relaxed);
    // Timing keeps every key forever: only 2xx API replies use a path prefix
    if (_status >= 200 && _status < 300) {
	const string_view res(staticfile ? "file" : resource(path));

	for (const char *s = cmd; *s && k < last; s++)
	    *k++ = (char)tolower((uchar)*s);
	for (const char *s = "::"; *s && k < last; s++)
	    *k++ = *s;
	for (size_t u = 0; u < res.size() && k < last; ++u)
	    *k++ = res[u];
    } else {
	memcpy(key, "http::", 6);
	k = to_chars(key + 6, last, _status).ptr;
    }
    *k = '\0';
    staticfile = false;
#ifdef UNICODE
    dtiming.add(achartowstring(string_view(key, (size_t)(k - key))).c_str(),
	elapsed);
#else
    dtiming.add(key, (uint)(k - key), elapsed);
#endif
    if (_status < 400)
	dlogl(Log::Info, Log::cmd(cmd), Log::kv(T("path"), path),
	    Log::kv(T("sts"), _status), Log::kv(T("duration"), elapsed / 1000));
    else
	dlogl(Log::Note, Log::cmd(cmd), Log::kv(T("path"), path),
	    Log::kv(T("sts"), _status));
    send();
}

void HTTPServerSocket::reply(int fd, ulong len) {
    if (len <= MaxRead) {
	char buf[4096];

	for (ulong n = len; n; ) {
	    ulong in = min(n, (ulong)sizeof (buf));

	    if (!readfull(fd, buf, in)) {
		error(500);
		return;
	    }
	    ss.write(buf, (streamsize)in);
	    n -= in;
	}
	len = 0;
    } else {
#ifdef _WIN32
	HANDLE hdl;

	if ((hdl = CreateFileMapping((HANDLE)(ullong)fd, NULL, PAGE_READONLY,
	    0, (DWORD)len, NULL)) == nullptr) {
	    error(404);
	    return;
	}
	if ((fmap = (char *)MapViewOfFile(hdl, FILE_MAP_READ,
	    0, 0, len)) == nullptr) {
	    CloseHandle(hdl);
	    error(404);
	    return;
	}
	CloseHandle(hdl);
#else
	void *p = mmap(nullptr, len, PROT_READ, MAP_PRIVATE, fd, 0);

	if (p == MAP_FAILED) {
	    error(500);
	    return;
	}
	fmap = (char *)p;
#endif
	fmapsz = len;
    }
    // coverity[string_null : FALSE ]
    reply(fmap, len);
}

void HTTPServerSocket::sendmetrics(bool close) {
    const char *val = arg("timing");
    string q(argdata);
    size_t top = 50;
    PrometheusWriter w(attr("accept"));

    w.labels(dspr.config());
    if (val)
	(void)from_chars(val, val + strlen(val), top);
    // name[] may repeat so scan the raw query
    for (char *p = q.data(), *rest; p && *p; p = rest) {
	char *eq;

	if ((rest = strchr(p, '&')) != nullptr)
	    *rest++ = '\0';
	if ((eq = strchr(p, '=')) == nullptr)
	    continue;
	*eq++ = '\0';
	unescape(p);
	if (!strcmp(p, "name[]")) {
	    unescape(eq);
	    w.filter(eq);
	}
    }
    metrics(w);
    if (top)
	w.timing(dtiming, top);
    status(200, w.contenttype(), 0, nullptr, close);
    *this << w.finish();
    reply();
}

void HTTPServerSocket::status(uint sts, const char *mime, time_t mtime, const
    char *str, bool close) {
    char dt[30];

    if (!str)
	str = statusmsg(sts);
    hdrs.reset();
    ss.reset();
    hdrs.writev(prot, ' ', sts, ' ', str, CRLF);
    if (date)
	header("Date", httpdate(time(nullptr), dt));
    if (mime)
	header("Content-Type", mime);
    if (mtime)
	header("Last-Modified", httpdate(mtime, dt));
    _status = sts;
    // an unread body would be parsed as the next request
    if (close || postin < postsz) {
	hdrs.write("Connection: close\r\n");
	ka = false;
    } else {
	keepalive();
    }
}

void HTTPServerSocket::header(const char *attr, const char *val) {
    hdrs.writev(attr, ": ", val, CRLF);
}

void HTTPServerSocket::error(uint sts, bool close) {
    error(sts, statusmsg(sts), close);
}

void HTTPServerSocket::error(uint sts, const char *errstr, bool close) {
    status(sts, "text/plain", 0, errstr, close);
    ss.writev(sts, ' ', errstr, CRLF);
    reply();
}

void HTTPServerSocket::done() {
    erase();
}

void HTTPServerSocket::metrics(PrometheusWriter &w) const {
    static constexpr PrometheusLabel codes[] = {
	{"code", "1xx"}, {"code", "2xx"}, {"code", "3xx"}, {"code", "4xx"},
	{"code", "5xx"}
    };
    array<ulong, std::size(stats.durations)> durations;

    for (size_t i = 0; i < std::size(durations); ++i)
	durations[i] = stats.durations[i].load(memory_order_relaxed);
    w.counter({"http_accepted_connections", "Accepted HTTP connections"},
	stats.accepted.load(memory_order_relaxed));
    w.gauge({"http_connections", "Open HTTP connections"},
	(double)stats.conns.load(memory_order_relaxed));
    for (size_t i = 0; i < std::size(codes); ++i)
	w.counter({"http_requests", "HTTP requests by status class"},
	    stats.codes[i].load(memory_order_relaxed), {codes[i]});
    w.histogram({"http_request_duration", "HTTP request duration",
	"seconds"}, DurationBounds, durations, (double)stats.duration.load(
	memory_order_relaxed) / 1e6);
    w.counter({"http_request_body", "HTTP request body size", "bytes"},
	stats.rxbytes.load(memory_order_relaxed));
    w.counter({"http_response", "HTTP response size", "bytes"},
	stats.txbytes.load(memory_order_relaxed));
    cntrstats.report(w);
    gaugestats.report(w);
    gdstats.report(w);
    sumstats.report(w);
    tdstats.report(w);
}

void HTTPServerSocket::get(bool head) {
    const char *ext, *val;
    int fd;
    string s(docroot);
    time_t since;
    struct stat statbuf;
    uint sts = 200;

    if (!strcmp(path, "/metrics")) {
	sendmetrics();
	return;
    }
    staticfile = true;
#ifdef _WIN32
    if (string_view(path).contains('\\')) {
	error(403);
	return;
    }
#endif
    if (*path != '/')
	s += '/';
    if (path[0] == '/' && !path[1])
	s += "/default.html";		    // deal w/ language later
    else
	s += path;
    for (const char *pp = s.c_str(); (pp = strstr(pp, "/..")) != nullptr;
	pp += 3) {
	if (pp[3] == '/' || pp[3] == '\0') {
	    error(403);
	    return;
	}
    }
    // s always contains a '/' so only dots in the file name are extensions
    size_t dot = s.rfind('.');

    ext = dot != s.npos && dot > s.rfind('/') ? s.c_str() + dot + 1 : nullptr;
    if ((fd = ::open(s.c_str(), O_RDONLY | O_CLOEXEC | O_SEQUENTIAL)) == -1) {
	error(404);
	return;
    }
    if (fstat(fd, &statbuf)) {
	::close(fd);
	error(404);
	return;
    }
    if ((statbuf.st_mode & S_IFMT) != S_IFREG) {
	::close(fd);
	error(403);
	return;
    }
    if ((val = attr("if-modified-since")) != nullptr &&
	parse_date(achartotchar(val)) >= statbuf.st_mtime)
	sts = 304;
    else if ((val = attr("if-unmodified-since")) != nullptr &&
	(since = parse_date(achartotchar(val))) != 0 &&
	since < statbuf.st_mtime)
	sts = 412;
    status(sts, mimetype(ext), statbuf.st_mtime);
    if (sts == 200 && !head)
	reply(fd, (ulong)statbuf.st_size);
    else
	reply(nullptr, sts == 200 ? (ulong)statbuf.st_size : 0);
    ::close(fd);
}

const char *HTTPServerSocket::mimetype(const char *ext) const {
    struct mimeent {
	attrkey ext;
	const char *type;
    };
    // literal keys hash at compile time; sorted by hash for lookup
    static constexpr auto mime = [] {
	auto a = to_array<mimeent>({
	    { "7z", "application/x-7z-compressed" },
	    { "aac", "audio/aac" },
	    { "avi", "video/x-msvideo" },
	    { "avif", "image/avif" },
	    { "bmp", "image/bmp" },
	    { "bz2", "application/x-bzip2" },
	    { "css", "text/css" },
	    { "csv", "text/csv" },
	    { "deb", "application/vnd.debian.binary-package" },
	    { "doc", "application/msword" },
	    { "docx", "application/vnd.openxmlformats-officedocument."
		"wordprocessingml.document" },
	    { "eot", "application/vnd.ms-fontobject" },
	    { "epub", "application/epub+zip" },
	    { "flac", "audio/flac" },
	    { "gif", "image/gif" },
	    { "gz", "application/gzip" },
	    { "heic", "image/heic" },
	    { "htm", "text/html" },
	    { "html", "text/html" },
	    { "ico", "image/vnd.microsoft.icon" },
	    { "ics", "text/calendar" },
	    { "jar", "application/java-archive" },
	    { "jpeg", "image/jpeg" },
	    { "jpg", "image/jpeg" },
	    { "js", "text/javascript" },
	    { "json", "application/json" },
	    { "m4a", "audio/mp4" },
	    { "md", "text/markdown" },
	    { "mjs", "text/javascript" },
	    { "mkv", "video/x-matroska" },
	    { "mov", "video/quicktime" },
	    { "mp3", "audio/mpeg" },
	    { "mp4", "video/mp4" },
	    { "mpeg", "video/mpeg" },
	    { "mpg", "video/mpeg" },
	    { "odp", "application/vnd.oasis.opendocument.presentation" },
	    { "ods", "application/vnd.oasis.opendocument.spreadsheet" },
	    { "odt", "application/vnd.oasis.opendocument.text" },
	    { "oga", "audio/ogg" },
	    { "ogg", "audio/ogg" },
	    { "ogv", "video/ogg" },
	    { "otf", "font/otf" },
	    { "pdf", "application/pdf" },
	    { "png", "image/png" },
	    { "ppt", "application/vnd.ms-powerpoint" },
	    { "pptx", "application/vnd.openxmlformats-officedocument."
		"presentationml.presentation" },
	    { "rar", "application/vnd.rar" },
	    { "rpm", "application/x-rpm" },
	    { "rtf", "application/rtf" },
	    { "sh", "application/x-sh" },
	    { "svg", "image/svg+xml" },
	    { "tar", "application/x-tar" },
	    { "tgz", "application/gzip" },
	    { "text", "text/plain" },
	    { "tif", "image/tiff" },
	    { "tiff", "image/tiff" },
	    { "ttf", "font/ttf" },
	    { "txt", "text/plain" },
	    { "vcf", "text/x-vcard" },
	    { "vsd", "application/vnd.visio" },
	    { "wasm", "application/wasm" },
	    { "wav", "audio/x-wav" },
	    { "weba", "audio/webm" },
	    { "webm", "video/webm" },
	    { "webp", "image/webp" },
	    { "woff", "font/woff" },
	    { "woff2", "font/woff2" },
	    { "xbm", "image/x-bitmap" },
	    { "xhtml", "application/xhtml+xml" },
	    { "xls", "application/vnd.ms-excel" },
	    { "xlsx", "application/vnd.openxmlformats-officedocument."
		"spreadsheetml.sheet" },
	    { "xml", "application/xml" },
	    { "xz", "application/x-xz" },
	    { "yaml", "application/yaml" },
	    { "yml", "application/yaml" },
	    { "zip", "application/x-zip-compressed" },
	    { "zst", "application/zstd" }
	});

	ranges::sort(a, {}, [](const mimeent &e) { return e.ext.hash; });
	return a;
    }();
    static constexpr auto hash = [](const mimeent &e) { return e.ext.hash; };

    static_assert(ranges::adjacent_find(mime, {}, hash) == mime.end(),
	"duplicate mimetype hash");
    if (ext) {
	const strhash_t h = stringihash(string_view(ext));
	// a class, not a pointer, on MSVC
	// NOLINTNEXTLINE(llvm-qualified-auto,readability-qualified-auto)
	auto it = ranges::lower_bound(mime, h, {}, hash);

	if (it != mime.end() && it->ext.hash == h)
	    return it->type;
    }
    return "application/octet-stream";
}

// UNIX loaders may try to construct static objects > 1 time
template<PrometheusWriter::Type T>
static PrometheusMetrics &registry(void) {
    static constexpr double MsecBounds[] = {
	5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000
    };
    static PrometheusMetrics metrics(T, T == PrometheusWriter::Histogram ||
	T == PrometheusWriter::GaugeHistogram ? span(MsecBounds) :
	span<const double>());

    return metrics;
}

PrometheusMetrics &cntrstats(registry<PrometheusWriter::Counter>());
PrometheusMetrics &gaugestats(registry<PrometheusWriter::Gauge>());
PrometheusMetrics &gdstats(registry<PrometheusWriter::GaugeHistogram>());
PrometheusMetrics &sumstats(registry<PrometheusWriter::Summary>());
PrometheusMetrics &tdstats(registry<PrometheusWriter::Histogram>());
string_view PrometheusWriter::pfx;

// the first OpenMetrics entry wins, else the first text one
PrometheusWriter::PrometheusWriter(const char *accept) {
    string_view a(accept ? accept : ""), pick;

    while (!a.empty()) {
	size_t comma = a.find(',');
	string_view e(a.substr(0, comma)), type(e.substr(0, e.find(';')));

	a = comma == a.npos ? string_view() : a.substr(comma + 1);
	type.remove_prefix(min(type.find_first_not_of(' '), type.size()));
	if (type.starts_with("application/openmetrics-text")) {
	    om = true;
	    pick = e;
	    break;
	} else if (pick.empty() && type.starts_with("text/plain")) {
	    pick = e;
	}
    }
    if (size_t pos = pick.find("escaping="); pos != pick.npos)
	esc = pick.substr(pos + 9).starts_with("allow-utf-8") ? Utf8 :
	    Underscores;
}

const char *PrometheusWriter::contenttype(void) const {
    static constexpr const char *types[2][3] = {
	{
	    "text/plain; version=0.0.4; charset=utf-8",
	    "text/plain; version=0.0.4; charset=utf-8; escaping=underscores",
	    "text/plain; version=0.0.4; charset=utf-8; escaping=allow-utf-8"
	}, {
	    "application/openmetrics-text; version=1.0.0; charset=utf-8",
	    "application/openmetrics-text; version=1.0.0; charset=utf-8; "
		"escaping=underscores",
	    "application/openmetrics-text; version=1.0.0; charset=utf-8; "
		"escaping=allow-utf-8"
	}
    };

    return types[om][esc];
}

void PrometheusWriter::counter(const PrometheusFamily &f, ullong val,
    PrometheusLabels labels) {
    family(f, Counter);
    sample("_total", labels, val);
}

void PrometheusWriter::distribution(Type type, span<const double> bounds,
    span<const ulong> counts, double sum, PrometheusLabels labels) {
    bool gauge = type == GaugeHistogram;
    ulong cnt = 0;
    string le;

    for (size_t i = 0; i < counts.size(); ++i) {
	cnt += counts[i];
	le.clear();
	if (i < bounds.size())
	    number(le, bounds[i]);
	else
	    le = "+Inf";
	sample("_bucket", labels, cnt, {{"le", le}});
    }
    sample(gauge ? "_gcount" : "_count", labels, cnt);
    sample(gauge ? "_gsum" : "_sum", labels, sum);
}

void PrometheusWriter::escape(string &s, string_view val) {
    for (char c : val) {
	if (c == '"' || c == '\\' || c == '\n')
	    s += '\\';
	s += c == '\n' ? 'n' : c;
    }
}

void PrometheusWriter::family(const PrometheusFamily &f, Type type) {
    static constexpr const char *types[] = {
	"counter", "gauge", "gaugehistogram", "histogram", "info", "stateset",
	"summary"
    };
    static constexpr string_view suffixes[] = {
	"_total", "", "", "", "_info", "", ""
    };
    auto out = back_inserter(s);
    string n(pfx);
    string qname;
    string_view sfx(suffixes[type]);
    const char *tname = types[type];

    n += f.name;
    if (esc != Utf8 && !PrometheusStr::legacy(n, true))
	n = underscore(n, true);
    if (n.ends_with(sfx))
	n.resize(n.size() - sfx.size());
    if (!f.unit.empty() && !n.ends_with(format("_{}", f.unit)))
	format_to(back_inserter(n), "_{}", f.unit);
    if (n == name && type == cur)
	return;
    cur = type;
    name = std::move(n);
    quote = esc == Utf8 && !PrometheusStr::legacy(name, true);
    skip = !names.empty() && ranges::none_of(names, [&](const string &m) {
	return m == name || (m.starts_with(name) && m.substr(name.size()) ==
	    sfx);
    });
    if (skip)
	return;
    // text 0.0.4 names families by sample and lacks the OpenMetrics types
    if (om) {
	sfx = {};
    } else if (type == GaugeHistogram) {
	tname = "histogram";
    } else if (type == Info || type == StateSet) {
	tname = "gauge";
    }
    if (quote) {
	qname = '"';
	escape(qname, name);
	qname += sfx;
	qname += '"';
    } else {
	qname = name;
	qname += sfx;
    }
    if (!f.help.empty())
	format_to(out, "# HELP {} {}\n", qname, f.help);
    format_to(out, "# TYPE {} {}\n", qname, tname);
    if (om && !f.unit.empty())
	format_to(out, "# UNIT {} {}\n", qname, f.unit);
}

const string &PrometheusWriter::finish(void) {
    if (om)
	s += "# EOF\n";
    return s;
}

void PrometheusWriter::gauge(const PrometheusFamily &f, double val,
    PrometheusLabels labels) {
    family(f, Gauge);
    sample("", labels, val);
}

void PrometheusWriter::info(const PrometheusFamily &f, PrometheusLabels
    labels) {
    family(f, Info);
    sample("_info", labels, 1);
}

void PrometheusWriter::labelname(string &str, string_view n) const {
    if (PrometheusStr::legacy(n, false)) {
	str += n;
    } else if (esc == Utf8) {
	str += '"';
	escape(str, n);
	str += '"';
    } else {
	str += underscore(n, false);
    }
}

void PrometheusWriter::labels(const Config &cfg) {
    const tstring keys(cfg.get(T("prometheus.labels")));

    for (tstring_view v(keys); !v.empty(); ) {
	size_t comma = v.find(',');
	tstring_view n(v.substr(0, comma));
	tstring val;

	v = comma == v.npos ? tstring_view() : v.substr(comma + 1);
	n.remove_prefix(min(n.find_first_not_of(T(" \t")), n.size()));
	n = n.substr(0, n.find_last_not_of(T(" \t")) + 1);
	if (n.empty() || (val = cfg.get(tstring(T("prometheus.label.")) +=
	    n)).empty())
	    continue;
	if (!tags.empty())
	    tags += ',';
	labelname(tags, tstringtoastring(tstring(n)));
	tags += "=\"";
	escape(tags, tstringtoastring(val));
	tags += '"';
    }
}

void PrometheusWriter::number(string &s, double val) {
    size_t len = s.size();

    format_to(back_inserter(s), "{:.6f}", val);
    while (s.size() > len && s.back() == '0')
	s.pop_back();
    if (s.size() > len && s.back() == '.')
	s.pop_back();
}

void PrometheusWriter::putlabel(const PrometheusLabel &l) {
    if (l.name.flags & PrometheusStr::Name)
	s += l.name;
    else
	labelname(s, l.name);
    s += "=\"";
    if (l.value.flags & PrometheusStr::Clean)
	s += l.value;
    else
	escape(s, l.value);
    s += '"';
}

template<class V>
void PrometheusWriter::sample(string_view suffix, PrometheusLabels labels,
    V val, PrometheusLabels extra) {
    auto out = back_inserter(s);
    bool comma = !tags.empty();
    const bool lbls = comma || !labels.empty() || !extra.empty();

    if (skip)
	return;
    // a quoted name moves inside the braces
    if (quote) {
	s += "{\"";
	escape(s, name);
	s += suffix;
	s += lbls ? "\"," : "\"";
    } else {
	s += name;
	s += suffix;
	if (lbls)
	    s += '{';
    }
    s += tags;
    for (PrometheusLabels ls : {labels, extra}) {
	for (const PrometheusLabel &l : ls) {
	    if (comma)
		s += ',';
	    comma = true;
	    putlabel(l);
	}
    }
    if (quote || lbls)
	s += '}';
    if constexpr (is_floating_point_v<V>) {
	// -ffast-math folds isnan/isinf to false
	auto bits = bit_cast<uint64_t>((double)val);

	if ((bits & 0x7ff0000000000000ULL) == 0x7ff0000000000000ULL) {
	    s += bits << 12 ? " NaN" : (int64_t)bits < 0 ? " -Inf" : " +Inf";
	} else {
	    s += ' ';
	    number(s, val);
	}
	s += '\n';
    } else {
	format_to(out, " {}\n", val);
    }
}

void PrometheusWriter::stateset(const PrometheusFamily &f,
    initializer_list<pair<string_view, bool>> states) {
    family(f, StateSet);
    for (const auto &[state, on] : states)
	sample("", {{name, state}}, on ? 1 : 0);
}

void PrometheusWriter::summary(const PrometheusFamily &f, ullong count,
    double sum, PrometheusLabels labels) {
    family(f, Summary);
    sample("_count", labels, count);
    sample("_sum", labels, sum);
}

void PrometheusWriter::timing(const Timing &t, size_t top) {
    static constexpr auto bounds = [] {
	array<double, std::size(Timing::Limits)> a{};

	for (size_t i = 0; i < a.size(); ++i)
	    a[i] = (double)Timing::Limits[i] / 1e6;
	return a;
    }();
    vector<Timing::Row> rows(t.snapshot());

    if (rows.size() > top)
	rows.resize(top);
    for (bool timed : {true, false}) {
	for (const Timing::Row &row : rows) {
	    ulong cnts[Timing::TIMINGSLOTS];
#ifdef UNICODE
	    const string key(tstringtoastring(tstring(row.key, row.klen)));
#else
	    const string_view key(row.key, row.klen);
#endif
	    const PrometheusLabel lbl{"key", key};

	    if (!row.tot != !timed)
		continue;
	    if (!timed) {
		family({"timing_calls", "Untimed call counts"}, Counter);
		sample("_total", {lbl}, row.cnt);
		continue;
	    }
	    for (uint u = 0; u < Timing::TIMINGSLOTS; ++u)
		cnts[u] = (ulong)row.cnts[u];
	    family({"timing", "Call durations", "seconds"}, Histogram);
	    distribution(Histogram, bounds, cnts, (double)row.tot / 1e6,
		{lbl});
	}
    }
}

// one '_' per invalid UTF-8 character, as Prometheus escapes
string PrometheusWriter::underscore(string_view n, bool metric) {
    string r;

    if (n.empty() || (n[0] >= '0' && n[0] <= '9'))
	r += '_';
    for (char c : n) {
	if (((uchar)c & 0xc0) != 0x80)
	    r += PrometheusStr::legacy(c, metric) ? c : '_';
    }
    return r;
}

void PrometheusMetrics::describe(const PrometheusFamily &f,
    span<const double> b) {
    FastSpinWLocker lkr(lck);
    Family &fam = family(f.name);

    if (!b.empty() && fam.series.empty())
	fam.bounds.assign(b.begin(), b.end());
    fam.help = f.help;
    fam.unit = f.unit;
}

PrometheusMetrics::Family &PrometheusMetrics::family(const PrometheusStr
    &name) {
    auto [it, added] = fams.try_emplace(name.key());
    Family &fam = it->second;

    if (added) {
	fam.bounds.assign(defbounds.begin(), defbounds.end());
	fam.name = name;
    }
    return fam;
}

void PrometheusMetrics::report(PrometheusWriter &w) const {
    FastSpinRLocker lkr(lck);
    vector<const Family *> sorted;

    sorted.reserve(fams.size());
    for (const auto &[hash, fam] : fams) {
	if (!fam.series.empty())
	    sorted.push_back(&fam);
    }
    ranges::sort(sorted, {}, [](const Family *f) -> const string & {
	return f->name;
    });
    for (const Family *fam : sorted) {
	w.family({fam->name, fam->help, fam->unit}, type);
	for (const Series *ser : fam->series) {
	    const PrometheusLabels lbls(ser->labels.data(), ser->labels.size());
	    llong sum = (llong)ser->sum.load(memory_order_relaxed);

	    if (type == PrometheusWriter::Counter) {
		w.sample("_total", lbls, sum);
	    } else if (type == PrometheusWriter::Gauge) {
		w.sample("", lbls, sum);
	    } else if (type == PrometheusWriter::Summary) {
		w.sample("_count", lbls, ser->cnts[0].load(
		    memory_order_relaxed));
		w.sample("_sum", lbls, sum);
	    } else {
		vector<ulong> cnts(fam->bounds.size() + 1);

		for (size_t i = 0; i < cnts.size(); ++i)
		    cnts[i] = ser->cnts[i].load(memory_order_relaxed);
		w.distribution(type, fam->bounds, cnts, (double)sum, lbls);
	    }
	}
    }
}

PrometheusMetrics::Series *PrometheusMetrics::series(const PrometheusStr
    &name, PrometheusLabels labels, strhash_t hash) {
    {
	FastSpinRLocker lkr(lck);

	if (auto it = smap.find(hash); it != smap.end())
	    return &it->second;
    }

    FastSpinWLocker lkr(lck);
    auto [it, added] = smap.try_emplace(hash);
    Series &ser = it->second;
    Family &fam = family(name);
    size_t len = 0;

    if (!added)
	return &ser;
    for (const PrometheusLabel &l : labels)
	len += l.name.size() + l.value.size();
    // reserved so the label views stay valid
    ser.text.reserve(len);
    for (const PrometheusLabel &l : labels) {
	size_t pos = ser.text.size();
	auto own = [&](size_t off, size_t n) {
	    PrometheusStr str(string_view(ser.text).substr(off, n));

	    str.hash = charhash(str.data(), str.size());
	    str.flags = PrometheusStr::classify(str);
	    return str;
	};

	ser.text += l.name;
	ser.text += l.value;
	ser.labels.push_back({own(pos, l.name.size()), own(pos +
	    l.name.size(), l.value.size())});
    }
    ser.cnts = make_unique<atomic<ulong>[]>(fam.bounds.size() + 1);
    ser.fam = &fam;
    ser.hash = hash;
    fam.series.push_back(&ser);
    return &ser;
}

const PrometheusLabel &PrometheusMetrics::sizelabel(ullong size) {
    static constexpr ullong limits[] = {
	0, 32ULL << 10, 128ULL << 10, 512ULL << 10, 2ULL << 20, 8ULL << 20,
	32ULL << 20, 128ULL << 20, 1ULL << 40
    };
    static constexpr PrometheusLabel labels[] = {
	{"size", "0"}, {"size", "0-32Kb"}, {"size", "32Kb-128Kb"},
	{"size", "128Kb-512Kb"}, {"size", "512Kb-2Mb"}, {"size", "2Mb-8Mb"},
	{"size", "8Mb-32Mb"}, {"size", "32Mb-128Mb"}, {"size", "128Mb-1Tb"},
	{"size", "infinite"}
    };

    return labels[ranges::lower_bound(limits, size) - limits];
}

void PrometheusMetrics::update(const PrometheusStr &name, llong val,
    PrometheusLabels labels, Op op) {
    strhash_t hash = name.key();
    Series *ser;

    for (const PrometheusLabel &l : labels)
	hash = rapidmix(hash ^ l.name.key(), l.value.key() ^ RAPID_SECRET0);
    ser = cache[hash & (CACHESIZE - 1)].load(memory_order_acquire);
    if (UNLIKELY(!ser || ser->hash != hash)) {
	ser = series(name, labels, hash);
	cache[hash & (CACHESIZE - 1)].store(ser, memory_order_release);
    }
    if (op == Set) {
	ser->sum.store((ullong)val, memory_order_relaxed);
    } else {
	ser->sum.fetch_add((ullong)(op == Add ? val : -val),
	    memory_order_relaxed);
	if (type == PrometheusWriter::Summary)
	    ser->cnts[0].fetch_add(1, memory_order_relaxed);
	else if (type == PrometheusWriter::Histogram ||
	    type == PrometheusWriter::GaugeHistogram)
	    ser->cnts[(size_t)(ranges::lower_bound(ser->fam->bounds,
		(double)val) - ser->fam->bounds.begin())].fetch_add(op == Add ?
		1 : (ulong)-1, memory_order_relaxed);
    }
}
