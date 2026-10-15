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
#include <ctime>
#include <time.h>
#include <fcntl.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/mman.h>
#endif
#include "HTTPClient.h"
#include "HTTPServer.h"
#include "Log.h"

static constexpr ulong MaxHdrs = 64UL * 1024;	// request + header bytes
static constexpr size_t MaxHdrCount = 100;
static constexpr ulong MaxBody = 256UL * 1024 * 1024;
static constexpr char CRLF[] = "\r\n";

bool HTTPServerSocket::date;
atomic_bool HTTPServerSocket::paused;

static const char *statusmsg(uint sts) {
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

// read exactly len bytes: a single read() is short for large or slow files
static bool readfull(int fd, char *buf, size_t len) {
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

HTTPServerSocket::~HTTPServerSocket(void) {
    delete [] data;
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
	if (sz > MaxHdrs) {
	    cmd = "BADCMD";
	    path = "/";
	    prot = "HTTP/1.0";
	    error(431, true);
	    return;
	}

	char *old = data;

	sz = min(sz < 1000 ? 1000UL : sz * 2, MaxHdrs + 1);
	room = (uint)(sz - datasz);
	data = new char[sz];
	memcpy(data, old, datasz);
	delete [] old;
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
    // chunked or read until close: size unknown so always use own buffer
    bool chunky = postsz == (ulong)-1;
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
	if (chunky && !postchunking) {
	    left = in = 0;
	    postsz = postin;
	} else {
	    disconnect();
	    return;
	}
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
	    if (ec != errc() || (e < lf && !strchr("\r; \t", *e))) {
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
	readable(readpost, rto);
    } else {
	savechar = postdata[postsz];
	postdata[postsz] = '\0';
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

    path = "/";
    prot = "HTTP/1.0";
    postsz = 0;
    while (*buf == ' ' || *buf == '\t')
	buf++;
    for (cmd = p = buf; *p != ' ' && *p != '\t' && *p != '\r'; p++)
	continue;
    if (*p == '\r') {
	cmd = "BADCMD";
	error(400, true);
	return;
    }
    *p++ = '\0';
    while (*p == ' ' || *p == '\t')
	p++;
    for (path = pp = p; *p != ' ' && *p != '\t' && *p != '\r'; p++)
	continue;
    noprot = (*p == '\r');
    *p++ = '\0';
    if ((pp = strchr(pp, '?')) == nullptr) {
	argdata.clear();
	args.clear();
    } else {
	*pp++ = '\0';
	argdata = pp;
	urldecode(pp, args);
    }
    if (!noprot) {
	while (*p == ' ' || *p == '\t')
	    p++;
	for (prot = p; *p != ' ' && *p != '\t' && *p != '\r'; p++)
	    continue;
	*p++ = '\0';
    }
    if (strnicmp(prot, "HTTP/1.", 7) != 0 || prot[7] < '0' || prot[7] > '9' ||
	prot[8]) {
	prot = "HTTP/1.0";
	error(400, true);
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
	    crlf = false;
	}
	// obsolete line folding is a request smuggling vector
	if (crlf && (end[2] == ' ' || end[2] == '\t')) {
	    error(400, true);
	    return;
	}
	while (*buf == ' ' || *buf == '\t')
	    buf++;
	p = end;
	while (p > buf && (p[-1] == ' ' || p[-1] == '\t'))
	    p--;
	*p = '\0';
	if (p == buf)
	    break;
	if ((p = strchr(buf, ':')) != nullptr) {
	    pp = p + 1;
	    while (p > buf && (p[-1] == ' ' || p[-1] == '\t'))
		p--;
	    *p = '\0';
	    p = pp;
	    while (*p == ' ' || *p == '\t')
		p++;

	    if (attrs.size() >= MaxHdrCount) {
		error(431, true);
		return;
	    }

	    auto [it, added] = attrs.try_emplace(buf, p);

	    if (!added) {
		if (stringieq(buf, "content-length") ||
		    stringieq(buf, "transfer-encoding")) {
		    error(400, true);
		    return;
		}
		it->second = p;
	    }
	}
	if (!crlf || !end[1])
	    break;
	buf = end + 2;
    }
    val = attr("transfer-encoding");
    postchunking = false;
    if (val) {
	string_view tv(val);
	size_t comma = tv.rfind(',');

	// only the final coding matters: earlier ones are passed through
	if (comma != tv.npos)
	    tv.remove_prefix(comma + 1);
	while (!tv.empty() && (tv.front() == ' ' || tv.front() == '\t'))
	    tv.remove_prefix(1);
	if (attr("content-length")) {
	    error(400, true);
	    return;
	} else if (!stringieq(tv, "chunked")) {
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
    } else if (stringieq(cmd, "POST") || stringieq(cmd, "PUT")) {
	postsz = (ulong)-1;
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
	else
	    postargs.clear();
	post();
    } else if (stringieq(cmd, "PUT")) {
	put();
    } else if (stringieq(cmd, "DELETE")) {
	del();
    } else {
	error(405);
    }
}

void HTTPServerSocket::urldecode(char *buf, attrmap &amap) const {
    auto unescape = [](char *s) {
#ifdef UNICODE
	tstring t(achartotchar(s));

	URL::unescape(t);
	strcpy(s, tstringtoachar(t));
#else
	URL::unescape(s);
#endif
    };

    amap.clear();
    while (buf) {
	char *rest = strchr(buf, '&');
	char *eq;

	if (rest)
	    *rest++ = '\0';
	while (*buf == ' ' || *buf == '\t')
	    buf++;
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
	hdrs.write("Connection: keep-alive\r\n", 24);
    else if (prot[7] == '1')
	hdrs.write("Connection: close\r\n", 19);
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
	ulong total = 0;

	for (const auto &v : iov)
	    total += (ulong)v.iov_len;
	if (out != total) {
	    for (auto &v : iov) {
		ulong n = min(out, (ulong)v.iov_len);

		v.iov_len -= (iovlen_t)n;
		v.iov_base = (char *)v.iov_base + n;
		out -= n;
	    }
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
	    delete [] data;
	    sz = datasz + 1000;
	    data = new char[sz];
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

void HTTPServerSocket::reply(const char *p, ulong len) {
    if (len == (ulong)-1)
	len = p ? (ulong)strlen(p) : 0;
    hdrs.write("Content-Length: ", 16);
    hdrs.write((ulong)ss.size() + len);
    hdrs.write("\r\n\r\n", 4);
    iov[0].iov_base = (char *)hdrs.str();	// NOSONAR
    iov[0].iov_len = (iovlen_t)hdrs.size();
    iov[1].iov_base = (char *)ss.str();		// NOSONAR
    iov[1].iov_len = (iovlen_t)ss.size();
    iov[2].iov_base = (char *)p;		// NOSONAR
    iov[2].iov_len = (iovlen_t)len;
    dlogl(_status < 400 ? Log::Info : Log::Note, Log::cmd(cmd),
	Log::kv(T("path"), path), Log::kv(T("sts"), _status));
    send();
}

void HTTPServerSocket::reply(int fd, ulong len) {
    char buf[2048];

    if (len <= sizeof (buf)) {
	if (!readfull(fd, buf, len)) {
	    error(500);
	    return;
	}
	ss.write(buf, (streamsize)len);
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

void HTTPServerSocket::status(uint sts, const char *mime, time_t mtime, const
    char *str, bool close) {
    if (!str)
	str = statusmsg(sts);
    hdrs.reset();
    ss.reset();
    hdrs.write(prot, (streamsize)strlen(prot));
    hdrs.write(' ');
    hdrs.write(sts);
    hdrs.write(' ');
    hdrs.write(str, (streamsize)strlen(str));
    hdrs.write(CRLF, 2);
    if (date) {
	auto hdr = format("Date: {:%a, %d %b %Y %H:%M:%S} GMT\r\n",
	    chrono::floor<chrono::seconds>(chrono::system_clock::now()));

	hdrs.write(hdr.c_str(), (streamsize)hdr.size());
    }
    if (mime) {
	hdrs.write("Content-Type: ", 14);
	hdrs.write(mime, (streamsize)strlen(mime));
	hdrs.write(CRLF, 2);
    }
    if (mtime) {
	auto hdr = format("Last-Modified: {:%a, %d %b %Y %H:%M:%S} GMT\r\n",
	    chrono::sys_seconds(chrono::seconds(mtime)));

	hdrs.write(hdr.c_str(), (streamsize)hdr.size());
    }
    _status = sts;
    if (close) {
	hdrs.write("Connection: close\r\n", 19);
	ka = false;
    } else {
	keepalive();
    }
}

void HTTPServerSocket::header(const char *attr, const char *val) {
    hdrs.write(attr, (streamsize)strlen(attr));
    hdrs.write(": ", 2);
    hdrs.write(val, (streamsize)strlen(val));
    hdrs.write(CRLF, 2);
}

void HTTPServerSocket::error(uint sts, bool close) {
    error(sts, statusmsg(sts), close);
}

void HTTPServerSocket::error(uint sts, const char *errstr, bool close) {
    status(sts, "text/plain", 0, errstr, close);
    ss.write(sts);
    ss.write(' ');
    ss.write(errstr, (streamsize)strlen(errstr));
    ss.write(CRLF, 2);
    reply();
}

void HTTPServerSocket::done() {
    erase();
}

void HTTPServerSocket::get(bool head) {
    const char *ext, *val;
    int fd;
    string s(1, '.');
    time_t since;
    struct stat statbuf;
    uint sts = 200;

#ifdef _WIN32
    if (strchr(path, '\\')) {
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
    if ((ext = strrchr(strrchr(s.c_str(), '/'), '.')) != nullptr)
	ext++;
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
	reply(nullptr);
    ::close(fd);
}

const char *HTTPServerSocket::mimetype(const char *ext) const {
    static const unordered_map<string_view, const char *, strihash, strieq>
	mime = {
	{ "avi", "video/x-msvideo" },
	{ "bmp", "image/bmp" },
	{ "css", "text/css" },
	{ "gif", "image/gif" },
	{ "htm", "text/html" },
	{ "html", "text/html" },
	{ "ico", "image/vnd.microsoft.icon" },
	{ "jpeg", "image/jpeg" },
	{ "jpg", "image/jpeg" },
	{ "js", "text/javascript" },
	{ "json", "application/json" },
	{ "mov", "video/quicktime" },
	{ "mp4", "video/mp4" },
	{ "mpeg", "video/mpeg" },
	{ "mpg", "video/mpeg" },
	{ "pdf", "application/pdf" },
	{ "png", "image/png" },
	{ "rtf", "application/rtf" },
	{ "svg", "image/svg+xml" },
	{ "text", "text/plain" },
	{ "tiff", "image/tiff" },
	{ "tif", "image/tiff" },
	{ "txt", "text/plain" },
	{ "vcf", "text/x-vcard" },
	{ "wasm", "application/wasm" },
	{ "wav", "audio/x-wav" },
	{ "webp", "image/webp" },
	{ "woff", "font/woff" },
	{ "woff2", "font/woff2" },
	{ "xbm", "image/x-bitmap" },
	{ "xml", "application/xml" },
	{ "zip", "application/x-zip-compressed" }
    };

    if (ext) {
	auto it = mime.find(string_view(ext));

	if (it != mime.end())
	    return it->second;
    }
    return "application/octet-stream";
}
