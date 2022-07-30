/*
 * Copyright 2001-2022 Todd Richmond
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
#include <fcntl.h>
#include <sys/stat.h>
#include "HTTPClient.h"
#include "HTTPServer.h"
#include "Log.h"
#include "SMTPClient.h"

const char HTTPServerSocket::CRLF[] = "\r\n";
bool HTTPServerSocket::date;

HTTPServerSocket::HTTPServerSocket(Dispatcher &d, Socket &sock):
    DispatchServerSocket(d, sock), path(NULL), prot(NULL), postdata(NULL),
    postsz(0), chunkin(0), chunktrailer(false), postchunking(false), cmd(NULL),
    data(NULL), datasz(0), sz(0), fmap(NULL), ka(false), nagleon(true),
    postdatasz(0), postin(0), rto(RTimeout), wto(WTimeout), savechar(0),
    _status(0) {
    ZERO(iov);
}

HTTPServerSocket::~HTTPServerSocket(void) {
    delete [] data;
#ifdef _WIN32
    if (fmap)
	UnmapViewOfFile(fmap);
#else
    delete [] fmap;
#endif
    if (postdatasz)
	delete [] postdata;
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

    if (msg == DispatchTimeout || msg == DispatchClose) {
	disconnect();
	return;
    }
    if (room <= 1) {
	char *old = data;

	sz += 1000;
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
    ulong room = postdatasz ? postdatasz - postin : sz - datasz;
    ulong left = room > 100 && postsz == (ulong)-1 ? room : postsz - postin;
    static const char chunkmap[256] = {
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -2, -1, -1, -2, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	 0,  1,  2,  3,  4,  5,  6,  7,  8,  9, -1, -2, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
	-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    };

    if (msg == DispatchTimeout) {
	disconnect();
	return;
    }
    if (msg != DispatchClose && room < left + 1 && (!postdatasz || postsz ==
	(ulong)-1)) {
	if (postsz == (ulong)-1)
	    in = postin < 8UL * 1024 ? 16UL * 1024 : postin * 2;
	else
	    in = postsz;
	postdata_grow(readpost, postin, in + 1);
	postdatasz = in;
	return;
    }
    if (msg == DispatchClose || (in = (ulong)read(postdata + postin,
	(uint)left)) == (ulong)-1) {
	if (postsz == (ulong)-1 && !postchunking) {
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
    if (postchunking) {
	while (chunkin < postin) {
	    // skip over terminating CRLF of previous chunk
	    ulong pos = chunkin + (chunkin && !chunktrailer ? 2 : 0);

	    if (postin <= pos)
		break;

	    char c;
	    ulong chunksize = 0;
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
		while ((c = chunkmap[(uchar)postdata[pos]]) >= 0) {
		    chunksize = chunksize * 16 + (ulong)c;
		    if (++pos == postin)
			break;
		}
		if (c != -2 || pos == chunkin) {
		    error(400);
		    return;
		}
	    }
	    ++lf;
	    memmove(postdata + chunkin, lf, (size_t)(postdata + postin - lf));
	    postin -= (ulong)(lf - (postdata + chunkin));
	    if (!postdatasz)
		datasz -= (ulong)(lf - (postdata + chunkin));
	    if (postsz != (ulong)-1)
		break;
	    else if (chunksize == 0)
		chunktrailer = true;
	    else
		chunkin += chunksize;
	}
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
    while (len-- > 0) {
	if (buf[0] == '\r') {
	    if (len < 3) {
		readable(readhdrs, rto);
		return;
	    } else if (!memcmp(buf, "\r\n\r\n", 4)) {
		postdata = buf + 4;
		buf[1] = '\0';
		if (append)
		    ready(parse);
		else
		    parse();
		return;
	    } else {
		buf += 2;
		len--;
	    }
	} else if (buf[0] == '\n') {
	    if (len < 2) {
		readable(readhdrs, rto);
		return;
	    } else if (buf[1] == '\n') {
		postdata = buf + 2;
		buf[0] = '\r';
		buf[1] = '\0';
		parse();
		return;
	    } else if (buf[1] == '\r' && buf[2] == '\n') {
		postdata = buf + 3;
		buf[0] = '\r';
		buf[1] = '\0';
		parse();
		return;
	    }
	} else {
	    buf++;
	}
    }
    readable(readhdrs, rto);
}

#pragma warning(disable: 26430)
void HTTPServerSocket::parse(void) {
    char *p, *pp, *start, *end;
    char *buf = data;
    const char *val;
    bool noprot;

    path = "/";
    prot = "HTTP/1.0";
    while (*buf == ' ' || *buf == '\t')
	buf++;
    for (cmd = p = buf; *p != ' ' && *p != '\t' && *p != '\r'; p++)
	continue;
    if (*p == '\r') {
	cmd = "BADCMD";
	error(400);
	return;
    }
    *p++ = '\0';
    while (*p == ' ' || *p == '\t')
	p++;
    for (path = pp = p; *p != ' ' && *p != '\t' && *p != '\r'; p++)
	continue;
    noprot = (*p == '\r');
    *p++ = '\0';
    if ((pp = strchr(pp, '?')) == NULL) {
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
    if (strnicmp(prot, "HTTP/1.", 7) != 0 || !prot[7] || prot[8] ||
	!isdigit((int)prot[7])) {
	prot = "HTTP/1.0";
	error(400);
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

	if ((end = strchr(buf, '\r')) == NULL) {
	    end = buf + strlen(buf);
	    crlf = false;
	} else if (end[1] != '\n') {
	    crlf = false;
	}
	while (end[0] && end[1] && (end[2] == ' ' || end[2] == '\t')) {
	    for (start = end + 2; *start == ' ' || *start == '\t'; start++)
		continue;
	    if ((p = strchr(start, '\r')) == NULL)
		p = start + strlen(start);
	    memmove(end, start, (size_t)(p - start));
	    end = p;
	}
	while (*buf == ' ' || *buf == '\t')
	    buf++;
	p = end;
	while (p > buf && (p[-1] == ' ' || p[-1] == '\t'))
	    p--;
	*p = '\0';
	if (p == buf)
	    break;
	if ((p = strchr(buf, ':')) != NULL) {
	    pp = p + 1;
	    while (p > buf && (p[-1] == ' ' || p[-1] == '\t'))
		p--;
	    *p = '\0';
	    p = pp;
	    while (*p == ' ' || *p == '\t')
		p++;
	    attrs[buf] = p;
	}
	if (!crlf || !end[1])
	    break;
	buf = end + 2;
    }
    val = attr("transfer-encoding");
    if (val && !strncasecmp(val, "chunked", 7)) {
	postchunking = true;
	chunktrailer = false;
	chunkin = 0;
	postsz = (uint)-1;
    } else {
	postchunking = false;
	val = attr("content-length");
	if (val)
	    postsz = (uint)atol(val);
	else if (!stricmp(cmd, "POST") || !stricmp(cmd, "PUT"))
	    postsz = (uint)-1;
	else
	    postsz = 0;
    }
    if (postsz) {
	postin = datasz - (ulong)(postdata - data);
	if (postin > postsz)
	    postin = postsz;
	if (postin == postsz) {
	    savechar = postdata[postsz];
	    postdata[postsz] = '\0';
	    exec();
	} else {
	    postpre(readpost);
	}
    } else {
	exec();
    }
}

void HTTPServerSocket::exec(void) {
    if (!stricmp(cmd, "GET")) {
	get(false);
    } else if (!stricmp(cmd, "HEAD")) {
	get(true);
    } else if (!stricmp(cmd, "POST")) {
	const char *val = attr("content-type");

	if (val != NULL && !stricmp(val, "application/x-www-form-urlencoded"))
	    urldecode(postdata, postargs);
	else
	    postargs.clear();
	post();
    } else if (!stricmp(cmd, "PUT")) {
	put();
    } else if (!stricmp(cmd, "DELETE")) {
	del();
    } else {
	error(405);
    }
}

void HTTPServerSocket::urldecode(char *buf, attrmap &amap) const {
    char *p = buf, *pp;

    amap.clear();
    while (p) {
	while (*p == ' ' || *p == '\t')
	    p++;
	buf = p;
	if ((p = strchr(p, '&')) != NULL)
	    *p++ = '\0';
#ifdef UNICODE
	tstring s(achartotchar(buf));

	URL::unescape(s);
	strcpy(buf, tstringtoachar(s));
#else
	URL::unescape(buf);
#endif
	if ((pp = strchr(buf, '=')) == NULL) {
	    amap[buf] = "";
	} else {
	    *pp++ = '\0';
	    amap[buf] = pp;
	}
    }
}

void HTTPServerSocket::keepalive(void) {
    const char *p = "Pragma";
    const char *val = attr(p);
    static const char keep[] = "keep-alive";

    ka = prot[7] == '1';		// HTTP 1.1
    if (val != NULL && !stricmp(val, keep)) {
	ka = true;
    } else {
	p = "Connection";
	if ((val = attr(p)) != NULL) {
	    if (!strnicmp(val, keep, 10))
		ka = true;
	    else if (!stricmp(val, "close"))
		ka = false;
	}
    }
    if (ka)
	hdrs << p << ": keep-alive\r\n";
}

void HTTPServerSocket::send(void) {
    ulong out;

    if (msg == DispatchTimeout || msg == DispatchClose) {
	disconnect();
	return;
    }
    if (ka && nagleon) {
	nodelay(true);
	nagleon = false;
    }
    out = (ulong)writev(iov, 3);
    if (out != (ulong)-1 &&
	out != (ulong)(iov[0].iov_len + iov[1].iov_len + iov[2].iov_len)) {
	ulong ul = out < (ulong)iov[0].iov_len ? out : (ulong)iov[0].iov_len;

	iov[0].iov_len -= ul;
	iov[0].iov_base = (char *)iov[0].iov_base + ul;
	out -= ul;
	ul = out < (ulong)iov[1].iov_len ? out : (ulong)iov[1].iov_len;
	iov[1].iov_len -= ul;
	iov[1].iov_base = (char *)iov[1].iov_base + ul;
	out -= ul;
	iov[2].iov_len -= out;
	iov[2].iov_base = (char *)iov[2].iov_base + out;
	writeable(send, wto);
	return;
    }
    if (fmap) {
#ifdef _WIN32
	UnmapViewOfFile(fmap);
#else
	delete [] fmap;
#endif
	fmap = NULL;
    }
    if (ka && out != (ulong)-1) {
	datasz -= postdatasz ? datasz : postsz + (ulong)(postdata - data);
	replydone(senddone);
    } else {
	disconnect();
    }
}

void HTTPServerSocket::senddone() {
    if (datasz) {
	postdata[postsz] = savechar;
	memmove(data, postdata + postsz, datasz);
	scan(data, datasz, true);
    } else {
	if (postdatasz) {
	    postdata_free();
	    postdatasz = 0;
	}
	readable(readhdrs, rto);
    }
}

void HTTPServerSocket::reply(const char *p, ulong len) {
    char buf[64];
    int i;

    if (len == (ulong)-1)
	len = p ? (ulong)strlen(p) : 0;
    i = sprintf(buf, "Content-Length: %lu\r\n\r\n", (ulong)ss.size() + len);
    hdrs.write(buf, i);
    iov[0].iov_base = (char *)hdrs.str();
    iov[0].iov_len = (iovlen_t)hdrs.size();
    iov[1].iov_base = (char *)ss.str();
    iov[1].iov_len = (iovlen_t)ss.size();
    iov[2].iov_base = (char *)p;
    iov[2].iov_len = (iovlen_t)len;
    dlog << (_status < 400 ? Log::Info : Log::Note) << Log::cmd(cmd) <<
	Log::kv(T("path"), path) << Log::kv(T("sts"), _status) << endlog;
    send();
}

void HTTPServerSocket::reply(int fd, ulong len) {
    char buf[2048];

    if (len <= sizeof (buf)) {
#ifdef _FORTIFY_SOURCE
	if ((long)::read(fd, buf, sizeof (buf)) < (long)len) {
#else
	if ((ulong)::read(fd, buf, (uint)len) != len) {
#endif
	    error(404);
	    return;
	}
	ss.write(buf, (streamsize)len);
	len = 0;
    } else {
#ifdef _WIN32
	HANDLE hdl;

	if ((hdl = CreateFileMapping((HANDLE)(ullong)fd, NULL, PAGE_READONLY,
	    0, (DWORD)len, NULL)) == NULL) {
	    error(404);
	    return;
	}
	if ((fmap = (char *)MapViewOfFile(hdl, FILE_MAP_READ,
	    0, 0, len)) == NULL) {
	    CloseHandle(hdl);
	    error(404);
	    return;
	}
	CloseHandle(hdl);
#else
	if ((fmap = new char[len]) == NULL || (ulong)::read(fd, fmap, len) !=
	    len) {
	    error(404);
	    return;
	}
#endif
    }
    // coverity[string_null : FALSE ]
    reply(fmap, len);
}

void HTTPServerSocket::status(uint sts, const char *mime, time_t mtime, const
    char *str, bool close) {
    char buf[128];
    int i;
    struct tm tmbuf, *tmptr;

    hdrs.reset();
    ss.reset();
    i = snprintf(buf, sizeof (buf), "%s %u %s\r\n", prot, sts, str ? str :
	sts < 300 ? "OK" : "ERR");
    i = min(i, (int)sizeof (buf) - 1);
    hdrs.write(buf, i);
    if (date) {
	time_t now = time(NULL);

	tmptr = gmtime_r(&now, &tmbuf);
	i = (int)strftime(buf, sizeof (buf),
	    "Date: %a, %d %b %Y %H:%M:%S UTC\r\n", tmptr);
	hdrs.write(buf, i);
    }
    if (mime)
	hdrs << "Content-Type: " << mime << CRLF;
    if (mtime) {
	tmptr = gmtime_r(&mtime, &tmbuf);
	i = (int)strftime(buf, sizeof (buf),
	    "Last-Modified: %a, %d %b %Y %H:%M:%S UTC\r\n", tmptr);
	hdrs.write(buf, i);
    }
    _status = sts;
    if (close)
	hdrs << "Connection: close\r\n";
    else
	keepalive();
}

void HTTPServerSocket::header(const char *attr, const char *val) {
    hdrs << attr << ": " << val << CRLF;
}

void HTTPServerSocket::error(uint sts, bool close) {
    const char *p;
    static const char *err2xx[] = {
	"OK", "Created", "Accepted", "Non-Authoritative Information",
	"No Content", "Reset Content", "Parial Content"
    };
    static const char *err3xx[] = {
	"Multiple Choices", "Moved Permanently", "Found", "See Other",
	"Not Modified", "Use Proxy", "Reserved", "Temporary Redirect"
    };
    static const char *err4xx[] = {
	"Bad Request", "Unauthorized", "Payment required", "Forbidden",
	"Not Found", "Method Not Allowed", "Not Acceptable",
	"Proxy Authentication Required", "Request Timeout", "Conflict",
	"Gone", "Length Required", "Precondition Failed",
	"Request Entity Too Large", "Request-URI Too Long",
	"Unsupported Media Type", "Requested Range Not Satisfiable",
	"Expectation Failed"
    };
    static const char *err5xx[] = {
	"Bad Request", "Unauthorized", "Payment required", "Forbidden",
	"Internal Server Error", "Not Implemented", "Bad Gateway",
	"Service Unavailable", "Gateway Timeout", "Version Not Supported"
    };
#pragma warning(push)
#pragma warning(disable: 6385)	// -V557
    if (sts >= 200 && sts < 200 + sizeof (err2xx) / sizeof (char *))
	// cppcheck-suppress arrayIndexOutOfBounds
	p = err2xx[sts % 200];
    else if (sts >= 300 && sts < 300 + sizeof (err3xx) / sizeof (char *))
	p = err3xx[sts % 300];
    else if (sts >= 400 && sts < 400 + sizeof (err4xx) / sizeof (char *))
	p = err4xx[sts % 400];
    else if (sts >= 500 && sts < 500 + sizeof (err5xx) / sizeof (char *))
	p = err5xx[sts % 500];
    else
	p = "HTTP error";
#pragma warning(pop)		// +V557
    status(sts, "text/plain", 0, NULL, close);
    ss << sts << ' ' << p << CRLF;
    _status = sts;
    reply();
}

void HTTPServerSocket::error(uint sts, const char *errstr, bool close) {
    status(sts, "text/plain", 0, errstr, close);
    ss << sts << ' ' << errstr << CRLF;
    _status = sts;
    reply();
}

void HTTPServerSocket::done() {
    erase();
}

void HTTPServerSocket::get(bool head) {
    const char *ext = NULL;
    int fd;
    string s;
    struct stat statbuf;
    uint sts = 200;
    const char *val;

    if (*path == '/')
	s = '.';
    else
	s = "./";
    if (path[1])
	s += path;
    else
	s += "/default.html";		    // deal w/ language later
    if ((ext = strrchr(s.c_str(), '.')) != NULL) {
	ext++;
	if (!stricmp(ext, "./")) {
	    error(403);
	    return;
	}
    }
    if ((fd = ::open(s.c_str(), O_RDONLY|O_CLOEXEC|O_SEQUENTIAL, 0666)) == -1) {
	error(404);
	return;
    }
    if (fstat(fd, &statbuf)) {
	::close(fd);
	error(404);
	return;
    }
    if ((val = attr("if-modified-since")) != NULL) {
	if (parse_date(achartotchar(val)) >= statbuf.st_mtime)
	    sts = 304;
    } else if ((val = attr("if-unmodified-since")) != NULL) {
	if (parse_date(achartotchar(val)) < statbuf.st_mtime)
	    sts = 304;
    }
    if (val != NULL && (val = strchr(val, ';')) != NULL &&
	!strnicmp(val + 1, "length=", 7) &&
	(ulong)atol(val + 8) != (ulong)statbuf.st_size)
	sts = 200;
    status(sts, mimetype(ext), statbuf.st_mtime);
    if (sts == 200 && !head)
	reply(fd, (ulong)statbuf.st_size);
    else
	reply((const char *)NULL);
    ::close(fd);
}

const char *HTTPServerSocket::mimetype(const char *ext) const {
    static const struct mimemap {
	const char *ext;
	const char *mime;
    } mime[] = {
	{ "html", "text/html" },
	{ "js", "application/x-javascript" },
	{ "htm", "text/html" },
	{ "shtml", "text/html" },
	{ "htx", "text/html" },
	{ "gif", "image/gif" },
	{ "jpeg", "image/jpeg" },
	{ "jpg", "image/jpeg" },
	{ "jpe", "image/jpeg" },
	{ "pjpeg", "image/jpeg" },
	{ "pjp", "image/jpeg" },
	{ "aif", "audio/aiff" },
	{ "aiff", "audio/aiff" },
	{ "art", "image/x-jg" },
	{ "au", "audio/basic" },
	{ "avi", "video/x-msvideo" },
	{ "bmp", "image/bmp" },
	{ "css", "text/css" },
	{ "enc", "application/pre-encrypted" },
	{ "hqx", "application/mac-binhex40" },
	{ "doc", "application/msword" },
	{ "dot", "application/msword" },
	{ "mid", "application/mid" },
	{ "mov", "video/quicktime" },
	{ "mpa", "audio/x-mpeg" },
	{ "abs", "audio/x-mpeg" },
	{ "mpega", "audio/x-mpeg" },
	{ "mpeg", "video/mpeg" },
	{ "mpg", "video/mpeg" },
	{ "mpe", "video/mpeg" },
	{ "mpv", "video/mpeg" },
	{ "mpegv", "video/mpeg" },
	{ "m1v", "video/mpeg" },
	{ "mpeg", "video/mpeg" },
	{ "mp2", "video/mpeg" },
	{ "ra", "audio/x-pn-realaudio" },
	{ "ram", "audio/x-pn-realaudio" },
	{ "rtf", "application/rtf" },
	{ "spl", "application/futuresplash" },
	{ "swf", "application/x-shockwave-flash" },
	{ "tiff", "image/tiff" },
	{ "tif", "image/tiff" },
	{ "txt", "text/plain" },
	{ "text", "text/plain" },
	{ "vcf", "text/x-vcard" },
	{ "wav", "audio/x-wav" },
	{ "xbm", "image/x-bitmap" },
	{ "zip", "application/x-zip-compressed" },
	{ NULL, NULL }
    };

    if (ext) {
	for (uint u = 0; mime[u].ext; ++u) {
	    if (!stricmp(ext, mime[u].ext))
		return mime[u].mime;
	}
    }
    return "application/octet-stream";
}
