/*
 * Copyright 2001-2010 Todd Richmond
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

typedef struct mimemap {
    const char *ext;
    const char *type;
    const char *subtype;
} mimemap;

static mimemap mime[] = {
    { "html", "text", "html" },
    { "js", "application", "x-javascript" },
    { "htm", "text", "html" },
    { "shtml", "text", "html" },
    { "htx", "text", "html" },
    { "gif", "image", "gif" },
    { "jpeg", "image", "jpeg" },
    { "jpg", "image", "jpeg" },
    { "jpe", "image", "jpeg" },
    { "jpfif", "image", "jpeg" },
    { "pjpeg", "image", "jpeg" },
    { "pjp", "image", "jpeg" },
    { "aif", "audio", "aiff" },
    { "aiff", "audio", "aiff" },
    { "art", "image", "x-jg" },
    { "au", "audio", "basic" },
    { "avi", "video", "x-msvideo" },
    { "bmp", "image", "bmp" },
    { "cs", "text", "css" },
    { "enc", "application", "pre-encrypted" },
    { "hqx", "application", "mac-binhex40" },
    { "doc", "application", "msword" },
    { "dot", "application", "msword" },
    { "mid", "application", "mid" },
    { "mov", "video", "quicktime" },
    { "mpa", "audio", "x-mpeg" },
    { "abs", "audio", "x-mpeg" },
    { "mpega", "audio", "x-mpeg" },
    { "mpeg", "video", "mpeg" },
    { "mpg", "video", "mpeg" },
    { "mpe", "video", "mpeg" },
    { "mpv", "video", "mpeg" },
    { "mpegv", "video", "mpeg" },
    { "m1v", "video", "mpeg" },
    { "mpeg", "video", "mpeg" },
    { "mp2", "video", "mpeg" },
    { "ra", "audio", "x-pn-realaudio" },
    { "ram", "audio", "x-pn-realaudio" },
    { "rtf", "application", "rtf" },
    { "spl", "application", "futuresplash" },
    { "swf", "application", "x-shockwave-flash" },
    { "tiff", "image", "tiff" },
    { "tif", "image", "tiff" },
    { "txt", "text", "plain" },
    { "text", "text", "plain" },
    { "vcf", "text", "x-vcard" },
    { "wav", "audio", "x-wav" },
    { "xbm", "image", "x-bitmap" },
    { "zip", "application", "x-zip-compressed" },
    { NULL, NULL, NULL }
};

static string CRLF("\r\n");

bool HTTPServerSocket::date;

HTTPServerSocket::HTTPServerSocket(Dispatcher &dspr, Socket &sock):
    DispatchServerSocket(dspr, sock), data(NULL), postdata(NULL), datasz(0),
    sz(0), delpost(false), nagleon(true), fmap(NULL), rto(RTimeout),
    wto(WTimeout) {
}

HTTPServerSocket::~HTTPServerSocket(void) {
    delete [] data;
#ifdef _WIN32
    if (fmap)
	UnmapViewOfFile(fmap);
#else
    delete [] fmap;
#endif
    if (delpost)
	delete [] postdata;
    eos();
}

void HTTPServerSocket::readhdrs() {
    uint room = (uint)(sz - datasz);
    int in;

    if (msg == Dispatcher::Timeout || msg == Dispatcher::Close) {
	erase();
	return;
    }
    if (!room) {
	char *old = data;

	sz += 1000;
	room = (uint)(sz - datasz);
	data = new char[sz];
	memcpy(data, old, datasz);
	delete [] old;
    }
    in = read(data + datasz, room);
    if (in == -1) {
	erase();
	return;
    }
    if (datasz + in > 3) {
	ulong oldsz = datasz;

	room = datasz < 3 ? (int)datasz : 3;
	datasz += in;
	scan(data + oldsz - room, in + room);
    } else {
	datasz += in;
	readable(readhdrs, rto);
    }
}

void HTTPServerSocket::readpost() {
    uint in = 0;
    uint room = (uint)(sz - datasz);
    uint left = room > 100 && postsz == (uint)-1 ? room : (uint)(postsz -
	postin);

    if (msg == Dispatcher::Timeout || msg == Dispatcher::Close) {
	erase();
	return;
    }
    if (msg != Dispatcher::Close && room < left &&
	(!delpost || postsz == (uint)-1)) {
	char *old = postdata;

	if (postsz == (uint)-1) {
	    in = postin < 16 * 1024 ? 16 * 1024 : (uint)(postin * 2);
	    left = (uint)(in - postin);
	} else {
	    in = (uint)postsz;
	}
	postdata = new char[in + 1];
	memcpy(postdata, old, postin);
	if (delpost)
	    delete [] old;
	else
	    delpost = true;
    }
    if (msg == Dispatcher::Close ||
	(in = (uint)read(postdata + postin, left)) == (uint)-1) {
	if (postsz == (uint)-1) {
	    left = in = 0;
	    postsz = postin;
	} else {
	    erase();
	    return;
	}
    }
    if (!delpost)
	datasz += in;
    postin += in;
    left -= in;
    if (left || postsz == (uint)-1) {
	readable(readpost, rto);
    } else {
	savechar = postdata[postsz];
	postdata[postsz] = '\0';
	exec();
    }
}

void HTTPServerSocket::scan(char *buf, int len, bool append) {
    if (delpost) {
	delete [] postdata;
	delpost = false;
    }
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
	    } else if (len && buf[1] == '\n') {
		postdata = buf + 2;
		buf[0] = '\r';
		buf[1] = '\0';
		parse();
		return;
	    } else if (len >= 2 && (buf[1] == '\r' && buf[2] == '\n')) {
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

void HTTPServerSocket::parse(void) {
    char *p, *pp, *start, *end;
    char *buf = data;
    const char *val;
    bool noprot;

    delpost = false;
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
	urldecode(pp, args);
    }
    if (!noprot) {
	while (*p == ' ' || *p == '\t')
	    p++;
	for (prot = p; *p != ' ' && *p != '\t' && *p != '\r'; p++)
	    continue;
	*p++ = '\0';
    }
    if (strnicmp(prot, "HTTP/1.", 7) || !prot[7] || prot[8] ||
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
	end = strchr(buf, '\r');
	while (end[2] == ' ' || end[2] == '\t') {   // unfold hdrs
	    end += 2;
	    for (start = end + 2; *start == ' ' || *start == '\t'; start++)
		continue;
	    p = strchr(start, '\r');
	    memmove(end, start, p - start);
	    end = p;
	}
	while (*buf == ' ' || *buf == '\t')
	    buf++;
	p = end;
	while (*p == ' ' || *p == '\t')
	    p--;
	*p = '\0';
	if (p == buf)
	    break;
	if ((p = strchr(buf, ':')) != NULL) {
	    pp = p + 1;
	    while (p > buf && (p[-1] == ' ' || p[-1] == '\t'))
		p--;
	    *p++ = '\0';
	    p = pp;
	    while (*p == ' ' || *p == '\t')
		p++;
	    attrs[buf] = p;
	}
	if (end[1])
	    buf = end + 2;
	else
	    break;
    }
    val = attr("content-length");
    if (val)
	postsz = (uint)atol(val);
    else if (!stricmp(cmd, "POST") || !stricmp(cmd, "PUT"))
	postsz = (uint)-1;
    else
	postsz = 0;
    if (postsz) {
	postin = datasz - (ulong)(postdata - data);
	if (postin > postsz)
	    postin = postsz;
	if (postin == postsz) {
	    savechar = postdata[postsz];
	    postdata[postsz] = '\0';
	    exec();
	} else {
	    readable(readpost, rto);
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
#ifdef UNICODE // TODO
    (void)buf; (void)amap;
#else
    char *p = buf, *pp;

    amap.clear();
    while (p) {
	while (*p == ' ' || *p == '\t')
	    p++;
	buf = p;
	if ((p = strchr(p, '&')) != NULL)
	    *p++ = '\0';
	URL::unescape(buf);
	if ((pp = strchr(buf, '=')) == NULL) {
	    amap[buf] = "";
	} else {
	    *pp++ = '\0';
	    amap[buf] = pp;
	}
    }
#endif
}

inline void HTTPServerSocket::keepalive(void) {
    const char *p = "Pragma";
    const char *val = attr(p);
    static const char *keep = "keep-alive";

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

    if (msg == Dispatcher::Timeout || msg == Dispatcher::Close) {
	erase();
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
	eos();
	datasz -= delpost ? datasz : postsz + (ulong)(postdata - data);
	if (datasz) {
	    postdata[postsz] = savechar;
	    memmove(data, postdata + postsz, datasz);
	    scan(data, (uint)datasz, true);
	} else {
	    readable(readhdrs, rto);
	}
    } else {
	erase();
    }
}

void HTTPServerSocket::reply(const char *p, size_t len) {
    char buf[64];
    int i;

    if (!len && p)
	len = strlen(p);
    i = sprintf(buf, "Content-Length: %lu\r\n\r\n", (ulong)ss.size() + len);
    hdrs.write(buf, i);
    iov[0].iov_base = (char *)hdrs.str();
    iov[0].iov_len = (size_t)hdrs.size();
    iov[1].iov_base = (char *)ss.str();
    iov[1].iov_len = (size_t)ss.size();
    iov[2].iov_base = (char *)p;
    iov[2].iov_len = len;
    dlog << (_status < 400 ? Log::Info : Log::Note) << cmd << ' ' << path <<
	T(": ") << _status << endlog;
    send();
}

void HTTPServerSocket::reply(int fd, size_t len) {
    char buf[1024];

    if (len < sizeof (buf)) {
	if ((size_t)::read(fd, buf, (uint)len) != len) {
	    error(404);
	    return;
	}
	ss.write(buf, len);
	len = 0;
    } else {
#ifdef _WIN32
	HANDLE hdl;

	if ((hdl = CreateFileMapping((HANDLE)fd, NULL, PAGE_READONLY,
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
	if ((fmap = new char[len]) == NULL || (size_t)::read(fd, fmap, len) != len) {
	    error(404);
	    return;
	}
#endif
    }
    reply(fmap, len);
}

void HTTPServerSocket::status(uint sts, const char *type,
    const char *subtype, time_t mtime) {
    struct tm tmbuf, *tmptr;
    char buf[64];
    size_t i;

    hdrs.reset();
    ss.reset();
    i = sprintf(buf, "%s %u OK\r\n", prot, sts);
    hdrs.write(buf, i);
    if (date) {
	time_t now = time(NULL);

	tmptr = gmtime_r(&now, &tmbuf);
	i = strftime(buf, sizeof (buf), "Date: %a, %d %b %Y %H:%M:%S UTC\r\n",
	    tmptr);
	hdrs.write(buf, i);
    }
    if (type)
	hdrs << "Content-Type: " << type << '/' << subtype << CRLF;
    if (mtime) {
	tmptr = gmtime_r(&mtime, &tmbuf);
	i = strftime(buf, sizeof (buf),
	    "Last-Modified: %a, %d %b %Y %H:%M:%S UTC\r\n", tmptr);
	hdrs.write(buf, i);
    }
    _status = sts;
    keepalive();
}

void HTTPServerSocket::header(const char *attr, const char *val) {
    hdrs << attr << ": " << val << CRLF;
}

void HTTPServerSocket::error(uint sts) {
    const char *p;
    static const char *errstr[] = {
	"Bad Request", "Unauthorized", "Payment required", "Forbidden",
	"Not Found", "Method Not Allowed", "Not Acceptable",
	"Proxy Authentication Required", "Request Timeout", "Conflict",
	"Gone", "Length Required", "Precondition Failed",
	"Request Entity Too Large", "Request-URI Too Long",
	"Unsupported Media Type", "Requested Range Not Satisfiable",
	"Expectation Failed"
    };

    if (sts >= 400 && sts < 400 + sizeof (errstr) / sizeof (char *))
	p = errstr[sts % 400];
    else
	p = "HTTP error";
    status(sts, "text", "plain");
    ss << sts << ' ' << p << CRLF;
    _status = sts;
    reply();
}

void HTTPServerSocket::get(bool head) {
    const char *type = "application";
    const char *subtype = "octet-stream";
    struct stat sbuf;
    const char *p;
    int fd;
    int i;
    uint sts = 200;
    const char *val;
    string s;

    if (*path == '/')
	s = '.';
    else
	s = "./";
    if (path[1])
	s += path;
    else
	s += "/default.html";		    // deal w/ language later
    if ((p = strrchr(s.c_str(), '.')) != NULL) {
	p++;
	for (i = 0; mime[i].ext; i++) {
	    if (!stricmp(p, mime[i].ext)) {
		type = mime[i].type;
		subtype = mime[i].subtype;
		break;
	    }
	}
    }
    if ((fd = ::open(s.c_str(), O_RDONLY|O_SEQUENTIAL, 0666)) == -1) {
	error(404);
	return;
    }
    if (fstat(fd, &sbuf)) {
	::close(fd);
	error(404);
	return;
    }
    if ((val = attr("if-modified-since")) != NULL) {
	if (parse_date(achartotchar(val)) >= sbuf.st_mtime)
	    sts = 304;
    } else if ((val = attr("if-unmodified-since")) != NULL) {
	if (parse_date(achartotchar(val)) < sbuf.st_mtime)
	    sts = 304;
    }
    if (val != NULL && (val = strchr(val, ';')) != NULL &&
	!strnicmp(val + 1, "length=", 7) &&
	(ulong)atol(val + 8) != (ulong)sbuf.st_size)
	sts = 200;
    status(sts, type, subtype, sbuf.st_mtime);
    if (sts == 200 && !head)
	reply(fd, (size_t)sbuf.st_size);
    else
	reply((const char *)NULL);
    ::close(fd);
}

