/*
 * Copyright 2001-2017 Todd Richmond
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
#include "Log.h"
#include "SMTPClient.h"
#include "Thread.h"

#ifdef _WIN32
#pragma warning(disable: 6328)
#pragma warning(disable: 6330)
#endif

string SMTPClient::crlf("\r\n");

SMTPClient::SMTPClient(): sstrm(sock), datasent(false), lmtp(false),
    mime(false), parts(0) {}

bool SMTPClient::add(vector<string> &v, const RFC822Addr &addrs) {
    bool ret = true;

    if (!addrs.size())
	return false;
    for (uint u = 0; u < addrs.size(); u++) {
	ret = cmd("RCPT TO:", addrs.address(u).c_str()) && ret;
	v.push_back(addrs.address(u, true));
    }
    return ret;
}

bool SMTPClient::add(vector<string> &v, const char *id) {
    bool ret = cmd(T("RCPT TO:"), id);
    v.push_back(id);
    return ret;
}

void SMTPClient::attribute(const tchar *attr, const tchar *val) {
    tstring s(attr);

    s += T(": ");
    s += val;
    hdrv.push_back(s);
}

bool SMTPClient::auth(const tchar *id, const tchar *pass) {
    size_t idlen = tstrlen(id) + 1;
    size_t passlen = tstrlen(pass) + 1;
    size_t uusz;
    char *uubuf;
    bool ret = false;

    if (exts.find(T("AUTH ")) == exts.npos) {
	// return "success" if server is open and does not allow auth
	ret = true;
    } else if (exts.find(T(" PLAIN")) != exts.npos) {
	char *buf = new char[idlen + passlen + 1];

	buf[0] = '\0';
	memcpy(buf + 1, tchartoachar(id), idlen);
	memcpy(buf + 1 + idlen, tchartoachar(pass), passlen);
	base64encode(buf, idlen + passlen, uubuf, uusz);
	while (isspace(uubuf[uusz - 1]))
	    uubuf[--uusz] = '\0';
	ret = cmd(T("AUTH PLAIN"), achartotchar(uubuf), 235);
	delete [] buf;
	delete [] uubuf;
    } else if (exts.find(T(" LOGIN")) != exts.npos) {
	base64encode(id, idlen, uubuf, uusz);
	while (isspace(uubuf[uusz - 1]))
	    uubuf[--uusz] = '\0';
	ret = cmd(T("AUTH LOGIN"), achartotchar(uubuf), 334);
	delete [] uubuf;
	if (ret && (ret = base64encode(pass, passlen, uubuf, uusz)) == true) {
	    while (isspace(uubuf[uusz - 1]))
		uubuf[--uusz] = '\0';
	    ret = cmd(achartotchar(uubuf), NULL, 235);
	    delete [] uubuf;
	}
    }
    return ret;
}

bool SMTPClient::cmd(const tchar *s1, const tchar *s2, int retcode) {
    string asts;
    
    multi.erase();
    if (s1) {
	sstrm << tchartoachar(s1);
	if (s2) {
	    bool addbracket = false;

	    if (s1[tstrlen(s1) - 1] != ':') {
		if (s2[0] != '<') {
		    addbracket = true;
		    sstrm << '<';
		}
	    } else {
		sstrm << ' ';
	    }
	    sstrm << tchartoachar(s2);
	    if (addbracket)
		sstrm << '>';
	}
	sstrm << crlf;
    }
    do {
	sts.erase();
	if (!sstrm) {
	    dlogd(T("mod=smtp status=closed"));
	    return false;
	} else if (!getline(sstrm, asts)) {
	    sock.close();
	    sts = T("000 socket disconnect");
	    dlogd(T("mod=smtp action=disconnect"));
	    return false;
	}
	sts = achartotstring(asts.c_str());
	if (sts.length() < 3 || (sts[3] != '-' && sts[3] != ' ')) {
	    dlogd(T("mod=smtp data=invalid"),
		Log::kv(T("reply"), sts.c_str()));
	    return false;
	}
	while (isspace(sts[sts.size() - 1]))
	    sts.erase(sts.size() - 1);
	if (!multi.empty())
	    multi += '\n';
	multi += sts.substr(4);
	dlogt(Log::kv(T("mod=smtp expected"), retcode),
	    Log::kv(T("reply"), sts.c_str()));
    } while (sts[3] == '-');
    return code() == retcode;
}

bool SMTPClient::connect(const Sockaddr &addr, uint to) {
    bool ret;

    sock.close();
    if (!addr.port()) {
	Sockaddr tmp(addr);

	tmp.port(25);
	ret = sock.connect(tmp, to);
    } else {
	ret = sock.connect(addr, to);
    }
    if (!ret) {
	sock.close();
	return false;
    }
    timeout(3 * 60 * 1000, 5 * 60 * 1000);
    sstrm.clear();
    sstrm.rdbuf()->str(NULL, 4096);
    return cmd(NULL, NULL, 220);
}

bool SMTPClient::ehlo(const tchar *domain) {
    if (cmd(T("EHLO"), domain ? domain : Sockaddr::hostname().c_str())) {
	exts = multi;
	return true;
    } else {
	return false;
    }
}

bool SMTPClient::from(const tchar *id) {
    tov.clear();
    ccv.clear();
    bccv.clear();
    hdrv.clear();
    sub.erase();
    sstrm.flush();
    sstrm.clear();
    datasent = false;
    mime = false;
    parts = 0;
    if (!*id)
	id = "<>";
    frm = id;
    return cmd(T("MAIL FROM:"), id);
}

bool SMTPClient::from(const RFC822Addr &addr) {
    tov.clear();
    ccv.clear();
    bccv.clear();
    hdrv.clear();
    sub.erase();
    sstrm.flush();
    sstrm.clear();
    datasent = false;
    mime = false;
    parts = 0;
    if (!addr.size())
	return false;
    frm =  addr.address(0, true);
    return cmd(T("MAIL FROM:"), addr.address().c_str());
}

bool SMTPClient::helo(const tchar *domain) {
    exts.erase();
    return cmd(T("HELO"), domain ? domain : Sockaddr::hostname().c_str());
}

bool SMTPClient::lhlo(const tchar *domain) {
    if (cmd(T("LHLO"), domain ? domain : Sockaddr::hostname().c_str())) {
	exts = multi;
	lmtp = true;
	return true;
    } else {
	return false;
    }
}

bool SMTPClient::quit() {
    bool ret = cmd(T("QUIT"), NULL, 221);

    sock.close();
    return ret || code() == 421;
}

void SMTPClient::recip(const tchar *hdr, const vector<tstring> &v) {
    vector<tstring>::const_iterator it;

    if (v.empty())
	return;
    sstrm << tchartoachar(hdr);
    for (it = v.begin(); it != v.end(); ++it) {
	const tstring &s = *it;

	if (it != v.begin())
	    sstrm << ",\r\n\t";
	sstrm << tstringtoachar(s);
    }
    sstrm << crlf;
}

bool SMTPClient::rcpt(const tchar *id) {
    RFC822Addr addr(id);

    return cmd(T("RCPT TO:"), addr.address().c_str());
}

bool SMTPClient::xclient(const tchar *xclient_cmd) {
    return cmd(T("XCLIENT"), xclient_cmd);
}

bool SMTPClient::vrfy(const tchar *id) {
    RFC822Addr addr(id);

    return cmd(T("VRFY"), addr.address(0, false, false).c_str());
}

bool SMTPClient::data(const void *start, size_t sz, bool dotstuff) {
    if (!datasent) {
	if (!cmd(T("DATA"), NULL, 354))
	    return false;
	datasent = true;
    }
    if (!start || !sz) {
	return true;
    } else if (dotstuff) {
	return stuff(start, sz);
    } else {
	sstrm.write(start, sz);
	sstrm << crlf;
	return sstrm.good();
    }
}

bool SMTPClient::data(bool m, const tchar *txt) {
    static TSNumber<uint64_t> nextmid((time(NULL) << 18) & uticks());
    char buf[64], gmtoff[16];
    int diff;
    char *encbuf;
    size_t encbufsz;
    vector<tstring>::const_iterator it;
    uint64_t mid = nextmid++;
    time_t now;
    uint pid = getpid();
    tm *tm = NULL, tmbuf, *tm2, tm2buf;

    mime = m;
    if (!cmd(T("DATA"), NULL, 354))
	return false;
    memcpy(buf, &pid, 4);
    memcpy(buf + 4, &mid, 8);
    if (!base64encode(buf, 12, encbuf, encbufsz))
	return false;
    encbuf[encbufsz - 2] = '\0';
    sstrm << "Message-ID: <" << encbuf << '@' <<
	tstringtoastring(Sockaddr::hostname()) << '>' << crlf;
    delete [] encbuf;
    time(&now);
    tm = localtime_r(&now, &tmbuf);
    tm2 = gmtime_r(&now, &tm2buf);
    strftime(buf, sizeof (buf), "%a, %d %b %Y %H:%M:%S ", tm);
    diff = (tm->tm_hour - tm2->tm_hour) * 100 + tm->tm_min - tm2->tm_min;
    if (tm2->tm_wday != tm->tm_wday)
	diff -= 2400 * (tm2->tm_wday > tm->tm_wday ||
	    (tm2->tm_wday == 0 && tm->tm_wday == 6) ? 1 : -1);
    if (diff < 0)
	sprintf(gmtoff, "-%04d", -1 * diff);
    else
	sprintf(gmtoff, "+%04d", diff);
    sstrm << "Date: " << buf << gmtoff << crlf;
    sstrm << "From: " << tstringtoastring(frm) << crlf;
    recip(T("To: "), tov);
    recip(T("Cc: "), ccv);
    sstrm << "Subject: " << tstringtoastring(sub) << crlf;
    for (it = hdrv.begin(); it != hdrv.end(); ++it)
	sstrm << tstringtoastring(*it) << crlf;
    if (mime) {
	sprintf(buf, "--%x%x%x%x", rand(), rand(), rand(), rand());
	boundary = buf;
	sstrm << "MIME-Version: 1.0" << crlf;
	sstrm << "Content-Type: multipart/mixed; boundary=\"" << boundary <<
	    '"' << crlf << crlf <<
	    "This is a multi-part message in MIME format." << crlf << crlf;
	if (txt) {
	    sstrm << "--" << boundary << crlf;
	    sstrm << "Content-Type: " << "txt/plain" << crlf << crlf;
	}
    } else {
	sstrm << crlf;
    }
    if (txt) {
#ifdef UNICODE
	string as(wchartoastring(txt));

	stuff(as.c_str(), as.size());
#else
	stuff(txt, strlen(txt));
#endif
	if (mime)
	    sstrm << crlf << "--" << boundary << "--" << crlf;
    }
    return sstrm.good();
}

bool SMTPClient::data(const void *p, uint sz, const tchar *type,
    const tchar *desc, const tchar *encoding, const tchar *disp,
    const tchar *name) {
    if (mime)
	sstrm << "--" << boundary << crlf;
    if (type && *type)
	sstrm << "Content-Type: " << tchartoachar(type) << crlf;
    if (desc && *desc)
	sstrm << "Content-Description: " << tchartoachar(desc) << crlf;
    if (encoding && *encoding)
	sstrm << "Content-Transfer-Encoding: " << tchartoachar(encoding) << crlf;
    sstrm << "Content-Disposition: " << tchartoachar(disp && *disp ? disp :
	T("inline"));
    if (name && *name)
	sstrm << "; filename=" << tchartoachar(name) << crlf;
    sstrm << crlf;
    stuff(p, sz);
    return sstrm.good();
}

bool SMTPClient::enddata() {
    if (mime)
	sstrm << "--" << boundary << "--" << crlf;
    return cmd(T("."));
}

bool SMTPClient::stuff(const void *data, size_t sz) {
    const char *start = (const char *)data;
    const char *p, *pp;
    const char *end = start + sz - 1;

    for (p = pp = start; p <= end; p++) {
	if (*p == '.' && (p == start || p[-1] == '\n')) {
	    sstrm.write(pp, p - pp);
	    sstrm << "..";
	    pp = p + 1;
	} else if (*p == '\n' && (p == start || p[-1] != '\r')) {
	    sstrm.write(pp, p - pp);
	    sstrm << crlf;
	    pp = p + 1;
	}
    }
    sstrm.write(pp, p - pp);
    if (*end != '\n')
	sstrm << crlf;
    return sstrm.good();
}

#define IS_ATEXT(c) (chartraits[(uchar)(c)] & (1 + 2 + 8))
#define IS_DIGIT(c) (chartraits[(uchar)(c)] & 8)
#define IS_DOMAIN(c) (chartraits[(uchar)(c)] & (2 + 4 + 8))

static const uchar chartraits[] = {
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0x0..0x7
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0x8..0xf
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0x10..0x17
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0x18..0x1f
    0,    1,    0,  1+4,    1,    1,    1,    1, 	// 0x20..0x27
    0,    0,    1,    1,    0,  1+4,    4,    1, 	// 0x28..0x2f
    8,    8,    8,    8,    8,    8,    8,    8, 	// 0x30..0x37
    8,    8,    4,    0,    0,    1,    0,    1, 	// 0x38..0x3f
    0,    2,    2,    2,    2,    2,    2,    2, 	// 0x40..0x47
    2,    2,    2,    2,    2,    2,    2,    2, 	// 0x48..0x4f
    2,    2,    2,    2,    2,    2,    2,    2, 	// 0x50..0x57
    2,    2,    2,    4,    0,    4,    1,  1+4, 	// 0x58..0x5f
    1,    2,    2,    2,    2,    2,    2,    2, 	// 0x60..0x67
    2,    2,    2,    2,    2,    2,    2,    2, 	// 0x68..0x6f
    2,    2,    2,    2,    2,    2,    2,    2, 	// 0x70..0x77
    2,    2,    2,    1,    1,    1,    1,    0, 	// 0x78..0x7f
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0x80..0x87
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0x88..0x8f
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0x90..0x97
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0x98..0x9f
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xa0..0xa7
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xa8..0xaf
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xb0..0xb7
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xb8..0xbf
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xc0..0xc7
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xc8..0xcf
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xd0..0xd7
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xd8..0xdf
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xe0..0xe7
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xe8..0xef
    0,    0,    0,    0,    0,    0,    0,    0, 	// 0xf0..0xf7
    0,    0,    0,    0,    0,    0,    0,    0 	// 0xf8..0xff
};

static const tchar *NonASCII = T("Non-ASCII character");

void RFC821Addr::parseaddr(const tchar *&input) {
    uint angledepth = 0;
    uint parendepth = 0;
    bool saw_colon = false;
    tstring::size_type anglelast = tstring::npos;

    addr.erase();
    domain_buf.erase();
    err.erase();
    local_part.erase();
    while (istspace(*input))
	++input;
    // Pass 1
    for (;;) {
	tuchar c = *input++;
	if (c & 0x80) {
	    err = NonASCII;
	    goto fail;
	}
	switch (c) {
	default:
	    addr += c;
	    break;

	case '"':
	    for (;;) {
		addr += c;
		c = *input++;
		if (c == '\\') {
		    addr += c;
		    c = *input++;
		} else if (c == '"') {
		    addr += c;
		    break;
		}
		if (c & 0x80) {
		    err = NonASCII;
		    goto fail;
		}
		if (!c) {
		    err = T("Unbalanced '\"'");
		    goto fail;
		}
	    }
	    break;

	case '(':
	    addr += ' ';
	    parendepth = 1;
	    do {
		c = *input++;
		if (c == '(') {
		    ++parendepth;
		} else if (c == ')') {
		    --parendepth;
		} else if (c == '\\') {
		    c = *input++;
		}
		if (c & 0x80) {
		    err = NonASCII;
		    goto fail;
		}
		if (!c) {
		    err = T("Unbalanced '('");
		    goto fail;
		}
	    } while (parendepth);
	    break;

	case ')':
	    err = T("Unbalanced ')'");
	    goto fail;

	case '<':
	    addr.erase();
	    anglelast = string::npos;
	    ++angledepth;
	    break;

	case '>':
	    if (!angledepth--) {
		err = T("Unbalanced '>'");
		goto fail;
	    }
	    if (anglelast == string::npos)
		anglelast = addr.length();
	    break;

	case '\\':
	    c = *input++;
	    if (c & 0x80) {
		err = NonASCII;
		goto fail;
	    }
	    if (c && !isspace(c)) {
		addr += '\\';
		addr += c;
		break;
	    }
	    /* no break backslash before whitespace is ignored */
	case ' ':
	case '\t':
	case '\v':
	case '\f':
	case '\r':
	case '\n':
	    if (c && angledepth) {
		addr += ' ';
		break;
	    }
	    /* no break */
	case '\0':
	    --input;
	    goto pass1done;
	}
    }

 pass1done:
    if (angledepth) {
	err = T("Unbalanced '<'");
	goto fail;
    }
    if (anglelast != string::npos)
	addr.erase(anglelast);
    // Pass 2
    for (tstring::size_type pos = 0; pos < addr.length();) {
	tuchar c = addr[pos++];

	switch (c) {
	case '@':
	    parsedomain(pos);
	    if (!err.empty())
		goto fail;
	    if (pos == addr.length()) {
		if (domain_buf.empty()) {
		    err = T("Hostname required");
		    goto fail;
		}
		goto pass2done;
	    }
	    switch (c = addr[pos++]) {
	    case ',':
	    case '@':
		if (!local_part.empty()) {
		    err = T("Invalid route address");
		    goto fail;
		}
		/* no break */
	    case ':':
		// Strip route-address
		local_part.erase();
		domain_buf.erase();
		continue;

	    default:
		err = T("Invalid domain");
		goto fail;
	    }
	    break;
	case '"':
	    while ((c = addr[pos++]) != '"') {
		if (c == '\\')
		    c = addr[pos++];
		local_part += c;
	    }
	    continue;

	case '\\':
	    local_part += addr[pos++];
	    continue;

	case ' ':
	case '.': {
		bool saw_dot = (c == '.');
		while (pos < addr.length() && 
		       ((c = addr[pos]) == ' ' || (!saw_dot && c == '.'))) {
		    if (c == '.')
			saw_dot = true;
		    ++pos;
		}
		if (saw_dot || (!local_part.empty() && pos < addr.length() && addr[pos] != '@'))
		    local_part += '.';
	    }
	    continue;

	case ';':
	    if (saw_colon) {
		err = T("List:; syntax illegal");
		goto fail;
	    }
	    /* no break */
	default:
	    local_part += c;
	    continue;

	case ',':
	    err = T("Invalid route address");
	    goto fail;

	case ':':
	    saw_colon = true;
	    local_part.erase();
	    continue;
	}
    }

 pass2done:
    if (local_part.empty()) {
	err = T("User address required");
	goto fail;
    }

    make_address();
    return;

 fail:
    addr.erase();
    domain_buf.erase();
    local_part.erase();
}

void RFC821Addr::parsedomain(tstring::size_type &pos) {
    bool sawspace = false;

    while (pos < addr.length()) {
	tuchar c = addr[pos++];

	switch (c) {
	case '.':
	    if (sawspace) {
		sawspace = false;
		continue;
	    }
	    if (domain_buf.empty() || domain_buf[domain_buf.length()-1] == '.')
		goto done;
	    domain_buf += c;
	    sawspace = false;
	    continue;

	case ' ':
	    if (!domain_buf.empty() && domain_buf[domain_buf.length()-1] != '.') {
		domain_buf += '.';
		sawspace = true;
	    }
	    continue;

	case '[':
	    sawspace = false;
	    domain_buf += c;
	    for (;;) {
		if (pos == addr.length()) {
		    err = T("Invalid domain");
		    return;
		}
		c = addr[pos++];
		if (c == ']') {
		    domain_buf += c;
		    break;
		}
		if (c == '\\') {
		    if (pos == addr.length()) {
			err = T("Invalid domain");
			return;
		    }
		    c = addr[pos++];
		    if (c == '\\' || c == '[' || c == ']') {
			domain_buf += '\\';
		    }
		}
		if (c & 0x80) {
		    err = NonASCII;
		    return;
		}
		domain_buf += c;
	    }
	    continue;

	case '\\':
	    sawspace = false;
	    if (pos == addr.length()) {
		err = T("Invalid domain");
		return;
	    }
	    c = addr[pos++];
	    if (c & 0x80) {
		err = NonASCII;
		return;
	    }
	    domain_buf += '\\';
	    domain_buf += c;
	    continue;

	default:
	    sawspace = false;
	    if (c & 0x80) {
		err = NonASCII;
		return;
	    }
	    domain_buf += c;
	    continue;

	case ':':
	case ',':
	case '@':
	case ';':
	    --pos;
	    goto done;
	}
    }
    done:
    while (!domain_buf.empty() && domain_buf[domain_buf.length()-1] == '.')
	domain_buf.erase(domain_buf.length()-1);
    if (domain_buf.empty())
	err = T("Invalid domain");
}

void RFC821Addr::setDomain(const tchar *domain) {
    domain_buf = domain;
    make_address();
}

void RFC821Addr::setLocal(const tchar *local) {
    local_part = local;
    make_address();
}

void RFC821Addr::make_address() {
    tstring::size_type pos;

    for (pos = 0; pos < local_part.length(); ++pos) {
	tuchar c = local_part[pos];

	if (c == '.') {
	    if (pos == 0 || pos == local_part.length()-1 ||
		local_part[pos + 1] == '.')
		break;
	} else if (!IS_ATEXT(c)) {
	    break;
	}
    }
    if (pos < local_part.length()) {
	addr = '"';
	for (pos = 0; pos < local_part.length(); ++pos) {
	    tuchar c = local_part[pos];

	    if (c == '"' || c == '\\')
		addr += '\\';
	    addr += c;
	}
	addr += '"';
    } else {
	addr = local_part;
    }
    if (!domain_buf.empty()) {
	addr += '@';
	addr += domain_buf;
    }
}

uint RFC822Addr::parse(const tchar *addrs) {
    tchar *d, *m, *n, *r, *unused;
    size_t len = tstrlen(addrs) + 1;
    tchar *phrase, *s;
    int tok = ' ';

    if (buf) {
	delete [] buf;
	buf = NULL;
	domains.clear();
	locals.clear();
	phrases.clear();
	routes.clear();
    }
    if ((!tstrrchr(addrs, '<') && !tstrrchr(addrs, ';') &&
	!tstrrchr(addrs, ',')) || !tstrrchr(addrs, '>')) {
	s = buf = new tchar [len + 2];
	s[0] = '<';
	memcpy(s + 1, addrs, len - 1);
	s[len] = '>';
	s[len + 1] = '\0';
    } else {
	s = buf = new tchar [len];
	memcpy(s, addrs, len);
    }
    while (tok) {
	tok = parse_phrase(s, phrase, T(",@<;:"));
	switch (tok) {
	case ',':
	case '\0':
	case ';':
	    continue;
	case ':':
	    parse_append(NULL, NULL, phrase, NULL);
	    continue;
	case '@':
	    tok = parse_domain(s, d, n);
	    parse_append(n, NULL, phrase, d);
	    continue;
	case '<':
	    tok = parse_phrase(s, m, T("@>"));
	    if (tok == '@') {
		r = 0;
		if (!*m) {
		    *--s = '@';
		    tok = parse_route(s, r);
		    if (tok != ':') {
			parse_append(phrase, r, T(""), T(""));
			while (tok && tok != '>')
			    tok = *s++;
			continue;
		    }
		    tok = parse_phrase(s, m, T("@>"));
		    if (tok != '@') {
			parse_append(phrase, r, m, T(""));
			continue;
		    }
		}
		tok = parse_domain(s, d, unused);
		parse_append(phrase, r, m, d);
		while (tok && tok != '>')
		    tok = *s++;
		continue;		// effectively inserts a comma
	    } else {
		parse_append(phrase, NULL, m, T(""));
	    }
	}
    }
    return (uint)locals.size();
}

void RFC822Addr::parse_append(const tchar *p, const tchar *r, const tchar *l,
    const tchar *d) {
    domains.push_back(d ? d : T(""));
    phrases.push_back(p ? p : T(""));
    locals.push_back(l ? l : T(""));
    routes.push_back(r ? r : T(""));
}

int RFC822Addr::parse_phrase(tchar *&in, tchar *&phrase, const tchar *specials) {
    tchar c;
    tchar *dst, *src = in;

    skip_whitespace(src);
    phrase = dst = src;
    for (;;) {
	if (skip_whitespace(src))
	    *dst++ = ' ';
	if (*src == '\n' && src[1] != ' ' && src[1] != '\t')
	    c = '\0';
	else
	    c = *src++;
	if (c == '\"') {
	    while ((c = *src) != 0 && !(c == '\n' && src[1] != ' ' && src[1] !=
		'\t')) {
		src++;
		if (c == '\"')
		    break;
		if (c == '\\') {
		    if ((c = *src) == 0)
			break;
		    src++;
		}
		*dst++ = c;
	    }
	} else if (!c || tstrchr(specials, c)) {
	    if (dst > phrase && dst[-1] == ' ')
		dst--;
	    *dst = '\0';
	    in = src;
	    break;
	} else {
	    *dst++ = c;
	}
    }
    return c;
}

int RFC822Addr::parse_domain(tchar *&in, tchar *&dom, tchar *&cmt) {
    tchar c;
    tchar *cdst;
    int cnt;
    tchar *dst;
    tchar *src = in;

    cmt = NULL;
    skip_whitespace(src);
    dom = dst = src;
    for (;;) {
	if (*src == '\n' && src[1] != ' ' && src[1] != '\t')
	    c = '\0';
	else
	    c = *src++;
	if (isalnum(c) || c == '-' || c == '_' || c == '[' || c == ']' || c ==
	    ':') {
	    *dst++ = c;
	    cmt = NULL;
	} else if (c == '.') {
	    if (dst > dom && dst[-1] != '.')
		*dst++ = c;
	    cmt = NULL;
	} else if (c == '(') {
	    cmt = cdst = src;
	    cnt = 1;
	    while (cnt && (c = *src) != 0 &&
		!(c == '\n' && src[1] != ' ' && src[1] != '\t')) {
		src++;
		if (c == '(')
		    cnt++;
		else if (c == ')')
		    cnt--;
		else if (c == '\\' && (c = *src) != 0)
		    src++;
		if (cnt)
		    *cdst++ = c;
	    }
	    *cdst = '\0';
	} else if (!istspace(c)) {
	    if (dst > dom && dst[-1] == '.')
		dst--;
	    *dst = '\0';
	    in = src;
	    break;
	}
    }
    return c;
}

int RFC822Addr::parse_route(tchar *&in, tchar *&rte) {
    tchar c;
    tchar *dst, *src = in;

    skip_whitespace(src);
    rte = dst = src;
    for (;;) {
	skip_whitespace(src);
        c = *src++;
	if (isalnum(c) || c == '-' || c == '[' || c == ']' || c == ',' ||
	    c == '@') {
	    *dst++ = c;
	} else if (c == '.') {
	    if (dst > rte && dst[-1] != '.')
		*dst++ = c;
	} else {
	    while (dst > rte &&
		(dst[-1] == '.' || dst[-1] == ',' || dst[-1] == '@'))
		dst--;
	    *dst = '\0';
	    in = src;
	    break;
	}
    }
    return c;
}

bool RFC822Addr::skip_whitespace(tchar *&in) {
    tchar *s = in;
    tchar c;
    uint cmt = 0;

    while ((c = *s) != 0) {
	if (c == '(') {
	    cmt = 1;
	    ++s;
	    while (cmt && (c = *s) != 0 && !(c == '\n' && s[1] != ' ' &&
		s[1] != '\t')) {
		++s;
		if (c == '\\' && *s)
		    ++s;
		else if (c == '(')
		    ++cmt;
		else if (c == ')')
		    --cmt;
	    }
	    s--;
	} else if (!istspace((uchar)c)) {
	    break;
	} else if (c == '\n' && s[1] != ' ' && s[1] != '\t') {
	    break;
	}
	++s;
    }
    if (s == in)
	return false;
    in = s;
    return true;
}

const tstring RFC822Addr::address(uint u, bool n, bool b) const {
    uchar c;
    uint pos = 0;
    tstring s;

    if (locals.empty())
	return s;
    if (n && *phrases[u]) {
	s += '"';
	s += phrases[u];
	s += T("\" ");
    }
    if (n || b)
	s += '<';
    if (*routes[u]) { // TFR
	s += routes[u];
	s += ':';
    }
    while ((c = locals[u][pos]) != '\0') {
	if (c == '.') {
	    if (pos == 0 || !locals[u][pos + 1] || locals[u][pos + 1] == '.')
		break;
	} else if (!IS_ATEXT(c)) {
	    break;
	}
	++pos;
    }
    if (locals[u][pos]) {
	s += '"';
	for (pos = 0; (c = locals[u][pos]) != '\0'; ++pos) {
	    if (c == '"' || c == '\\') {
		s += '\\';
	    }
	    s += c;
	}
	s += '"';
    } else {
	s += locals[u];
    }

    if (*domains[u]) {
	s += '@';
	s += domains[u];
    }
    if (n || b)
	s += '>';
    return s;
}

static const uint maxlen = 45;

#define	DEC(c) (((c) - ' ') & 077)
#define ENC(c) (table[(c) & 077])

static inline void encode(const void *input, size_t len, void *output, size_t
    &outsz, const uchar *table, bool base64) {
    const char *in = (const char *)input;
    size_t n = 0;
    char *out = (char *)output;

    while (len) {
	n = len < maxlen ? len : maxlen;
	if (!base64) {
	    *out++ = ENC(n);
	    outsz++;
	}
	len -= n;
	while (n >= 3) {
	    out[0] = ENC(in[0] >> 2);
	    out[1] = ENC(((in[0] << 4) & 060) | ((in[1] >> 4) & 017));
	    out[2] = ENC(((in[1] << 2) & 074) | ((in[2] >> 6) & 03));
	    out[3] = ENC(in[2]);
	    out += 4;
	    outsz += 4;
	    in += 3;
	    n -= 3;
	}
	if (!n) {
	    *out++ = '\r';
	    *out++ = '\n';
	    outsz += 2;
	}
    }
    if (n) {
	char c1 = in[0];
	char c2 = n == 1 ? '\0' : in[1];

	out[0] = ENC(c1 >> 2);
	out[1] = ENC(((c1 << 4) & 060) | ((c2 >> 4) & 017));
	if (n == 1)
	    out[2] = base64 ? '=' : ENC('\0');
	else
	    out[2] = ENC((c2 << 2) & 074);
	out[3] = base64 ? '=' : ENC('\0');
	out[4] = '\r';
	out[5] = '\n';
	outsz += 5;
	out += 5;
    }
    *out = '\0';
}

bool base64encode(const void *input, size_t len, char *&out, size_t &outsz) {
    static const uchar table[64] = {
      'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
      'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
      'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
      'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
      'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
      'w', 'x', 'y', 'z', '0', '1', '2', '3',
      '4', '5', '6', '7', '8', '9', '+', '/'
    };

    outsz = 0;
    if ((out = new char[(len + 2) * 4 / 3 + (len / maxlen * 2) + 8]) == NULL)
	return false;
    encode(input, len, out, outsz, table, true);
    return true;
}

bool uuencode(const tchar *file, const void *input, size_t len, char *&out,
    size_t &outsz) {
    static const char begin[] = "begin 644 ";
    static const char end[] = "\r\nend\r\n";
    static const uchar table[64] = {
      '`', '!', '"', '#', '$', '%', '&', '\'',
      '(', ')', '*', '+', ',', '-', '.', '/',
      '0', '1', '2', '3', '4', '5', '6', '7',
      '8', '9', ':', ';', '<', '=', '>', '?',
      '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G',
      'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',
      'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W',
      'X', 'Y', 'Z', '[', '\\', ']', '^', '_'
    };

    outsz = (size_t)tstrlen(file);
    if ((out = new char[len * 4 / 3 + (len / maxlen * 2) + outsz + 32]) == NULL)
	return false;
    memcpy(out, begin, sizeof (begin) - 1);
    memcpy(out + sizeof (begin) - 1, tchartoachar(file), outsz);
    outsz += sizeof (begin) - 1;
    out[outsz++] = '\r';
    out[outsz++] = '\n';
    encode(input, len, out + outsz, outsz, table, false);
    out[outsz++] = ENC('\0');
    memcpy(out + outsz, end, sizeof (end));
    outsz += sizeof (end) - 1;
    return true;
}

bool uudecode(const char *input, size_t sz, uint &perm, tstring &file,
    void *&output, size_t &outsz) {
    const char *in = (const char *)input;
    char *out;
    const char *p = in;

    outsz = 0;
    while (isspace(*p))
	p++;
    if (strnicmp(p, "begin ", 6) != 0)
	return false;
    p += 5;
    while (isspace(*p))
	p++;
    perm = (uint)strtoul(p, &out, 8);
    if (!isspace(*out))
	return false;
    while (!isspace(*p))
	p++;
    while (isspace(*p))
	p++;
    file.erase();
    while (*p != '\r' && *p != '\n'&& !isspace(*p))
	file.append(1, *p++);
    sz -= (size_t)(p - in);
    if ((output = out = new char[sz * 3 / 4 + 8]) == NULL)
	return false;
    while (sz) {
	if (isspace(*p)) {
	    p++;
	    sz--;
	    continue;
	}
	int n = DEC(*p++);

	if (n <= 0)
	    break;
	for (; n > 0; p += 4, n -= 3) {
	    if (n >= 3) {
		if (sz < 4) {
		    delete [] (char *)output;
		    return false;
		}
		out[0] = DEC(p[0]) << 2 | DEC(p[1]) >> 4;
		out[1] = DEC(p[1]) << 4 | DEC(p[2]) >> 2;
		out[2] = DEC(p[2]) << 6 | DEC(p[3]);
		out += 3;
		outsz += 3;
		sz -= 4;
	    } else {
		if (sz < 2) {
		    delete [] (char *)output;
		    return false;
		}
		out[0] = DEC(p[0]) << 2 | DEC(p[1]) >> 4;
		if (n >= 2) {
		    if (sz < 3) {
			delete [] (char *)output;
			return false;
		    }
		    out[1] = DEC(p[1]) << 4 | DEC(p[2]) >> 2;
		    outsz += 2;
		    sz -= 3;
		} else {
		    outsz++;
		    sz -= 2;
		}
	    }
	}
    }
    out[0] = '\0';
    while (isspace(*p))
	p++;
    if (memcmp(p, "end", 3) != 0) {
	delete [] (char *)output;
	return false;
    }
    return true;
}

bool base64decode(const void *input, size_t sz, char *&output, size_t &outsz) {
    const char *in = (const char *)input;
    char *out;
    int out_byte = 0, out_bits = 0;
    static const uchar table[256] = {
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*000-007*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*010-017*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*020-027*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*030-037*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*040-047*/
	'\177', '\177', '\177', '\76',  '\177', '\177', '\177', '\77',  /*050-057*/
	'\64',  '\65',  '\66',  '\67',  '\70',  '\71',  '\72',  '\73',  /*060-067*/
	'\74',  '\75',  '\177', '\177', '\177', '\100', '\177', '\177', /*070-077*/
	'\177', '\0',   '\1',   '\2',   '\3',   '\4',   '\5',   '\6',   /*100-107*/
	'\7',   '\10',  '\11',  '\12',  '\13',  '\14',  '\15',  '\16',  /*110-117*/
	'\17',  '\20',  '\21',  '\22',  '\23',  '\24',  '\25',  '\26',  /*120-127*/
	'\27',  '\30',  '\31',  '\177', '\177', '\177', '\177', '\177', /*130-137*/
	'\177', '\32',  '\33',  '\34',  '\35',  '\36',  '\37',  '\40',  /*140-147*/
	'\41',  '\42',  '\43',  '\44',  '\45',  '\46',  '\47',  '\50',  /*150-157*/
	'\51',  '\52',  '\53',  '\54',  '\55',  '\56',  '\57',  '\60',  /*160-167*/
	'\61',  '\62',  '\63',  '\177', '\177', '\177', '\177', '\177', /*170-177*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*200-207*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*210-217*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*220-227*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*230-237*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*240-247*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*250-257*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*260-267*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*270-277*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*300-307*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*310-317*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*320-327*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*330-337*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*340-347*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*350-357*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*360-367*/
	'\177', '\177', '\177', '\177', '\177', '\177', '\177', '\177', /*370-377*/
    };

    outsz = 0;
    if ((output = out = new char[sz * 3 / 4 + 8]) == NULL)
	return false;
    while (sz) {
	int add_bits = table[(int)*in++];

	sz--;
	if (add_bits >= 64) {
	    if (in[0] == '=' && in[1] == '=' && in[2] == '=')
		break;
	    else
		continue;
	}
	out_byte = (out_byte << 6) + add_bits;
	out_bits += 6;
	if (out_bits == 24) {
	    out[0] = (char)((out_byte & 0xFF0000) >> 16);
	    out[1] = (char)((out_byte & 0x00FF00) >> 8);
	    out[2] = (char)(out_byte & 0x0000FF);
	    out_bits = 0;
	    out_byte = 0;
	    out += 3;
	    outsz += 3;
	}
    }
    while (out_bits >= 8) {
	if (out_bits == 8) {
	    *out++ = (char)out_byte;
	    out_byte = 0;
	} else {
	    int mask = 0xFF << (out_bits - 8);

	    *out++ = (char)((out_byte & mask) >> (out_bits - 8));
	    out_byte &= ~mask;
	}
	outsz++;
	out_bits -= 8;
    }
    out[0] = '\0';
    return true;
}

static void parse_rfc822space(const tchar *&s) {
    uint cmt = 0;
    const tchar *p = s;

    if (!p)
	return;
    while (*p && (isspace(*p) || *p == '(')) {
	if (*p == '\n') {
	    p++;
	    if (*p != ' ' && *p != '\t') {
		s = NULL;
		return;
	    }
	} else if (*p == '(') {
	    p++;
	    cmt++;
	    while (cmt) {
		switch (*p) {
		case '\n':
		    p++;
		    if (*p == ' ' || *p == '\t')
			break;
		    /* no break */
		case '\0':
		    s = NULL;
		    return;
		case '\\':
		    p++;
		    break;
		case '(':
		    cmt++;
		    break;
		case ')':
		    cmt--;
		    break;
		}
		p++;
	    }
	} else {
	    p++;
	}
    }
    s = *p ? p : NULL;
}

static int tmcomp(const tm *const atmp, const tm *const btmp) {
    int result;

    if ((result = (atmp->tm_year - btmp->tm_year)) == 0 &&
	(result = (atmp->tm_mon - btmp->tm_mon)) == 0 &&
	(result = (atmp->tm_mday - btmp->tm_mday)) == 0 &&
	(result = (atmp->tm_hour - btmp->tm_hour)) == 0 &&
	(result = (atmp->tm_min - btmp->tm_min)) == 0)
	result = atmp->tm_sec - btmp->tm_sec;
    return result;
}

time_t mkgmtime(const tm *const tmp) {
    int bits;
    int seconds;
    time_t t;
    tm orgtm, tmbuf;
    
    orgtm = *tmp;
    seconds = orgtm.tm_sec;
    orgtm.tm_sec = 0;
    /*
     * Calculate the number of magnitude bits in a time_t
     * If time_t is signed, then 0 is the median value,
     * if time_t is unsigned, then 1 << bits is median.
     */
    for (bits = 0, t = 1; t > 0; ++bits, t <<= 1)
	;
    t = (t < 0) ? 0 : ((time_t) 1 << bits);
    while (true) {
	int dir;
	tm *newtm = gmtime_r(&t, &tmbuf);

	if (newtm == NULL)
	    return 0;
	dir = tmcomp(newtm, &orgtm);
	if (dir != 0) {
	    if (bits-- < 0)
		return -1;
	    if (bits < 0)
		--t;
	    else if (dir > 0)
		t -= (time_t)1 << bits;
	    else
		t += (time_t)1 << bits;
	    continue;
	}
	break;
    }
    t += seconds;
    return t;
}

time_t parse_date(const tchar *hdr, int adjhr, int adjmin) {
    int hour = 0, min = 0;
    tchar month[4];
    tchar *p;
    bool rfcerr = false;
    tm tm;
    time_t t;
    static const tchar *monthname[] = {
	T("jan"), T("feb"), T("mar"), T("apr"), T("may"), T("jun"), T("jul"),
	T("aug"), T("sep"), T("oct"), T("nov"), T("dec")
    };

    ZERO(tm);
    parse_rfc822space(hdr);
    if (!hdr)
	return 0;
    if (istalpha(*hdr)) {
	// skip day name
	hdr++;
	if (!istalpha(*hdr))
	    return 0;
	hdr++;
	if (!istalpha(*hdr))
	    return 0;
	hdr++;
	parse_rfc822space(hdr);
	if (!hdr)
	    return 0;
	if (*hdr == ',')
	    hdr++;
	parse_rfc822space(hdr);
	if (!hdr)
	    return 0;
    }
    if (istdigit(*hdr)) {
	tm.tm_mday = *hdr++ - '0';
	if (istdigit(*hdr))
	    tm.tm_mday = tm.tm_mday * 10 + *hdr++ - '0';
    } else {
	rfcerr = true;
    }
    // parse month
    parse_rfc822space(hdr);
    if (!hdr)
	return 0;
    month[0] = *hdr++;
    if (!istalpha(month[0]))
	return 0;
    month[1] = *hdr++;
    if (!istalpha(month[1]))
	return 0;
    month[2] = *hdr++;
    if (!istalpha(month[2]))
	return 0;
    month[3] = '\0';
    for (p = month; *p; p++)
    	*p = (char)tolower(*p);
    for (tm.tm_mon = 0; tm.tm_mon < 12; tm.tm_mon++) {
	if (!tstrcmp(month, monthname[tm.tm_mon]))
	    break;
    }
    if (tm.tm_mon == 12)
	return 0;
    if (rfcerr) {
	parse_rfc822space(hdr);
	if (!hdr || !istdigit(*hdr))
	    return 0;
	tm.tm_mday = *hdr++ - '0';
	if (istdigit(*hdr))
	    tm.tm_mday = tm.tm_mday * 10 + *hdr++ - '0';
	parse_rfc822space(hdr);
	if (!hdr)
	    return 0;
	if (*hdr == ',')
	    hdr++;
    }
    // parse year
    parse_rfc822space(hdr);
    if (!hdr || !istdigit(*hdr))
	return 0;
    tm.tm_year = *hdr++ - '0';
    if (!istdigit(*hdr))
	return 0;
    tm.tm_year = tm.tm_year * 10 + *hdr++ - '0';
    if (istdigit(*hdr)) {
	if (tm.tm_year < 19)
	    return 0;
	tm.tm_year -= 19;
	tm.tm_year = tm.tm_year * 10 + *hdr++ - '0';
	if (!istdigit(*hdr))
	    return 0;
	tm.tm_year = tm.tm_year * 10 + *hdr++ - '0';
    } else if (tm.tm_year < 70) {
	tm.tm_year += 100;
    }
    tm.tm_isdst = -1;
    tm.tm_hour = 12;
    /* Parse time if available */
    parse_rfc822space(hdr);
    if (!hdr)
	goto gmt;
    if (!istdigit(*hdr))
	goto gmt;
    tm.tm_hour = *hdr++ - '0';
    if (istdigit(*hdr))
	tm.tm_hour = tm.tm_hour * 10 + *hdr++ - '0';
    hdr++;
    if (!istdigit(*hdr))
	goto gmt;
    tm.tm_min = *hdr++ - '0';
    if (istdigit(*hdr))
	tm.tm_min = tm.tm_min * 10 + *hdr++ - '0';
    hdr++;
    if (isdigit(*hdr)) {
	tm.tm_sec = *hdr++ - '0';
	if (isdigit(*hdr))
	    tm.tm_sec = tm.tm_sec * 10 + *hdr++ - '0';
    } else {
	parse_rfc822space(hdr);
	if (hdr && toupper(hdr[1]) == 'M') {
	    if (toupper(*hdr) == 'P' && tm.tm_hour < 12)
		tm.tm_hour += 12;
	    hdr += 2;
	}
    }
    parse_rfc822space(hdr);
    // parse GMT offset
    if (!hdr) {
	goto gmt;
    } else if (istdigit(*hdr) || *hdr == '-' || *hdr == '+') {
	bool neg = *hdr == '-';

	if (!istdigit(*hdr))
	    hdr++;
	if (!istdigit(hdr[0]) || !istdigit(hdr[1]) || !istdigit(hdr[2]))
	    goto gmt;
	hour = *hdr++ - '0';
	if (istdigit(hdr[2]))
	    hour = hour * 10 + *hdr++ - '0';
	min = (*hdr++ - '0') * 10;
	min += *hdr++ - '0';
	if (neg) {
	    hour *= -1;
	    min *= -1;
	}
    } else if (istalpha(*hdr) && (istspace(hdr[1]) || hdr[1] == '\0')) {
	char zone = (char)toupper(*hdr);

	/* military time */
	if (zone < 'J')
	    hour = zone - 'A' + 1;
	else if (zone < 'N')
	    hour = zone - 'A';
	else if (zone < 'Z')
	    hour = (zone - 'M') * -1;
    } else if (!tstrnicmp(hdr, T("EDT"), 3)) {
	hour = -4;
    } else if (!tstrnicmp(hdr, T("EST"), 3) || !tstrnicmp(hdr, T("CDT"), 3)) {
	hour = -5;
    } else if (!tstrnicmp(hdr, T("CST"), 3) || !tstrnicmp(hdr, T("MDT"), 3)) {
	hour = -6;
    } else if (!tstrnicmp(hdr, T("MST"), 3) || !tstrnicmp(hdr, T("PDT"), 3)) {
	hour = -7;
    } else if (!tstrnicmp(hdr, T("PST"), 3)) {
	hour = -8;
    }
    tm.tm_min = tm.tm_min - min + adjmin;
    tm.tm_hour = tm.tm_hour - hour + adjhr;
    if ((t = mktime(&tm)) != (time_t)-1)
	t = mkgmtime(&tm);
    return t == (time_t)-1 ? 0 : t;

gmt:
    t = mktime(&tm);
    return t == (time_t)-1 ? 0 : t;
}
