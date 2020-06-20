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

#ifndef SMTPClient_h
#define SMTPClient_h

#include <time.h>
#include "Socket.h"

class BLISTER RFC821Addr: nocopy {
public:
    explicit RFC821Addr(const tchar *address = NULL) {
	if (address)
	    parse(address);
    }
    RFC821Addr(const tchar *&address, tstring &reterr) {
	parseaddr(address);
	reterr = err;
    }

    const tstring &address(void) const { return addr; }
    const tstring &domain(void) const { return domain_buf; }
    const tstring &error(void) const { return err; }
    const tstring &local(void) const { return local_part; }

    bool parse(const tchar *address) { parseaddr(address); return err.empty(); }
    void setDomain(const tchar *domain);
    void setLocal(const tchar *local);

private:
    tstring addr, domain_buf, local_part;
    tstring err;

    void parseaddr(const tchar *&addr);
    void parsedomain(tstring::size_type &pos);
    void make_address(void);
};

class BLISTER RFC822Addr: nocopy {
public:
    explicit RFC822Addr(const tchar *addrs = NULL): buf(NULL) {
	if (addrs)
	    parse(addrs);
    }
    explicit RFC822Addr(const tstring &addrs): buf(NULL) { parse(addrs.c_str()); }
    ~RFC822Addr() { delete [] buf; }

    const tstring address(uint u = 0, bool name = false, bool brkt = true) const;
    const tstring domain(uint u = 0) const {
	return domains.empty() ? T("") : domains[u];
    }
    const tstring local(uint u = 0) const {
	return locals.empty() ? T("") : locals[u];
    }
    const tstring phrase(uint u = 0) const {
	return phrases.empty() ? T("") : phrases[u];
    }
    const tstring route(uint u = 0) const {
	return routes.empty() ? T("") : routes[u];
    }
    size_t size(void) const { return locals.size(); }

    uint parse(const tchar *addrs);

private:
    tchar *buf;
    vector<const tchar *> domains, locals, phrases, routes;

    void parse_append(const tchar *name, const tchar *route,
	const tchar *mailbox, const tchar *domain);
    int parse_domain(tchar *&in, tchar *&domain, tchar *&commment);
    int parse_phrase(tchar *&in, tchar *&phrase, const tchar *specials);
    int parse_route(tchar *&in, tchar *&route);
    static bool skip_whitespace(tchar *&in);
};

class BLISTER SMTPClient: nocopy {
public:
    SMTPClient();
    virtual ~SMTPClient() {}

    const tstring &extensions(void) const { return exts; }
    int code(void) const { return ttoi(sts.c_str()); }
    const tchar *message(void) const {
	return sts.length() > 4 ? sts.c_str() + 4 : T("");
    }
    const tstring &message_multi(void) const { return multi; }
    const tstring &result(void) const { return sts; }

    bool connect(const Sockaddr &addr, uint timeout = SOCK_INFINITE);
    bool connect(const tchar *hostport, uint timeout = SOCK_INFINITE) {
	return connect(Sockaddr(hostport), timeout);
    }
    bool close(void) { return sock.close(); }
    bool cmd(const tchar *s1, const tchar *s2 = NULL, int retcode = 250);
    bool ehlo(const tchar *domain = NULL);
    bool helo(const tchar *domain = NULL);
    bool lhlo(const tchar *domain = NULL);
    bool auth(const tchar *id, const tchar *passwd);
    bool xclient(const tchar *xclient_cmd);
    bool from(const tchar *id);
    bool from(const RFC822Addr &addrs);
    bool rcpt(const tchar *id);
    bool bcc(const tchar *id) { return add(bccv, id); }
    bool bcc(const RFC822Addr &addrs) { return add(bccv, addrs); }
    bool cc(const tchar *id) { return add(ccv, id); }
    bool cc(const RFC822Addr &addrs) { return add(ccv, addrs); }
    bool to(const tchar *id) { return add(tov, id); }
    bool to(const RFC822Addr &addrs) { return add(tov, addrs); }
    void attribute(const tchar *attr, const tchar *val);
    void header(const tchar *hdr) { hdrv.emplace_back(hdr); }
    void subject(const tchar *s) { sub = s; }
    bool data(bool mime = false, const tchar *txt = NULL);
    bool data(const void *p, size_t sz, bool dotstuff = true);
    bool data(const tstring &s) {
#ifdef UNICODE
	string as(tstringtoastring(s));

	return data(as.c_str(), as.size());
#else
	return data(s.c_str(), s.size());
#endif
    }
    bool data(const void *p, uint sz, const tchar *type,
	const tchar *desc = NULL, const tchar *encoding = NULL,
	const tchar *disp = NULL, const tchar *name = NULL);
    bool enddata(void);
    bool quit(void);
    bool rset(void) { return cmd(T("RSET")); }
    void timeout(uint rto, uint wto = SOCK_INFINITE) {
	sock.rtimeout(rto);
	sock.wtimeout(wto);
    }
    bool vrfy(const tchar *id);
    static const tchar *section(void) { return T("smtp"); }

protected:
    tstring exts, multi, sts;
    Socket sock;
    sockstream sstrm;
    static const char crlf[];

private:
    bool add(vector<tstring> &v, const tchar *id);
    bool add(vector<tstring> &v, const RFC822Addr &addrs);
    void recip(const tchar *hdr, const vector<tstring> &v);
    bool stuff(const void *p, size_t sz);

    string boundary;
    tstring frm, sub;
    bool datasent, lmtp, mime;
    uint parts;
    vector<tstring> tov, ccv, bccv, hdrv;
};

bool base64encode(const void *in, size_t len, char *&out, size_t &outsz);
bool base64decode(const char *in, size_t sz, void *&out, size_t &outsz);
bool uuencode(const tchar *file, const void *in, size_t len, char *&out,
    size_t &outsz);
bool uudecode(const char *in, size_t sz, uint &perm, tstring &file, void
    *&out, size_t &outsz);

time_t mkgmtime(const struct tm *tmp);
time_t parse_date(const tchar *hdr, int adjhr = 0, int adjmin = 0);

#endif // SMTPClient_h
