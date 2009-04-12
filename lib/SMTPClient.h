/*
 * Copyright 2001 - 2009 Todd Richmond
 *
 * This file is part of Blister - a light weight, scalable, high performance
 * C++ server infrastructure.
 *
 * Blister is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or any later version.
 *
 * Blister is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Blister. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef SMTPClient_h
#define SMTPClient_h

#include <fstream>
#include <time.h>
#include "Socket.h"

class SMTPClient: nocopy {
public:
    SMTPClient();
    virtual ~SMTPClient() {};
    
    const tstring &extensions(void) const { return exts; }
    int code(void) const { return ttoi(sts.c_str()); }
    const tchar *message(void) const {
	return sts.length() > 4 ? sts.c_str() + 4 : T("");
    }
    const tstring &message_multi(void) const { return multi; }
    const tstring &result(void) const { return sts; }

    bool connect(const Sockaddr &addr, ulong timeout = SOCK_INFINITE);
    bool connect(const tchar *hostport, ulong timeout = SOCK_INFINITE) {
	return connect(Sockaddr(hostport), timeout);
    }
    bool close(void) { return sock.close(); }
    bool cmd(const tchar *s1, const tchar *s2 = NULL, int retcode = 250);
    bool ehlo(const tchar *domain = NULL);
    bool helo(const tchar *domain = NULL);
    bool lhlo(const tchar *domain = NULL);
    bool auth(const tchar *id, const tchar *passwd);
    bool from(const tchar *id);
    bool rcpt(const tchar *id);
    bool bcc(const tchar *id) { return add(bccv, id); }
    bool cc(const tchar *id) { return add(ccv, id); }
    bool to(const tchar *id) { return add(tov, id); }
    void attribute(const tchar *attr, const tchar *val);
    void header(const tchar *hdr) { hdrv.push_back(hdr); }
    void subject(const tchar *s) { sub = s; }
    bool data(bool mime = false, const tchar *txt = NULL);
    bool data(const void *p, size_t sz, bool dotstuff = true);
    bool data(const tstring &s) {
	return data(tstringtoa(s).c_str(), s.size());
    }
    bool data(const void *p, uint sz, const tchar *type,
	const tchar *desc = NULL, const tchar *encoding = NULL,
	const tchar *disp = NULL, const tchar *name = NULL);
    bool enddata(void);
    bool quit(void);
    bool rset(void) { return cmd(T("RSET")); }
    void timeout(ulong rto, ulong wto = SOCK_INFINITE) {
	sock.rtimeout(rto);
	sock.wtimeout(wto);
    }
    bool vrfy(const tchar *id);
    static const tchar *section(void) { return T("smtp"); }

protected:
    tstring exts, multi, sts;
    Socket sock;
    sockstream sstrm;
    static string crlf;

private:    
    string boundary;
    tstring frm, sub;
    bool datasent, lmtp, mime;
    uint parts;
    vector<tstring> tov, ccv, bccv, hdrv;

    bool add(vector<tstring> &v, const tchar *id);
    void recip(const tchar *hdr, const vector<tstring> &v);
    bool stuff(const void *p, size_t sz);    
};

class RFC821Addr: nocopy {
public:
    RFC821Addr(const tchar *addr = NULL) { if (addr) parse(addr); }
    RFC821Addr(const tchar *&addr, tstring &reterr) {
	parseaddr(addr);
	reterr = err;
    }

    const tstring &address(void) const { return addr; }
    const tstring &domain(void) const { return domain_buf; }
    const tstring &error(void) const { return err; }
    const tstring &local(void) const { return local_part; }

    bool parse(const tchar *addr) { parseaddr(addr); return err.empty(); }
    void setDomain(const tchar *domain);

private:
    tstring addr, domain_buf, local_part;
    tstring err;

    void parseaddr(const tchar *&addr);
    void parsedomain(tstring::size_type &pos);
    void make_address(void);
};

class RFC822Addr: nocopy {
public:
    RFC822Addr(const tchar *addrs = NULL): buf(NULL) { if (addrs) parse(addrs); }
    ~RFC822Addr() { delete [] buf; }

    vector<const tchar *> domain, mbox, name, route;

    const tstring address(uint u = 0, bool name = false, bool brkt = true) const;
    size_t size(void) const { return mbox.size(); }

    uint parse(const tchar *addrs);

private:
    tchar *buf;

    void parse_append(const tchar *name, const tchar *route,
	const tchar *mailbox, const tchar *domain);
    int parse_domain(tchar *&in, tchar *&domain, tchar *&commment);
    int parse_phrase(tchar *&in, tchar *&phrase, const tchar *specials);
    int parse_route(tchar *&in, tchar *&route);
};

bool base64encode(const void *in, size_t len, void *&out, size_t &outsz);
bool base64decode(const void *in, size_t sz, void *&out, size_t &outsz);
bool uuencode(const tchar *file, const void *in, size_t len, void *&out,
    size_t &outsz);
bool uudecode(const void *in, size_t sz, uint &perm, tstring &file,
    void *&out, size_t &outsz);

time_t mkgmtime(struct tm *const tmp);
time_t parse_date(const tchar *hdr, int adjhr = 0, int adjmin = 0);
void rfc822whitespace(tchar *&s);

#endif // SMTPClient_h
