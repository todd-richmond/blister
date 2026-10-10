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

#ifndef SMTPClient_h
#define SMTPClient_h

#include <time.h>
#include <fstream>
#include <memory_resource>
#include "Socket.h"

class BLISTER RFC821Addr: nocopy {
public:
    explicit RFC821Addr(const tchar *address = nullptr, bool smtputf8 = false) {
	if (address)
	    parse(address, smtputf8);
    }
    RFC821Addr(const tchar *&address, tstring &reterr, bool smtputf8 = false) {
	parseaddr(address, smtputf8);
	reterr = err;
    }

    const tstring &address(void) const { return addr; }
    const tstring &domain(void) const { return domain_buf; }
    const tstring &error(void) const { return err; }
    const tstring &local(void) const { return local_part; }
    bool smtputf8(void) const { return utf8; }

    bool parse(const tchar *address, bool smtputf8 = false) {
	parseaddr(address, smtputf8);
	return err.empty();
    }
    void setDomain(const tchar *domain);
    void setLocal(const tchar *local);

private:
    tstring addr, domain_buf, local_part;
    tstring err;
    bool utf8 = false;

    void parseaddr(const tchar *&addr, bool smtputf8);
    bool scan(const tchar *&addr, bool smtputf8);
    bool split(void);
    bool parsedomain(size_t &pos);
    void make_address(void);
};

class BLISTER RFC822Addr: nocopy {
public:
    explicit RFC822Addr(const tchar *addrs = nullptr, bool smtputf8 = false) {
	if (addrs)
	    parse(addrs, smtputf8);
    }
    explicit RFC822Addr(const tstring &addrs, bool smtputf8 = false) {
	parse(addrs.c_str(), smtputf8);
    }

    tstring address(uint u = 0, bool name = false, bool brkt = true) const;
    tstring domain(uint u = 0) const { return tstring(at(u).domain); }
    tstring local(uint u = 0) const { return tstring(at(u).local); }
    tstring phrase(uint u = 0) const { return tstring(at(u).phrase); }
    tstring route(uint u = 0) const { return tstring(at(u).route); }
    size_t size(void) const { return entries.size(); }
    bool smtputf8(void) const { return utf8; }

    uint parse(const tchar *addrs, bool smtputf8 = false);

private:
    // views into buf
    struct Entry {
	tstring_view domain, local, phrase, route;
    };

    // the parsed copy of the input and the entries live in an inline arena
    // so typical addresses need no heap allocation
    alignas(Entry) std::byte space[280];
    std::pmr::monotonic_buffer_resource arena{space, sizeof (space)};
    std::pmr::vector<Entry> entries{&arena};
    bool utf8 = false;

    const Entry &at(uint u) const {
	static constexpr Entry none;

	return u < entries.size() ? entries[u] : none;
    }
    void parse_append(const tchar *name, const tchar *route, const tchar
	*mailbox, const tchar *domain);
    int parse_domain(tchar *&in, tchar *&domain, tchar *&comment,
	bool smtputf8);
    int parse_phrase(tchar *&in, tchar *&phrase, const tchar *specials,
	bool smtputf8, bool &hi);
    int parse_route(tchar *&in, tchar *&route, bool smtputf8);
    static bool skip_whitespace(tchar *&in);
};

class BLISTER SMTPClient: nocopy {
public:
    SMTPClient();
    virtual ~SMTPClient() = default;

    int code(void) const { return atoi<int>(sts.c_str()); }
    bool exts_find(const tchar *s) const { return exts.find(s) != exts.npos; }
    const tstring &extensions(void) const { return exts; }
    const tchar *message(void) const {
	return sts.length() > 4 ? sts.c_str() + 4 : T("");
    }
    const tstring &message_multi(void) const { return multi; }
    bool multi_find(const tchar *s) const { return multi.find(s) != multi.npos; }
    const tstring &result(void) const { return sts; }
    const vector<tstring> &results(void) const { return resultsv; }

    bool connect(const Sockaddr &addr, uint timeout = SOCK_INFINITE);
    bool connect(const tchar *hostport, uint timeout = SOCK_INFINITE) {
	return connect(Sockaddr(hostport), timeout);
    }
    bool close(void) { return sock.close(); }
    bool cmd(const tchar *s1, const tchar *s2 = nullptr, int retcode = 250);
    bool ehlo(const tchar *domain = nullptr);
    bool helo(const tchar *domain = nullptr);
    bool lhlo(const tchar *domain = nullptr);
    bool auth(const tchar *id, const tchar *passwd);
    bool xclient(const tchar *xclient_cmd);
    bool pipeline(void) {
	if (!exts_find(T("PIPELINING")))
	    return false;
	pipelined = true;
	return true;
    }
    bool from(const tchar *id, const tchar *parms = nullptr);
    bool from(const RFC822Addr &addrs, const tchar *parms = nullptr);
    bool rcpt(const tchar *id);
    bool rcpt(const RFC822Addr &addr);
    bool bcc(const tchar *id) { return add(bccv, id); }
    bool bcc(const RFC822Addr &addrs) { return add(bccv, addrs); }
    bool cc(const tchar *id) { return add(ccv, id); }
    bool cc(const RFC822Addr &addrs) { return add(ccv, addrs); }
    bool to(const tchar *id) { return add(tov, id); }
    bool to(const RFC822Addr &addrs) { return add(tov, addrs); }
    void attribute(const tchar *attr, const tchar *val);
    void header(const tchar *hdr) { hdrv.emplace_back(hdr); }
    void subject(const tchar *s) { sub = s; }
    bool data(bool mime = false, const tchar *txt = nullptr);
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
	const tchar *desc = nullptr, const tchar *encoding = nullptr,
	const tchar *disp = nullptr, const tchar *name = nullptr);
    bool bdat(const void *p, size_t sz, bool last = true);
    bool enddata(void);
    bool quit(void);
    bool rset(void) { pipelined = false; return cmd(T("RSET")); }
    void timeout(uint rto, uint wto = SOCK_INFINITE) {
	sock.rtimeout(rto);
	sock.wtimeout(wto);
    }
    void use_fstream(fstream *fs = nullptr) {
	fstrm = fs;
	strm = fs ? static_cast<iostream *>(fs) : &sstrm;
    }
    bool vrfy(const tchar *id, const tchar *parms = nullptr);
    bool vrfy(const RFC822Addr &addr, const tchar *parms = nullptr);
    static const tchar *section(void) { return T("smtp"); }

protected:
    tstring exts, multi, sts;
    Socket sock;
    sockstream sstrm;
    fstream *fstrm = nullptr;
    iostream *strm = &sstrm;
    bool ext_chunking = false, ext_smtputf8 = false;
    static const char crlf[];

private:
    bool add(vector<tstring> &v, const tchar *id);
    bool add(vector<tstring> &v, const RFC822Addr &addrs);
    void recip(const tchar *hdr, const vector<tstring> &v);
    bool downgrade(const tchar *cmd, tstring &id);
    bool canutf8(void) const { return ext_smtputf8 || fstrm; }
    bool envarg(const tchar *cmd, tstring &id, const tchar *parms, bool brkt,
	bool always, tstring &arg);
    string hdrtext(const tchar *s) const;
    tstring hdraddr(const RFC822Addr &addr, uint u, const tstring &orig,
	const tstring &sent) const;
    bool rcptcmd(tstring &id);
    bool startdata(void);
    bool stuff(const void *p, size_t sz);

    string boundary;
    tstring frm, sub;
    bool datasent, lmtp, mime;
    bool pipelined = false;
    vector<tstring> tov, ccv, bccv, hdrv, resultsv;
};

bool base64encode(const void *in, size_t len, char *&out, size_t &outsz);
bool base64decode(const char *in, size_t sz, void *&out, size_t &outsz);
bool qpencode(const void *in, size_t len, char *&out, size_t &outsz);
bool qpdecode(const char *in, size_t sz, void *&out, size_t &outsz);
bool uuencode(const tchar *file, const void *in, size_t len, char *&out,
    size_t &outsz);
bool uudecode(const char *in, size_t sz, uint &perm, tstring &file, void *&out,
    size_t &outsz);

#endif // SMTPClient_h
