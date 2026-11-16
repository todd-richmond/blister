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
#include "Dispatch.h"

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
    tstring addr, domain_buf, err, local_part;
    bool utf8 = false;

    bool fail(const tchar *msg) {
	err = msg;
	return false;
    }
    void make_address(void);
    void parseaddr(const tchar *&addr, bool smtputf8);
    bool parsedomain(size_t &pos);
    bool scan(const tchar *&addr, bool smtputf8);
    bool split(void);
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
    // UTF-8 was replaced by '=' so the addresses are not what was parsed
    bool masked(void) const { return mask; }
    tstring phrase(uint u = 0) const { return tstring(at(u).phrase); }
    tstring route(uint u = 0) const { return tstring(at(u).route); }
    size_t size(void) const { return entries.size(); }
    bool smtputf8(void) const { return utf8; }

    // without smtputf8 any UTF-8 in a mailbox or domain is replaced by '='
    uint parse(const tchar *addrs, bool smtputf8 = false);

private:
    // views into buf
    struct Entry {
	tstring_view domain, local, phrase, route;
    };

    // inline arena so typical addresses need no heap allocation
    alignas(Entry) std::byte space[280];
    std::pmr::monotonic_buffer_resource arena{space, sizeof (space)};
    std::pmr::vector<Entry> entries{&arena};
    bool mask = false, utf8 = false;

    const Entry &at(uint u) const {
	static constexpr Entry none;

	return u < entries.size() ? entries[u] : none;
    }
    int parse_domain(tchar *&in, tchar *&domain, tchar *&comment,
	bool smtputf8);
    int parse_phrase(tchar *&in, tchar *&phrase, const tchar *specials,
	bool smtputf8, bool &hi) const;
    int parse_route(tchar *&in, tchar *&route, bool smtputf8);
    static bool skip_whitespace(tchar *&in);
};

class BLISTER SMTPClient: nocopy {
public:
    virtual ~SMTPClient() = default;

    int code(void) const { return atoi<int>(sts.c_str()); }
    bool exts_find(const tchar *s) const {
	return ifind(exts, s) != tstring_view::npos;
    }
    const tstring &extensions(void) const { return exts; }
    // the server's SIZE limit or 0 if it has none
    size_t maxsize(void) const { return maxsz; }
    const tchar *message(void) const {
	return sts.length() > 4 ? sts.c_str() + 4 : T("");
    }
    const tstring &message_multi(void) const { return multi; }
    bool multi_find(const tchar *s) const { return multi.contains(s); }
    // recipients refused by RCPT or, for LMTP, at delivery with the reply
    const vector<pair<tstring, tstring>> &rejected(void) const {
	return rejectedv;
    }
    const tstring &result(void) const { return sts; }
    const vector<tstring> &results(void) const { return resultsv; }

    bool connect(const Sockaddr &addr, uint timeout = SOCK_INFINITE);
    bool connect(const tchar *hostport, uint timeout = SOCK_INFINITE) {
	return connect(Sockaddr(hostport), timeout);
    }
    bool close(void) { return sock.close(); }
    // literal commands are code controlled so skip the CR/LF check
    bool cmd(const strlit &s1, const tchar *s2 = nullptr, int retcode = 250) {
	return sendcmd(tstring_view(s1.data(), s1.size()), s2, retcode, false);
    }
    template<cstr_ptr P>
    bool cmd(P &&s1, const tchar *s2 = nullptr, int retcode = 250) {
	const tchar *p = std::forward<P>(s1);

	return sendcmd(p ? tstring_view(p) : tstring_view(), s2, retcode, true);
    }
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
    // SMTPUTF8 is declared only for a UTF-8 sender or if it is in parms
    bool from(const tchar *id, const tchar *parms = nullptr);
    bool from(const RFC821Addr &addr, const tchar *parms = nullptr);
    // a message has a single sender so more than one address is refused
    bool from(const RFC822Addr &addrs, const tchar *parms = nullptr);
    // parms are RCPT parameters such as DSN NOTIFY= and ORCPT=
    bool rcpt(const tchar *id, const tchar *parms = nullptr);
    bool rcpt(const RFC821Addr &addr, const tchar *parms = nullptr) {
	return add(nullptr, addr, parms);
    }
    // every address in the list is sent
    bool rcpt(const RFC822Addr &addrs, const tchar *parms = nullptr) {
	return add(nullptr, addrs, parms);
    }
    bool bcc(const tchar *id, const tchar *parms = nullptr) {
	return add(&bccv, RFC822Addr(id, true), parms);
    }
    bool bcc(const RFC821Addr &addr, const tchar *parms = nullptr) {
	return add(&bccv, addr, parms);
    }
    bool bcc(const RFC822Addr &addrs, const tchar *parms = nullptr) {
	return add(&bccv, addrs, parms);
    }
    bool cc(const tchar *id, const tchar *parms = nullptr) {
	return add(&ccv, RFC822Addr(id, true), parms);
    }
    bool cc(const RFC821Addr &addr, const tchar *parms = nullptr) {
	return add(&ccv, addr, parms);
    }
    bool cc(const RFC822Addr &addrs, const tchar *parms = nullptr) {
	return add(&ccv, addrs, parms);
    }
    bool to(const tchar *id, const tchar *parms = nullptr) {
	return add(&tov, RFC822Addr(id, true), parms);
    }
    bool to(const RFC821Addr &addr, const tchar *parms = nullptr) {
	return add(&tov, addr, parms);
    }
    bool to(const RFC822Addr &addrs, const tchar *parms = nullptr) {
	return add(&tov, addrs, parms);
    }
    void attribute(const tchar *attr, const tchar *val);
    void header(const tchar *hdr) { hdrv.emplace_back(hdr); }
    void subject(const tchar *s) { sub = s; }
    bool data(bool mime = false, const tchar *txt = nullptr);
    bool data(const void *p, size_t sz, bool dotstuff = true);
    // complete RFC 5322 message: sent as is, only dot stuffed. The pointer is
    // an exact match so a string never converts to the bool mime parameter
    bool data(const tchar *msg) { return rawdata(msg ? msg : T("")); }
    bool data(const tstring &msg) { return rawdata(msg); }
    bool data(const void *p, uint sz, const tchar *type,
	const tchar *desc = nullptr, const tchar *encoding = nullptr,
	const tchar *disp = nullptr, const tchar *name = nullptr);
    bool bdat(const void *p, size_t sz, bool last = true);
    // use BDAT when supported: pipelines small messages, avoids large copies
    void chunking(bool enable) { usebdat = enable; }
    bool enddata(void);
    bool quit(void);
    bool rset(void) { pipelined = false; return cmd(T("RSET")); }
    // applies to the current and later connections
    void timeout(uint rto, uint wto = SOCK_INFINITE) {
	rtmo = rto;
	wtmo = wto;
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
    // after each connect before the greeting, such as to start TLS
    virtual bool onconnect(void) { return true; }

    tstring exts, multi, sts;
    Sockaddr peer;
    Socket sock;
    sockstream sstrm { sock };
    fstream *fstrm = nullptr;
    iostream *strm = &sstrm;
    bool ext_8bitmime = false, ext_chunking = false, ext_smtputf8 = false;
    static const char crlf[];

private:
    friend class AsyncSMTPClient;

    bool add(vector<tstring> *v, const RFC821Addr &addr, const tchar *parms);
    bool add(vector<tstring> *v, const RFC822Addr &addrs, const tchar *parms);
    bool bigchunk(const void *p, size_t sz, bool dotstuff);
    void buffer(bool on) {
	chunked = on;
	strm = on ? static_cast<iostream *>(&bstrm) : &sstrm;
    }
    bool can8bit(void) const { return ext_8bitmime || canutf8(); }
    // SMTPUTF8 was declared for the transaction or there is no server
    bool canutf8(void) const { return utf8decl || fstrm; }
    bool downgrade(const tchar *cmd, tstring &id, bool utf8);
    bool endreply(void);
    bool envarg(const tchar *cmd, tstring &id, const tchar *parms, bool brkt,
	bool always, tstring &arg);
    bool finish(tstring_view c);
    bool fits(size_t sz);
    tstring hdraddr(const RFC822Addr &addr, uint u, const tstring &orig,
	const tstring &sent) const;
    string hdrtext(const tchar *s) const;
    bool hello(tstring_view c, const tchar *domain);
    bool masked(const RFC822Addr &addr);
    bool rawdata(tstring_view msg);
    bool rcptcmd(tstring &id, const tchar *parms);
    void recip(const tchar *hdr, const vector<tstring> &v);
    bool replies(void);
    bool reply(void);
    bool sendchunk(bool last);
    bool sendcmd(tstring_view s1, const tchar *s2, int retcode, bool check);
    bool sendend(tstring_view c);
    bool startdata(void);
    bool stuff(const void *p, size_t sz, bool dotstuff = true);
    static size_t barelfs(const char *p, const char *end);
    static string base64line(string_view in);
    static void encodedwords(string &out, string_view text);
    static string encodewords(string_view text);
    static bool idna(string_view domain, string &out);
    static size_t ifind(tstring_view s, tstring_view needle);
    static tstring numstr(size_t n);
    static bool punycode(const vector<char32_t> &in, string &out);
    static tstring sasl64(const string &in);
#ifdef __AVX2__
    template<bool dots> static __m256i stuffhits(const char *p);
#elif defined(__aarch64__)
    template<bool dots> static uint8x16_t stuffhits(const char *p);
#endif
    template<bool dots> static const char *stuffscan(const char *p,
	const char *end, const char *start);
    static bool utf8decode(string_view s, vector<char32_t> &cp);

    struct Expect {
	tstring rcpt;
	int code;
	bool delivery;
    };
    vector<tstring> acceptedv;
    size_t bdatsz = 0;
    vector<tstring> bccv;
    string boundary;
    stringstream bstrm;
    vector<tstring> ccv;
    bool chunked = false;
    bool datasent = false;
    vector<Expect> expectv;
    tstring frm;
    vector<tstring> hdrv;
    bool lmtp = false;
    size_t maxsz = 0;
    bool mime = false;
    bool nowait = false;
    bool pipelined = false;
    size_t refused = 0;
    vector<pair<tstring, tstring>> rejectedv;
    vector<tstring> resultsv;
    uint rtmo = 3 * 60 * 1000;
    tstring sub;
    vector<tstring> tov;
    bool usebdat = true;
    bool utf8decl = false;
    uint wtmo = 5 * 60 * 1000;
};

/*
 * Waits for the slow replies to RCPT and the end of a message in a Dispatcher
 * instead of a thread; everything else is synchronous. The client must not be
 * used or destroyed until the callback runs
 */
class BLISTER AsyncSMTPClient: public SMTPClient {
public:
    using DispatchObjCB = DispatchObj::DispatchObjCB;

    explicit AsyncSMTPClient(Dispatcher &d): waiter(d, *this) {}

    // result of the last async call; result() and rejected() have the replies
    bool ok(void) const { return okay; }

    using SMTPClient::enddata;
    using SMTPClient::rcpt;
    // false on immediate failure, else cb runs on co when the replies arrive
    bool enddata(DispatchObjCB cb, DispatchObj &co);
    // a list of addresses sends several RCPTs so needs PIPELINING
    bool rcpt(const tchar *id, DispatchObjCB cb, DispatchObj &co,
	const tchar *parms = nullptr);

private:
    class Waiter: public DispatchIOSocket {
    public:
	Waiter(Dispatcher &d, AsyncSMTPClient &c): DispatchIOSocket(d, c.sock),
	    client(c) {}

	DSP_DECLARE(Waiter, onread) {
	    client.check(reason() == DispatchTimeout);
	}

    private:
	AsyncSMTPClient &client;
    };

    void check(bool timedout);
    bool wait(DispatchObjCB cb, DispatchObj &co, bool end);

    DispatchObj *caller = nullptr;
    DispatchObjCB done = nullptr;
    bool end = false, okay = false;
    Waiter waiter;
};

void base64encode(const void *in, size_t len, char *&out, size_t &outsz);
bool base64decode(const char *in, size_t sz, void *&out, size_t &outsz);
void qpencode(const void *in, size_t len, char *&out, size_t &outsz);
bool qpdecode(const char *in, size_t sz, void *&out, size_t &outsz);
void uuencode(const tchar *file, const void *in, size_t len, char *&out,
    size_t &outsz);
bool uudecode(const char *in, size_t sz, uint &perm, tstring &file, void *&out,
    size_t &outsz);
void xxencode(const tchar *file, const void *in, size_t len, char *&out,
    size_t &outsz);
bool xxdecode(const char *in, size_t sz, uint &perm, tstring &file, void *&out,
    size_t &outsz);

#endif // SMTPClient_h
