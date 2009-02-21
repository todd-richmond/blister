#ifndef SMTPClient_h
#define SMTPClient_h

#include <fstream>
#include <time.h>
#include "Socket.h"

class SMTPClient: nocopy {
public:
    SMTPClient();
    virtual ~SMTPClient() {};
    
    const string &extensions(void) const { return exts; }
    int code(void) const { return atoi(sts.c_str()); }
    const char *message(void) const { return sts.length() > 4 ? sts.c_str() + 4 : ""; }
    const string &message_multi(void) const { return multi; }
    const string &result(void) const { return sts; }

    bool connect(const Sockaddr &addr, ulong timeout = SOCK_INFINITE);
    bool connect(const tchar *hostport, ulong timeout = SOCK_INFINITE)
	{ return connect(Sockaddr(hostport), timeout); }
    bool close(void) { return sock.close(); }
    bool cmd(const char *s1, const char *s2 = NULL, int retcode = 250);
    bool ehlo(const char *domain = NULL);
    bool helo(const char *domain = NULL);
    bool lhlo(const char *domain = NULL);
    bool auth(const char *id, const char *passwd);
    bool from(const char *id);
    bool rcpt(const char *id);
    bool bcc(const char *id) { return add(bccv, id); }
    bool cc(const char *id) { return add(ccv, id); }
    bool to(const char *id) { return add(tov, id); }
    void attribute(const char *attr, const char *val);
    void header(const char *hdr) { hdrv.push_back(hdr); }
    void subject(const char *s) { sub = s; }
    bool data(bool mime = false, const char *txt = NULL);
    bool data(const void *p, uint sz, bool dotstuff = true);
    bool data(const string &s) { return data(s.c_str(), s.size()); }
    bool data(const void *p, uint sz, const char *type, const char *desc = NULL,
	const char *encoding = NULL, const char *disp = NULL,
	const char *name = NULL);
    bool enddata(void);
    bool quit(void);
    bool rset(void) { return cmd("RSET"); }
    void timeout(ulong rto, ulong wto = SOCK_INFINITE) {
	sock.rtimeout(rto);
	sock.wtimeout(wto);
    }
    void use_fstream(fstream *fs = NULL) {
	fstrm = fs;
	strm = fs ? (iostream *)fs : &sstrm;
    }
    bool vrfy(const char *id);
    static const tchar *section(void) { return T("smtp"); }

protected:
    string exts, multi, sts;
    fstream *fstrm;
    Socket sock;
    sockstream sstrm;
    iostream *strm;
    static string crlf;

private:    
    string boundary;
    string frm, sub;
    bool datasent, lmtp, mime;
    uint parts;
    vector<string> tov, ccv, bccv, hdrv;

    bool add(vector<string> &v, const char *id);
    void recip(const char *hdr, const vector<string> &v);
    bool stuff(const void *p, uint sz);    
};

class RFC821Addr: nocopy {
public:
    RFC821Addr(const char *addr = NULL) { if (addr) parse(addr); }
    RFC821Addr(const char *&addr, string &reterr) {
	parseaddr(addr);
	reterr = err;
    }

    const string &address(void) const { return addr; }
    const string &domain(void) const { return domain_buf; }
    const string &error(void) const { return err; }
    const string &local(void) const { return local_part; }

    bool parse(const char *addr) { parseaddr(addr); return err.empty(); }
    void setDomain(const char *domain);

private:
    string addr, domain_buf, local_part;
    string err;

    void parseaddr(const char *&addr);
    void parsedomain(string::size_type &pos);
    void make_address(void);
};

class RFC822Addr: nocopy {
public:
    RFC822Addr(const char *addrs = NULL): buf(NULL) { if (addrs) parse(addrs); }
    ~RFC822Addr() { delete [] buf; }

    vector<const char *> domain, mbox, name, route;

    const string address(uint u = 0, bool name = false, bool brkt = true) const;
    uint size(void) const { return mbox.size(); }

    uint parse(const char *addrs);

private:
    char *buf;

    void parse_append(const char *name, const char *route, const char *mailbox,
	const char *domain);
    int parse_domain(char *&in, char *&domain, char *&commment);
    int parse_phrase(char *&in, char *&phrase, const char *specials);
    int parse_route(char *&in, char *&route);
};

bool base64encode(const char *data, uint len, char *&out, uint &outsz);
bool base64decode(const char *data, uint sz, char *&out, uint &outsz);
bool uuencode(const char *file, const char *data, uint len, char *&out,
    uint &outsz);
bool uudecode(const char *data, uint sz, uint &perm, string &file,
    char *&out, uint &outsz);

time_t mkgmtime(struct tm *const tmp);
time_t parse_date(const char *hdr, int adjhr = 0, int adjmin = 0);
void rfc822whitespace(char *&s);

#endif // SMTPClient_h
