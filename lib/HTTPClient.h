#ifndef HTTPClient_h
#define HTTPClient_h

#include STL_HASH_MAP
#include "Socket.h"

class URL {
public:
    URL() { set(NULL); }
    URL(const tchar *url) { set(url); }
    URL(const URL &url) { operator =(url); }

    tstring host, path, prot, query;
    ushort port;

    const URL &operator =(const URL &url);
    const tstring fullpath(void) const;
    const tstring relpath(void) const
	{ return query.empty() ? path : path + T("?") + query; }
    bool set(const tchar *url);
    static void unescape(tchar *str, bool plus = true);
    static void unescape(tstring &str, bool plus = true);
};

class HTTPClient: nocopy {
public:
#ifdef STL_HASH_MAP_4ARGS
    typedef hash_multimap<string, string, strihash<char>, strihashcmp<char> > attrmap;
#else
    typedef hash_multimap<string, string, strihash<char> > attrmap;
#endif

    HTTPClient();
    ~HTTPClient() { delete [] result; }

    const Sockaddr &address(void) const { return addr; }
    const char *data(void) const { return result; }
    int err(void) const { return sock.err(); }
    bool keepalive(void) const { return ka; }
    long rtimeout(void) const { return rto; }
    long size(void) const { return ressz; }
    uint status(void) const { return sts; }
    long wtimeout(void) const { return wto; }

    ostream &operator <<(ostream &os);
    bool close(void) { return sock.close(); }
    bool connect(const Sockaddr &addr, bool keepalive = false, 
	ulong timeout = SOCK_INFINITE);
    bool connect(const char *host, ushort port = 80, bool keepalive = false,
	ulong timeout = SOCK_INFINITE) {
	return connect(Sockaddr(host, port), keepalive, timeout);
    }
    template<class H, class V> void header(const H &hdr, const V &val)
	{ hstrm << hdr << ": " << val << "\r\n"; }
    bool del(const tchar *path) { return send("DELETE", path); }
    bool get(const tchar *path) { return send("GET", path); }
    bool head(const tchar *path) { return send("HEAD", path); }
    bool post(const tchar *path, const void *data, uint len)
	{ return send("POST", path, data, len); }
    bool put(const tchar *path, const void *data, uint len)
	{ return send("PUT", path, data, len); }
    const char *response(const string &name) const {
	attrmap::const_iterator it = reshdrs.find(name);
	return it == reshdrs.end() ? NULL: (*it).second.c_str();
    }
    const attrmap &responses(void) const { return reshdrs; }
    void timeout(ulong r, ulong w = SOCK_INFINITE) { rto = r; wto = w; }

protected:
    Sockaddr addr;
    bufferstream hstrm;
    Socket sock;
    bool ka;
    attrmap reshdrs;
    ulong ressz;
    char *result;
    ulong rto, wto;
    sockstream sstrm;
    uint sts;
    ulong sz;

    bool send(const char *op, const tchar *path, const void *data = NULL,
	long datasz = 0);
};

#endif // HTTPClient_h
