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
    typedef hash_multimap<tstring, tstring, strihash<tchar>, strihasheq<tchar> >
	attrmap;
#else
    typedef hash_multimap<tstring, tstring, strihash<tchar> > attrmap;
#endif

    HTTPClient();
    ~HTTPClient() { delete [] result; }

    const Sockaddr &address(void) const { return addr; }
    const char *data(void) const { return result; }
    int err(void) const { return sock.err(); }
    bool keepalive(void) const { return ka; }
    long rtimeout(void) const { return rto; }
    size_t size(void) const { return ressz; }
    uint status(void) const { return sts; }
    long wtimeout(void) const { return wto; }

    tostream &operator <<(tostream &os);
    bool close(void) { return sock.close(); }
    bool connect(const Sockaddr &addr, bool keepalive = false, 
	ulong timeout = SOCK_INFINITE);
    bool connect(const tchar *host, ushort port = 80, bool keepalive = false,
	ulong timeout = SOCK_INFINITE) {
	return connect(Sockaddr(host, port), keepalive, timeout);
    }
    template<class C> void header(const tchar *hdr, const C &val) {
	hstrm << hdr << T(": ") << val << T("\r\n");
    }
    template<class C> void header(const tstring &hdr, const C &val) {
	hstrm << hdr << T(": ") << val << T("\r\n");
    }
    bool cmd(const tchar *cmd, const tchar *path) { return send(cmd, path); }
    bool del(const tchar *path) { return send(T("DELETE"), path); }
    bool get(const tchar *path) { return send(T("GET"), path); }
    bool head(const tchar *path) { return send(T("HEAD"), path); }
    bool post(const tchar *path, const void *data, size_t len)
	{ return send(T("POST"), path, data, len); }
    bool put(const tchar *path, const void *data, size_t len)
	{ return send(T("PUT"), path, data, len); }
    const tchar *response(const tstring &name) const {
	attrmap::const_iterator it = reshdrs.find(name);
	return it == reshdrs.end() ? NULL : it->second.c_str();
    }
    const attrmap &responses(void) const { return reshdrs; }
    void timeout(ulong r, ulong w = SOCK_INFINITE) { rto = r; wto = w; }

protected:
    Sockaddr addr;
    bufferstream<tchar> hstrm;
    Socket sock;
    bool ka;
    attrmap reshdrs;
    size_t ressz;
    char *result;
    ulong rto, wto;
    sockstream sstrm;
    uint sts;
    size_t sz;

    bool send(const tchar *op, const tchar *path, const void *data = NULL,
	size_t datasz = 0);
};

#endif // HTTPClient_h
