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

#ifndef HTTPClient_h
#define HTTPClient_h

#include STL_UNORDERED_MAP_H
#include "Socket.h"

class BLISTER URL {
public:
    URL(): port(80) { set(NULL); }
    explicit URL(const tchar *url): port(80) { set(url); }
    URL(const URL &url): port(0) { operator =(url); }

    tstring host, path, prot, query;
    ushort port;

    URL &operator =(const URL &url);
    const tstring fullpath(void) const;
    const tstring relpath(void) const {
	return query.empty() ? path : path + T("?") + query;
    }
    bool set(const tchar *url);
    static void unescape(tchar *str, bool plus = true);
    static void unescape(tstring &str, bool plus = true);
};

class BLISTER HTTPClient: nocopy {
public:
    typedef unordered_multimap<tstring, tstring, strihash<tchar>,
	strieq<tchar> > attrmap;

    HTTPClient();
    ~HTTPClient() { delete [] result; }

    const Sockaddr &address(void) const { return addr; }
    const char *data(void) const { return result; }
    int err(void) const { return sock.err(); }
    bool keepalive(void) const { return ka; }
    uint rtimeout(void) const { return rto; }
    ulong size(void) const { return ressz; }
    uint status(void) const { return sts; }
    uint wtimeout(void) const { return wto; }

    tostream &operator <<(tostream &os) const;
    bool close(void) { return sock.close(); }
    bool connect(const Sockaddr &sa, bool keepalive = false, uint timeout =
	SOCK_INFINITE);
    bool connect(const tchar *host, ushort port = 80, bool keepalive = false,
	uint timeout = SOCK_INFINITE) {
	return connect(Sockaddr(host, port), keepalive, timeout);
    }
    template<class C> void header(const tchar *hdr, const C &val) {
	hstrm << hdr << T(": ") << val << T("\r\n");
    }
    template<class C> void header(const tstring &hdr, const C &val) {
	hstrm << hdr << T(": ") << val << T("\r\n");
    }
    void headers(const tstring &headers) { hstrm << headers; }
    bool cmd(const tchar *cmd, const tchar *path) { return send(cmd, path); }
    bool del(const tchar *path) { return send(T("DELETE"), path); }
    bool get(const tchar *path) { return send(T("GET"), path); }
    bool head(const tchar *path) { return send(T("HEAD"), path); }
    bool post(const tchar *path, const void *data, ulong len) {
	return send(T("POST"), path, data, len);
    }
    bool put(const tchar *path, const void *data, ulong len) {
	return send(T("PUT"), path, data, len);
    }
    const tchar *response(const tstring &name) const {
	attrmap::const_iterator it = reshdrs.find(name);
	return it == reshdrs.end() ? NULL : it->second.c_str();
    }
    const attrmap &responses(void) const { return reshdrs; }
    void timeout(uint r, uint w = SOCK_INFINITE) {
	sock.rtimeout(rto = r);
	sock.wtimeout(wto = w);
    }

protected:
    Sockaddr addr;
    bufferstream<tchar> hstrm;
    Socket sock;
    bool ka;
    attrmap reshdrs;
    ulong ressz;
    char *result;
    uint rto, wto;
    sockstream sstrm;
    uint sts;
    ulong sz;

    bool send(const tchar *op, const tchar *path, const void *data = NULL,
	ulong datasz = 0);
};

#endif // HTTPClient_h
