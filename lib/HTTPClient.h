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

#ifndef HTTPClient_h
#define HTTPClient_h

#include <deque>
#include <unordered_map>
#include "Dispatch.h"
#include "Timing.h"

#ifdef _WIN32
struct msghdr;
#endif

class BLISTER URL {
public:
    explicit URL(const tchar *url = nullptr) { set(url); }

    tstring host, prot;
    ushort port = 80;

    friend auto operator <=>(const URL &a, const URL &b) = default;

    tstring fullpath(void) const;
    // path and query are stored escaped so they are always wire-correct
    tstring path(void) const {
	tstring s(rpath);

	unescape(s, false);
	return s;
    }
    tstring query(void) const {
	tstring s(rquery);

	unescape(s);
	return s;
    }
    const tstring &rawpath(void) const { return rpath; }
    const tstring &rawquery(void) const { return rquery; }
    constexpr tstring relpath(void) const {
	return rquery.empty() ? rpath : rpath + T("?") + rquery;
    }
    bool set(const tchar *url);
    static void unescape(tchar *str, bool plus = true);
    static void unescape(tstring &str, bool plus = true);

private:
    tstring rpath = T("/"), rquery;
};

class BLISTER HTTPClient: nocopy {
public:
    using attrmap = unordered_multimap<tstring, tstring, strihash, strieq>;

    HTTPClient();

    friend tostream &operator <<(tostream &os, const HTTPClient &hc) {
	os << hc.sts << '\n';
	for (const auto &[key, value] : hc.reshdrs)
	    os << key << ": " << value << '\n';
	os.write(achartotchar(hc.data()), (streamsize)hc.ressz);
	os << '\n';
	return os;
    }

    const Sockaddr &address(void) const { return addr; }
    const Socket &socket(void) const { return sock; }
    const char *data(void) const { return result ? result.get() : ""; }
    int err(void) const { return sock.err(); }
    bool keepalive(void) const { return ka; }
    uint rtimeout(void) const { return rto; }
    ulong size(void) const { return ressz; }
    uint status(void) const { return sts; }
    uint wtimeout(void) const { return wto; }

    bool close(void) { return sock.close(); }
    bool connect(const Sockaddr &sa, bool keepalive = false, uint timeout =
	SOCK_INFINITE);
    // adopt an already connected socket (shares its fd with the caller)
    bool connect(Socket &s, bool keepalive = false);
    bool connect(const tchar *host, ushort port = 80, bool keepalive = false,
	uint timeout = SOCK_INFINITE) {
	return connect(Sockaddr(host, port), keepalive, timeout);
    }
    template<typename C>
    void header(tstring_view hdr, const C &val) {
	hstrm << hdr << T(": ") << val << T("\r\n");
    }
    void headers(tstring_view headers) { hstrm << headers; }
    bool cmd(const tchar *cmd, const tchar *path) { return send(cmd, path); }
    bool del(const tchar *path) { return send(T("DELETE"), path); }
    bool get(const tchar *path) { return send(T("GET"), path); }
    bool head(const tchar *path) { return send(T("HEAD"), path); }
    // msgh (optional) sends on an adopted socket with ancillary data
    bool post(const tchar *path, const void *data, ulong len, msghdr *msgh =
	nullptr) {
	return send(T("POST"), path, data, len, msgh);
    }
    // msgh (optional) sends on an adopted socket with ancillary data
    bool put(const tchar *path, const void *data, ulong len, msghdr *msgh =
	nullptr) {
	return send(T("PUT"), path, data, len, msgh);
    }
    const tchar *response(tstring_view name) const {
	auto it = reshdrs.find(name);
	return it == reshdrs.end() ? nullptr : it->second.c_str();
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
    bool ka = true;
    attrmap reshdrs;
    ulong ressz = 0;
    unique_ptr<char[]> result;
    uint rto = 90 * 1000;
    uint wto = 60 * 1000;
    sockstream sstrm;
    uint sts = 0;
    ulong sz = 0;

    bool send(const tchar *op, const tchar *path, const void *data = nullptr,
	ulong datasz = 0, msghdr *msgh = nullptr);

private:
    void setup(void);
    bool transmit(const string &req, const void *data, ulong datasz,
	msghdr *msgh);
    void grow(ulong need);
    bool readbody(bool head, bool &keep);
    bool readchunked(void);
    bool readhdrs(string &line, bool &http11);
};

BLISTER time_t parse_date(const tchar *hdr, int adjhr = 0, int adjmin = 0);

#endif // HTTPClient_h
