/*
 * Copyright 2001-2010 Todd Richmond
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

#ifndef HTTPServer_h
#define HTTPServer_h

#include "Dispatch.h"
#include "Service.h"

const uint RTimeout = 30 * 1000;
const uint WTimeout = 150 * 1000;

class HTTPServerSocket: public DispatchServerSocket {
public:
#ifdef STL_HASH_MAP_4ARGS
    typedef hash_map<const char *, const char *, strihash<char>,
	strihasheq<char> > attrmap;
#else
    typedef hash_map<const char *, const char *, strihash<char> > attrmap;
#endif
    HTTPServerSocket(Dispatcher &dspr, Socket &sock);
    virtual ~HTTPServerSocket();

    const attrmap &attributes(void) const { return attrs; }
    const attrmap &arguments(void) const { return args; }
    const attrmap &postarguments(void) const { return postargs; }
    void urldecode(char *data, attrmap &amap) const;
    static void senddate(bool b) { date = b; }
    static const tchar *section(void) { return T("http"); }

    virtual void start(void) { readable(readhdrs, rto); }

protected:
    void header(const char *attr, const char *val);
    void error(uint errnum);
    void reply(const char *data = NULL, size_t len = 0);
    void reply(int fd, size_t sz);
    void reply(uint sts) { status(sts, NULL); reply(); }
    void status(uint sts, const char *type = "text",
	const char *subtype = "plain", time_t mtime = 0);
    template<class C> ostream &operator <<(const C &c) { return ss << c; }
    virtual void del(void) { error(501); }
    virtual void eos(void) {}
    virtual void get(bool head = false);
    virtual void post(void) { error(501); }
    virtual void put(void) { error(501); }

    attrmap attrs, args, postargs;
    const char *cmd, *path, *prot;
    char *data, *postdata;
    ulong datasz, postsz, postin, sz;
    bool delpost, ka, nagleon;
    char *fmap;
    bufferstream<char> hdrs, ss;
    iovec iov[3];
    uint rto, wto;
    char savechar;
    uint _status;
    static bool date;

    const char *arg(const char *name) const { return find(args, name); }
    const char *attr(const char *name) const { return find(attrs, name); }
    const char *postarg(const char *name) const { return find(postargs, name); }
    void keepalive(void);
    void scan(char *buf, int len, bool append = false);
    const char *find(const attrmap &amap, const char *name) const {
	attrmap::const_iterator it = amap.find(name);
	return it == amap.end() ? NULL : (*it).second;
    }
    virtual void exec(void);
    DSP_DECLARE(HTTPServerSocket, parse);
    DSP_DECLARE(HTTPServerSocket, readhdrs);
    DSP_DECLARE(HTTPServerSocket, readpost);
    DSP_DECLARE(HTTPServerSocket, send);
};

#endif // HTTPServer_h
