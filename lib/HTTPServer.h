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
    void error(int errnum);
    void reply(const char *data = NULL, size_t len = 0);
    void reply(int fd, size_t sz);
    void reply(int sts) { status(sts, NULL); reply(); }
    void status(int sts, const char *type = "text",
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
    int _status;
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
