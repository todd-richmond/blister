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

#ifndef HTTPServer_h
#define HTTPServer_h

#include STL_UNORDERED_MAP_H
#include "Dispatch.h"
#include "Service.h"

const uint RTimeout = 30 * 1000;
const uint WTimeout = 150 * 1000;

class BLISTER HTTPServerSocket: public DispatchServerSocket {
public:
    typedef unordered_map<const char *, const char *, strihash<char>,
	strieq<char> > attrmap;

    HTTPServerSocket(Dispatcher &dspr, Socket &sock);
    virtual ~HTTPServerSocket();

    const attrmap &arguments(void) const { return args; }
    const attrmap &attributes(void) const { return attrs; }
    const attrmap &postarguments(void) const { return postargs; }
    void urldecode(char *buf, attrmap &amap) const;
    virtual const string mimetype(const char *ext) const;
    static void senddate(bool b) { date = b; }
    static const tchar *section(void) { return T("http"); }

    virtual void start(void) { readable(readhdrs, rto); }

protected:
    string argdata;
    const char *path, *prot;
    char *postdata;
    ulong postsz;
    static const char CRLF[];

    template<class C> ostream &operator <<(const C &c) const { return ss << c; }
    const char *arg(const char *name) const { return find(args, name); }
    const char *attr(const char *name) const { return find(attrs, name); }
    const char *postarg(const char *name) const { return find(postargs, name); }
    void header(const char *attr, const char *val);
    void error(uint sts);
    void error(uint sts, const char *errstr);
    void keepalive(void);
    void reply(const char *data = NULL, ulong len = (ulong)-1);
    void reply(int fd, ulong sz);
    void reply(uint sts) { status(sts, NULL); reply(); }
    void status(uint sts, const char *mime = "text/plain", time_t mtime = 0,
	const char *str = NULL, bool close = false);
    virtual void del(void) { error(501); }
    virtual void disconnect(DispatchObjCB cb = done) { ready(cb); }
    virtual void exec(void);
    virtual void get(bool head = false);
    virtual void post(void) { error(501); }
    // call at beginning of PUT or POST unless all body data read
    virtual void postpre(DispatchObjCB cb) { ready(cb); }
    // allow subclasses to allocate their own postdata buffers
    // subclasses must reset postdata to NULL in their destructor to prevent
    // it from freeing buffer incorrectly
    virtual void postdata_free(void);
    virtual void postdata_grow(DispatchObjCB cb, ulong keepsize, ulong newsize);
    virtual void put(void) { error(501); }
    // Called when reply() no longer needs its buffer data
    virtual void replydone(DispatchObjCB cb) { ready(cb); }
    DSP_DECLARE(HTTPServerSocket, done);
    DSP_DECLARE(HTTPServerSocket, send);

private:
    attrmap attrs, args, postargs;
    ulong chunkin;
    bool chunktrailer, postchunking;
    const char *cmd;
    char *data;
    ulong datasz, postin, sz;
    char *fmap;
    bufferstream<char> hdrs, ss;
    iovec iov[3];
    bool ka, nagleon;
    ulong postdatasz;
    uint rto, wto;
    char savechar;
    uint _status;
    static bool date;

    void scan(char *buf, ulong len, bool append = false);
    const char *find(const attrmap &amap, const char *name) const {
	attrmap::const_iterator it = amap.find(name);

	return it == amap.end() ? (const char *)NULL : it->second;
    }
    DSP_DECLARE(HTTPServerSocket, parse);
    DSP_DECLARE(HTTPServerSocket, readhdrs);
    DSP_DECLARE(HTTPServerSocket, readpost);
    DSP_DECLARE(HTTPServerSocket, senddone);
};

#endif // HTTPServer_h
