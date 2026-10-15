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

#ifndef HTTPServer_h
#define HTTPServer_h

#include <flat_map>
#include <unordered_map>
#include "Dispatch.h"
#include "Service.h"

class BLISTER HTTPServerSocket: public DispatchServerSocket {
public:
    using attrmap = unordered_map<const char *, const char *, strihash,
	strieq>;
    // a handful of headers: sorted vectors beat hashing, inserts are O(n)
    using hdrmap = flat_map<const char *, const char *, striless>;

    HTTPServerSocket(Dispatcher &d, Socket &sock):
	DispatchServerSocket(d, sock) {}
    virtual ~HTTPServerSocket();

    const attrmap &arguments(void) const { return args; }
    const hdrmap &attributes(void) const { return attrs; }
    const attrmap &postarguments(void) const { return postargs; }
    void urldecode(char *buf, attrmap &amap) const;
    virtual const char *mimetype(const char *ext) const;
    void start(void) override { readable(readhdrs, rto); }
    static void pause(bool b) { paused = b; }
    static void senddate(bool b) { date = b; }
    static const tchar *section(void) { return T("http"); }

protected:
    string argdata;
    iovec iov[3] = {};
    bufferstream<char> hdrs, ss;
    const char *path = nullptr, *prot = nullptr;
    char *postdata = nullptr;
    ulong postsz = 0;

    const char *arg(const char *name) const { return find(args, name); }
    const char *attr(const char *name) const { return find(attrs, name); }
    const char *postarg(const char *name) const { return find(postargs, name); }
    template<class C> ostream &operator <<(const C &c) { return ss << c; }
    void header(const char *attr, const char *val);
    using DispatchObj::error;
    void error(uint sts, bool close = false);
    void error(uint sts, const char *errstr, bool close = false);
    void keepalive(void);
    void reply(const char *data = nullptr, ulong len = (ulong)-1);
    void reply(int fd, ulong sz);
    void reply(uint sts) { status(sts, nullptr); reply(); }
    void status(uint sts, const char *mime = "text/plain", time_t mtime = 0,
	const char *str = nullptr, bool close = false);
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
    virtual void postdata_free(void) { delete [] postdata; }
    virtual void postdata_grow(DispatchObjCB cb, ulong keepsize, ulong newsize);
    virtual void put(void) { error(501); }
    // called when reply() no longer needs its buffer data
    // a lone request continues at once but pipelined bytes or an owned body
    // buffer may still be in use by the caller of reply() so defer those
    virtual void replydone(DispatchObjCB cb) {
	if (datasz || postdatasz)
	    ready(cb);
	else
	    cb(this);
    }
    DSP_DECLARE(HTTPServerSocket, done);
    DSP_DECLARE(HTTPServerSocket, send);

private:
    attrmap args, postargs;
    hdrmap attrs;
    ulong chunkin = 0;
    bool chunktrailer = false, postchunking = false;
    const char *cmd = nullptr;
    char *data = nullptr;
    ulong datasz = 0, sz = 0;
    char *fmap = nullptr;
    ulong fmapsz = 0;
    bool ka = false, nagleon = true;
    ulong postdatasz = 0, postin = 0;
    uint rto = 30 * 1000, wto = 150 * 1000;
    char savechar = 0;
    uint _status = 0;
    static bool date;
    static atomic_bool paused;

    template<class M>
    const char *find(const M &amap, const char *name) const {
	auto it = amap.find(name);

	return it == amap.end() ? nullptr : it->second;
    }
    void scan(char *buf, ulong len, bool append = false);
    void unmap(void);
    DSP_DECLARE(HTTPServerSocket, parse);
    DSP_DECLARE(HTTPServerSocket, readhdrs);
    DSP_DECLARE(HTTPServerSocket, readpost);
    DSP_DECLARE(HTTPServerSocket, senddone);
};

#endif // HTTPServer_h
