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
#include <vector>
#include "Dispatch.h"
#include "Timing.h"

#ifdef _WIN32
struct msghdr;
#endif

class BLISTER URL {
public:
    explicit URL(const tchar *url = nullptr) { set(url); }

    friend auto operator <=>(const URL &a, const URL &b) = default;

    const tstring &host(void) const { return hoststr; }
    const tstring &prot(void) const { return protstr; }
    ushort port(void) const { return portnum; }
    tstring fullpath(void) const;
    // path and query are stored escaped
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
    // in place decode returning the new length
    static size_t unescape(tchar *str, bool plus = true);
    static void unescape(tstring &str, bool plus = true);

private:
    tstring hoststr, protstr, rpath = T("/"), rquery;
    ushort portnum = 80;
};

class BLISTER HTTPClient: nocopy {
public:
    using attrmap = unordered_multimap<tstring, tstring, strihash, strieq>;

    HTTPClient(): sstrm(3L * 1460) {}

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
    // shares the caller's fd
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
    bool post(const tchar *path, const void *data, ulong len,
	msghdr *msgh = nullptr) {
	return send(T("POST"), path, data, len, msgh);
    }
    bool put(const tchar *path, const void *data, ulong len,
	msghdr *msgh = nullptr) {
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
    string hostval;
    bufferstream<tchar> hstrm;
    bool ka = true;
    string line;
    string req;
    attrmap reshdrs;
    ulong ressz = 0;
    unique_ptr<char[]> result;
    uint rto = 90 * 1000;
    Socket sock;
    sockstream sstrm;
    uint sts = 0;
    ulong sz = 0;
    uint wto = 60 * 1000;

    bool send(const tchar *op, const tchar *path, const void *data = nullptr,
	ulong datasz = 0, msghdr *msgh = nullptr);

private:
    void grow(ulong need);
    bool readbody(bool head, bool &keep);
    bool readchunked(void);
    bool readhdrs(bool &http11);
    void setup(void);
};

// Pipelines requests over one keep-alive connection. Must outlive its
// Requests, which cannot be destroyed in flight
class BLISTER AsyncHTTPClient: nocopy {
public:
    using attrmap = HTTPClient::attrmap;
    using DispatchObjCB = DispatchObj::DispatchObjCB;

    class BLISTER Request: public DispatchObj {
    public:
	explicit Request(Dispatcher &d): DispatchObj(d) {}
	explicit Request(DispatchObj &parent): DispatchObj(child, parent) {}
	~Request() override { free(result); }

	const char *data(void) const { return result ? result : ""; }
	int err(void) const { return sockerr; }
	tstring errstr(void) const {
	    return sockerr == EOF ? T("socket EOF") :
		tstring(tstrerror(sockerr));
	}
	ulong size(void) const { return sz; }
	uint status(void) const { return sts; }
	const tchar *response(tstring_view name) const {
	    auto it = reshdrs.find(name);

	    return it == reshdrs.end() ? nullptr : it->second.c_str();
	}
	const attrmap &responses(void) const { return reshdrs; }

	template<typename C>
	void header(tstring_view hdr, const C &val) {
	    hstrm << hdr << T(": ") << val << T("\r\n");
	}
	void headers(tstring_view hdrs) { hstrm << hdrs; }
	virtual void reset(void);
	// data must remain valid until the callback is called
	void send(DispatchObjCB cb, DispatchObj &co, AsyncHTTPClient &client,
	    const tchar *op, const tchar *path, const void *data = nullptr,
	    ulong datasz = 0);
	void set_logprefix(const tchar *prefix) { logprefix = prefix; }

    protected:
	// grow result to newsize keeping keepsize bytes of old
	virtual void result_grow(DispatchObjCB cb, DispatchObj &co, char *old,
	    uint keepsize, uint newsize);

	bool setup(DispatchObjCB cb, DispatchObj &co, AsyncHTTPClient &client,
	    const tchar *op, const tchar *path, const void *data, ulong datasz);
	void queue(void) { client->submit(*this); }
	// true if resubmitted to a client instead of completing
	virtual bool resend(void) { return false; }

	attrmap reshdrs;
	tbufferstream hstrm;
	tstring logprefix;
	char *result = nullptr;
	int sockerr = 0;
	ulong sz = 0;
	uint sts = 0;

    private:
	friend class AsyncHTTPClient;
	enum Phase: uchar {
	    Status, Headers, Length, Eof, ChunkSize, ChunkData, ChunkEnd,
	    Trailers, Done
	};

	void rewind(void);

	AsyncHTTPClient *client = nullptr;
	DispatchObj *caller = nullptr;
	DispatchObjCB done = nullptr;
	const void *datap = nullptr;
	string req;
	ulong cap = 0, datasz = 0, remain = 0, written = 0;
	timing_t start = 0;
	size_t hdrleft = 0;
	Phase phase = Status;
	uchar attempts = 0;
	bool head = false, http11 = false, keep = false;
    };

    // built on a Dispatcher it gets its own group, on a parent it shares it
    // and the parent's callbacks run within client io so must not delete it
    AsyncHTTPClient(Dispatcher &d, const Sockaddr &sa, Timing *tm = nullptr):
	AsyncHTTPClient(new IOSocket(d, *this), sa, tm) {}
    AsyncHTTPClient(DispatchObj &parent, const Sockaddr &sa, Timing *tm =
	nullptr): AsyncHTTPClient(new IOSocket(parent, *this), sa, tm) {}
    ~AsyncHTTPClient() {
	intake.erase();
	sock.erase();
    }

    const Sockaddr &address(void) const { return addr; }
    uint numPending(void) const { return pending - 1; }
    void status(tostream &out, uint indent) const;
    void timeout(uint connect, uint io) { cto = connect; rto = io; }

    // pending is requests plus one for the owner. A client deletes itself
    // once idle after the last release() so the owner must then forget it
    void acquire(void) { pending++; }
    void release(void) {
	if (!--pending)
	    intake.ready(Intake::drain);
    }

private:
    class IOSocket: public DispatchClientSocket {
    public:
	IOSocket(Dispatcher &d, AsyncHTTPClient &c): DispatchClientSocket(d),
	    client(c) {}
	IOSocket(DispatchObj &parent, AsyncHTTPClient &c):
	    DispatchClientSocket(parent), client(c) {}

	// the last read emptied the socket
	bool drained(void) const { return rdrain; }

	DSP_DECLARE(IOSocket, ongrown) { client.grown(); }
	DSP_DECLARE(IOSocket, onio) { client.io(); }

    protected:
	void onConnect(void) override { client.connected(); }

    private:
	AsyncHTTPClient &client;
    };

    // relays requests from any thread into the client's group
    class Intake: public DispatchObj {
    public:
	Intake(DispatchObj &parent, AsyncHTTPClient &c):
	    DispatchObj(child, parent), client(c) {}

	DSP_DECLARE(Intake, drain) { client.drain(); }

    private:
	AsyncHTTPClient &client;
    };

    AsyncHTTPClient(IOSocket *s, const Sockaddr &sa, Timing *tm);

    // Retry: resend requests sent once, Resend: resend all unanswered
    enum class Down { Fail, Retry, Resend };
    enum class Flow { Ok, Wait, Stop };
    enum State: uchar { Closed, Connecting, Open };

    Flow advance(Request &r);
    Flow bad(int err);
    Flow broke(int err) {
	down(err, Down::Retry);
	return Flow::Stop;
    }
    Flow endhdrs(Request &r);
    Flow finish(Request &r);
    Flow nextline(string_view &line, size_t &left);
    Flow readall(void);
    Flow reserve(Request &r, ulong need);
    Flow writeall(void);
    int fill(void);
    long take(Request &r, ulong want);
    void complete(Request &r, int err);
    void connect(void);
    void connected(void);
    void count(void) {
	rcnt = (uint)rq.size();
	wcnt = (uint)wq.size();
    }
    void down(int err, Down how);
    void drain(void);
    void enqueue(Request &r);
    void grown(void);
    void io(bool event = true);
    void submit(Request &r);

    const Sockaddr addr;
    const string host;
    tstring ckey;
    atomic<ulong> connects = 0;
    timing_t cstart = 0;
    atomic<uint> cto = 30 * 1000;
    bool growing = false, idle = false, inreserve = false;
    vector<Request *> batch, inbox;
    atomic<DispatchObj *> incall = nullptr;
    SpinLock inlock;
    Intake &intake;
    atomic<uint> pending = 1, rcnt = 0;
    unique_ptr<char[]> rdbuf;
    size_t rdcap = 0, rdend = 0, rdpos = 0;
    atomic<ulong> requests = 0;
    tstring rkey;
    deque<Request *> rq;
    atomic<uint> rto = 90 * 1000;
    IOSocket &sock;
    atomic<State> state = Closed;
    Timing *timing;
    atomic<uint> wcnt = 0;
    tstring wkey;
    deque<Request *> wq;
};

// true if a comma separated header token list contains token (case-insensitive)
template<typename A, typename B>
bool hastoken(const A &l, const B &t) {
    auto list = strview(l);
    const auto token = strview(t);

    while (!list.empty()) {
	size_t pos = list.find(',');
	auto v = list.substr(0, pos);

	list = pos == list.npos ? decltype(list)() : list.substr(pos + 1);
	while (!v.empty() && (v.front() == ' ' || v.front() == '\t'))
	    v.remove_prefix(1);
	while (!v.empty() && (v.back() == ' ' || v.back() == '\t'))
	    v.remove_suffix(1);
	if (stringieq(v, token))
	    return true;
    }
    return false;
}

BLISTER time_t parse_date(const tchar *hdr, int adjhr = 0, int adjmin = 0);

#endif // HTTPClient_h
