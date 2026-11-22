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

// response headers in one reused buffer: too few to need hashing
class DLL_LOCAL HTTPHeaders {
public:
    using attrmap = unordered_multimap<tstring, tstring, strihash, strieq>;

    void add(string_view hdr);
    void clear(void) {
	buf.clear();
	hdrs.clear();
    }
    const tchar *find(tstring_view name) const {
	for (const auto &h : hdrs) {
	    if (stringieq(tstring_view(buf.data() + h.name, h.nlen), name))
		return buf.data() + h.val;
	}
	return nullptr;
    }
    attrmap map(void) const {
	attrmap m;

	for (const auto &h : hdrs)
	    m.emplace(tstring(buf.data() + h.name, h.nlen), buf.data() + h.val);
	return m;
    }

private:
    struct Hdr {
	uint name, nlen, val;
    };

    static void tappend(tstring &s, string_view sv);

    tstring buf;
    vector<Hdr> hdrs;
};

template<class S>
class HTTPParser;

// request headers and response state shared by the blocking and async clients
class BLISTER HTTPResponse: nocopy {
public:
    using attrmap = HTTPHeaders::attrmap;

    const char *data(void) const { return result ? result : ""; }
    int err(void) const { return sockerr; }
    tstring errstr(void) const {
	return sockerr == EOF ? T("socket EOF") : tstring(tstrerror(sockerr));
    }
    ulong size(void) const { return sz; }
    uint status(void) const { return sts; }
    const tchar *response(tstring_view name) const {
	return reshdrs.find(name);
    }
    attrmap responses(void) const { return reshdrs.map(); }

    template<typename C>
    void header(tstring_view hdr, const C &val) {
	hstrm.writev(hdr, T(": "), val, T("\r\n"));
    }
    void headers(tstring_view hdrs) { hstrm << hdrs; }

protected:
    HTTPResponse() = default;
    ~HTTPResponse() { free(result); }

    static constexpr ulong Unknown = ~0UL;

    // consumes hstrm; EINVAL if op or path could inject into the request
    // line. A small body is appended, zeroing datasz
    bool buildreq(string &out, const tchar *op, const tchar *path,
	string_view host, bool keep, const void *data, ulong &datasz);
    static string hosthdr(const Sockaddr &sa);
    static bool idempotent(const tchar *op);

    // result capacity for need bytes + NUL: exact when the length is known
    ulong capfor(ulong need, bool exact) const;
    // keeps a small buffer for the next response
    void reset(void);
    bool resize(ulong newcap);

    tbufferstream hstrm;
    char *result = nullptr;
    HTTPHeaders reshdrs;
    int sockerr = 0;
    ulong cap = 0, sz = 0;
    uint sts = 0;

private:
    friend class AsyncHTTPClient;
    template<class S>
    friend class HTTPParser;

    enum class Body: uchar { Bad, None, Length, Chunked, Eof };

    static Body framing(const HTTPHeaders &hdrs, uint sts, bool head,
	bool http11, bool &keep, ulong &len);
    static bool hashost(tstring_view hdrs);
    static bool parsenum(string_view s, ulong &n, bool hex);
    static bool parsestatus(string_view str, uint &code, bool &http11);
};

/*
 * Incremental HTTP/1.x response parser over a buffered socket. S is Socket or
 * a DispatchSocket: the latter can return Wait. One response is in flight per
 * connection so its state lives here and not in the request
 */
template<class S>
class DLL_LOCAL HTTPParser: nocopy {
public:
    enum class Step: uchar { Done, Wait, Proto, Sock };

    explicit HTTPParser(S &s): sb(s, 3L * 1460), sock(s) {}

    faststreambuf<S> &buf(void) { return sb; }
    bool buffered(void) const { return !sb.avail().empty(); }
    int err(void) const { return ecode; }
    bool keep(void) const { return reuse; }

    // grow(newcap) allocates r.result and returns Done, Wait or Proto
    template<class G>
    Step advance(HTTPResponse &r, bool head, G grow);
    // 1 data buffered, 0 would block, -1 error
    int fill(void);
    void reset(void);
    // a poll event may have added data to a drained socket
    void wake(void) { idle = false; }

private:
    enum Phase: uchar {
	Status, Headers, Length, Eof, ChunkSize, ChunkData, ChunkEnd, Trailers,
	Complete
    };

    bool emptied(void) const {
	if constexpr (requires { sock.drained(); })
	    return sock.drained();
	return false;
    }
    Step fail(int e) {
	ecode = e;
	return Step::Proto;
    }
    Step nextline(string_view &line);
    template<class G>
    Step reserve(HTTPResponse &r, ulong need, G &grow);
    Step sockfail(void) {
	ecode = sock.err();
	return Step::Sock;
    }
    long take(HTTPResponse &r, ulong want);
    void start(Phase p, size_t limit) {
	phase = p;
	left = limit;
    }

    int ecode = 0;
    bool http11 = false, idle = false, partial = false, reuse = false;
    size_t left = 0;
    string line;
    Phase phase = Status;
    ulong remain = 0;
    faststreambuf<S> sb;
    S &sock;
};

class BLISTER HTTPClient: public HTTPResponse {
public:
    virtual ~HTTPClient() = default;

    friend tostream &operator <<(tostream &os, const HTTPClient &hc) {
	os << hc.sts << '\n';
	for (const auto &[key, value] : hc.responses())
	    os << key << ": " << value << '\n';
	os.write(achartotchar(hc.data()), (streamsize)hc.sz);
	os << '\n';
	return os;
    }

    const Sockaddr &address(void) const { return addr; }
    const Socket &socket(void) const { return sock; }
    bool keepalive(void) const { return ka; }
    uint rtimeout(void) const { return rto; }
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
    bool cmd(const tchar *cmd, const tchar *path, const void *data = nullptr,
	ulong len = 0, msghdr *msgh = nullptr) {
	return send(cmd, path, data, len, msgh);
    }
    bool del(const tchar *path) { return send(T("DELETE"), path); }
    bool get(const tchar *path) { return send(T("GET"), path); }
    bool head(const tchar *path) { return send(T("HEAD"), path); }
    bool options(const tchar *path) { return send(T("OPTIONS"), path); }
    bool patch(const tchar *path, const void *data, ulong len, msghdr *msgh =
	nullptr) {
	return send(T("PATCH"), path, data, len, msgh);
    }
    bool post(const tchar *path, const void *data, ulong len, msghdr *msgh =
	nullptr) {
	return send(T("POST"), path, data, len, msgh);
    }
    bool put(const tchar *path, const void *data, ulong len, msghdr *msgh =
	nullptr) {
	return send(T("PUT"), path, data, len, msgh);
    }
    void timeout(uint r, uint w = SOCK_INFINITE) {
	sock.rtimeout(rto = r);
	sock.wtimeout(wto = w);
    }
    /*
     * chunked request body of unknown length: sendbegin(), sendchunk()s,
     * sendend() (true if a response arrived). If the server replies early
     * sendchunk() fails with err() 0 and that response
     */
    bool sendbegin(const tchar *op, const tchar *path);
    bool sendchunk(const void *data, ulong len) {
	iovec iov;

	iov.iov_base = (char *)data;		// NOSONAR
	iov.iov_len = (iovlen_t)len;
	return sendchunk(&iov, 1);
    }
    bool sendchunk(const iovec *iov, int cnt);
    bool sendend(void);

protected:
    Sockaddr addr;
    uint cto = SOCK_INFINITE;
    string hostval;
    bool ka = true;
    HTTPParser<Socket> parser { sock };
    string req;
    uint rto = 90 * 1000;
    Socket sock;
    bool streaming = false;
    uint wto = 60 * 1000;

    // after each connect, such as to start TLS
    virtual bool onconnect(void) { return true; }
    bool send(const tchar *op, const tchar *path, const void *data = nullptr,
	ulong datasz = 0, msghdr *msgh = nullptr);
    // socket options and an empty parser for a new connection
    void setup(void);

private:
    using Step = HTTPParser<Socket>::Step;

    Step receive(bool head, bool &keep);
    void sendfail(void);
    bool transmit(const void *data, ulong datasz, ulong off);
};

/*
 * Pipelines requests over one keep-alive connection. Must outlive its
 * Requests, which cannot be destroyed in flight
 */
class BLISTER AsyncHTTPClient: nocopy {
public:
    using attrmap = HTTPResponse::attrmap;
    using DispatchObjCB = DispatchObj::DispatchObjCB;

    // NOLINTNEXTLINE(misc-multiple-inheritance)
    class BLISTER Request: public DispatchObj, public HTTPResponse {
    public:
	explicit Request(Dispatcher &d): DispatchObj(d) {}
	explicit Request(DispatchObj &parent): DispatchObj(child, parent) {}

	// NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
	virtual void reset(void) { HTTPResponse::reset(); }
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

	tstring logprefix;

    private:
	friend class AsyncHTTPClient;

	AsyncHTTPClient *client = nullptr;
	DispatchObj *caller = nullptr;
	DispatchObjCB done = nullptr;
	const void *datap = nullptr;
	string req;
	ulong datasz = 0, written = 0;
	timing_t start = 0;
	uchar attempts = 0;
	bool head = false, idem = true;
    };

    // on a parent shares its group; parent callbacks must not delete the client
    AsyncHTTPClient(Dispatcher &d, const Sockaddr &sa, Timing *tm = nullptr):
	AsyncHTTPClient(new IOSocket(d, *this), sa, tm) {}
    AsyncHTTPClient(DispatchObj &parent, const Sockaddr &sa, Timing *tm =
	nullptr): AsyncHTTPClient(new IOSocket(parent, *this), sa, tm) {}
    virtual ~AsyncHTTPClient() {
	intake.erase();
	sock.erase();
    }

    const Sockaddr &address(void) const { return addr; }
    uint numPending(void) const { return pending - 1; }
    void status(tostream &out, uint indent) const;
    void timeout(uint connect, uint io) { cto = connect; rto = io; }

    // pending counts requests + owner; self deletes once idle after release()
    void acquire(void) { pending++; }
    void release(void) {
	if (!--pending)
	    intake.ready(Intake::drain);
    }

protected:
    // install a layer such as TLS on each new connection before its handshake
    virtual bool onconnect(Socket &s) { (void)s; return true; }

    const Sockaddr addr;

private:
    class IOSocket: public DispatchClientSocket {
    public:
	IOSocket(Dispatcher &d, AsyncHTTPClient &c): DispatchClientSocket(d),
	    client(c) {}
	IOSocket(DispatchObj &parent, AsyncHTTPClient &c):
	    DispatchClientSocket(parent), client(c) {}

	DSP_DECLARE(IOSocket, ongrown) { client.grown(); }
	DSP_DECLARE(IOSocket, onio) { client.io(); }
	DSP_DECLARE(IOSocket, onshake) { client.shake(); }

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
    using Step = HTTPParser<IOSocket>::Step;

    Flow bad(int err);
    Flow finish(Request &r);
    Flow readall(void);
    Flow writeall(void);
    Step reserve(Request &r, ulong newcap);
    void complete(Request &r, int err);
    void connect(void);
    void connected(void);
    void down(int err, Down how);
    void drain(void);
    void enqueue(Request &r);
    void grown(void);
    void io(bool event = true);
    void opened(void);
    void shake(void);
    void submit(Request &r);

    const string host;
    tstring ckey;
    atomic<ulong> connects = 0;
    timing_t cstart = 0;
    atomic<uint> cto = 30 * 1000;
    bool growing = false, inreserve = false;
    vector<Request *> batch, inbox;
    atomic<DispatchObj *> incall = nullptr;
    SpinLock inlock;
    Intake &intake;
    HTTPParser<IOSocket> parser;
    atomic<uint> pending = 1;
    atomic<ulong> requests = 0;
    tstring rkey;
    deque<Request *> rq;
    atomic<uint> rto = 90 * 1000;
    IOSocket &sock;
    atomic<State> state = Closed;
    Timing *timing;
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
	using C = decltype(list)::value_type;
	static constexpr C ws[] = { ' ', '\t', 0 };

	list = pos == list.npos ? decltype(list)() : list.substr(pos + 1);
	v.remove_prefix(min(v.find_first_not_of(ws), v.size()));
	v = v.substr(0, v.find_last_not_of(ws) + 1);
	if (stringieq(v, token))
	    return true;
    }
    return false;
}

BLISTER time_t parse_date(const tchar *hdr, int adjhr = 0, int adjmin = 0);

#endif // HTTPClient_h
