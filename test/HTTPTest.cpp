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

#include "stdapi.h"
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif
#include "Config.h"
#include "Dispatch.h"
#include "HTTPClient.h"
#include "HTTPServer.h"
#include "Log.h"
#include "Timing.h"

const int DELAY = 20;
const int RETRY = 100;
const int TIMEOUT = 10 * 1000;
static const tchar *const URI = T("/echo");

static char *dbuf;
static uint dsz;
static atomic<uint> active;

class HTTPTest: public Dispatcher {
public:
    using Dispatcher::Dispatcher;

    // POST a string to the server and verify that it is echoed back
    class AsyncClient: public DispatchTimer {
    public:
	AsyncClient(HTTPTest &ht, const Sockaddr &sa, ulong t, ulong n):
	    DispatchTimer(ht), client(*this, sa), req(*this), nap(n) {
	    client.timeout((uint)t, (uint)t);
	    active++;
	}
	~AsyncClient() override { active--; }

	void start(ulong msec) { timeout(go, msec); }

    private:
	AsyncHTTPClient client;
	AsyncHTTPClient::Request req;
	timing_t begin = 0;
	ulong nap;

	DSP_DECLARE(AsyncClient, done);
	DSP_DECLARE(AsyncClient, go);
    };

    class EchoSocket: public HTTPServerSocket {
    public:
	using HTTPServerSocket::HTTPServerSocket;

    protected:
	void get(bool) override { error(405); }
	void post(void) override {
	    status(200, "application/octet-stream");
	    reply(postdata, postsz);
	}
    };

    using ListenSocket = SimpleDispatchListenSocket<HTTPTest, EchoSocket>;

    bool listen(const Sockaddr &sa);
    void connect(const Sockaddr &sa, uint count, ulong delay, ulong tmt,
	ulong nap);
};

// blocking HTTPClient on its own thread
class SyncClient: public Thread {
public:
    SyncClient(const Sockaddr &a, ulong t, ulong n, ulong s): sa(a), tmt(t),
	nap(n), stagger(s) {}

protected:
    int onStart(void) override;

private:
    const Sockaddr &sa;
    ulong tmt, nap, stagger;
};

static HTTPTest *htp;
static atomic<uint> errs, ops;
static atomic loops(LLONG_MAX);
static volatile sig_atomic_t qflag;
alignas(64) static atomic<usec_t> usecs;

static inline bool loop_exit(void) {
    return loops.fetch_sub(1, memory_order_relaxed) <= 0 || qflag;
}

static ulong stagger(uint u, uint count, ulong delay, ulong nap) {
    return u * (!delay || count < nap / delay ? nap / count : delay);
}

// nullptr if the reply is the echoed data
static const tchar *check(uint sts, const char *data, ulong size) {
    if (sts != 200)
	return T("status");
    return size == dsz && !memcmp(data, dbuf, dsz) ? nullptr : T("data");
}

static void good(timing_t usec) {
    ::ops.fetch_add(1, memory_order_relaxed);
    ::usecs.fetch_add(usec, memory_order_relaxed);
    dtiming.add(T("post"), usec);
}

static void bad(const tstring &why) {
    errs.fetch_add(1, memory_order_relaxed);
    dtiming.add(T("error"), 0);
    dloge(T("client post="), why);
}

void HTTPTest::AsyncClient::done() {
    if (req.err()) {
	bad(req.errstr());
    } else if (const tchar *why = check(req.status(), req.data(),
	req.size())) {
	bad(why);
    } else {
	good(Timing::now() - begin);
	if (!nap)
	    go();
	else
	    timeout(go, nap);
	return;
    }
    timeout(go, max(nap, (ulong)RETRY));
}

void HTTPTest::AsyncClient::go() {
    if (loop_exit()) {
	erase();
	return;
    }
    begin = Timing::now();
    req.send(done, *this, client, T("POST"), URI, dbuf, dsz);
}

int SyncClient::onStart(void) {
    HTTPClient hc;

    msleep(stagger);
    hc.timeout((uint)tmt, (uint)tmt);
    while (!loop_exit()) {
	timing_t begin = Timing::now();

	if (hc.connect(sa, true, (uint)tmt) && hc.post(URI, dbuf, dsz)) {
	    if (const tchar *why = check(hc.status(), hc.data(), hc.size())) {
		bad(why);
	    } else {
		good(Timing::now() - begin);
		if (nap)
		    msleep(nap);
	    }
	} else {
	    bad(T("io"));
	    hc.close();
	    msleep(max(nap, (ulong)RETRY));
	}
    }
    return 0;
}

void HTTPTest::connect(const Sockaddr &sa, uint count, ulong delay, ulong tmt,
    ulong nap) {
    for (uint u = 0; u < count; u++) {
	AsyncClient *ac = new AsyncClient(*this, sa, tmt, nap);

	ac->detach();
	ac->start(stagger(u, count, delay, nap));
    }
}

bool HTTPTest::listen(const Sockaddr &sa) {
    ListenSocket *ls = new ListenSocket(*this);

    // detach before listen registers ls with the poller thread
    ls->detach();
    if (ls->listen(sa)) {
	return true;	// -V::773
    } else {
	delete ls;
	return false;
    }
}

static void signal_handler(int) {
    qflag = true;
    if (!errs && !ops)
	htp->stop();
}

int tmain(int argc, const tchar * const argv[]) {
    bool client = true, server = true, sync = false;
    ulong delay = DELAY, tmt = TIMEOUT, nap = 0;
    Config config;
    HTTPTest ht(config);
    int fd;
    const tchar *host = nullptr;
    int i;
    msec_t last, now;
    const tchar *path = T("echo this short test string as quickly as possible");
    Sockaddr sa;
    struct stat sbuf;
    uint sockets = 20, threads = 20;
    vector<unique_ptr<SyncClient>> syncs;

    // each request is logged at info
    dlog.level(Log::Note);

    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-b"))) {
	    sync = true;
	} else if (!tstricmp(argv[i], T("-c"))) {
	    server = false;
	} else if (!tstricmp(argv[i], T("-d")) && i + 1 < argc) {
	    delay = tstrtoul(argv[++i], nullptr, 10);
	} else if (!tstricmp(argv[i], T("-e")) && i + 1 < argc) {
	    sockets = (uint)tstrtoul(argv[++i], nullptr, 10);
	} else if (!tstricmp(argv[i], T("-h")) && i + 1 < argc) {
	    host = argv[++i];
	} else if (!tstricmp(argv[i], T("-l")) && i + 1 < argc) {
	    loops = atoi<llong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-p")) && i + 1 < argc) {
	    threads = (uint)tstrtoul(argv[++i], nullptr, 10);
	} else if (!tstricmp(argv[i], T("-s"))) {
	    client = false;
	} else if (!tstricmp(argv[i], T("-t")) && i + 1 < argc) {
	    tmt = tstrtoul(argv[++i], nullptr, 10);
	} else if (!tstricmp(argv[i], T("-v"))) {
	    dlog.level(dlog.level() < Log::Trace ? Log::Level(dlog.level() + 1) :
		Log::Trace);
	} else if (!tstricmp(argv[i], T("-w")) && i + 1 < argc) {
	    nap = tstrtoul(argv[++i], nullptr, 10);
	} else if (*argv[i] != '-') {
	    path = argv[i];
	} else {
	    tcerr << T("Usage: httptest\n")
		T("\t[-b]\t\tblocking HTTPClient threads, not AsyncHTTPClient\n")
		T("\t[-c]\n")
		T("\t[-d delay]\n")
		T("\t[-h host[:port]]\n")
		T("\t[-e clients]\n")
		T("\t[-l loops]\n")
		T("\t[-p threads]\n")
		T("\t[-s]\n")
		T("\t[-t timeout]\n")
		T("\t[-v*]\n")
		T("\t[-w wait]\n")
		T("\tdatafile | datastr") << endl;
	    return 1;
	}
    }
    if ((fd = open(tchartoachar(path), O_CLOEXEC | O_RDONLY)) == -1) {
	if (access(tchartoachar(path), 0) == 0) {
	    tcerr << T("httptest: unable to open ") << path << endl;
	    return 1;
	} else {
	    dsz = (uint)(tstrlen(path) * sizeof (tchar));
	    dbuf = new char[dsz];
	    memcpy(dbuf, path, dsz);
	}
    } else {
	if (fstat(fd, &sbuf) == -1) {
	    close(fd);
	    tcerr << T("httptest: unable to stat ") << path << endl;
	    return 1;
	}
	dsz = (uint)sbuf.st_size;
	dbuf = new char[dsz];
	if ((dsz = (uint)read(fd, dbuf, dsz)) == (uint)-1) {
	    delete [] dbuf;
	    dbuf = nullptr;
	    dsz = 0;
	    close(fd);
	    tcerr << T("httptest: unable to read ") << path << endl;
	    return 1;
	}
	close(fd);
    }
    if (!host)
	host = T("unix:./http.sock");
    if (!sa.set(host)) {
	tcerr << T("httptest: unknown host ") << host << endl;
	return 1;
    }
    if (sa.proto() != Sockaddr::UNIX && !sa.port())
	sa.port(8888);
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    struct rlimit rl;
    struct sigaction sig {};

    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur != rl.rlim_max) {
	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rl);
    }
    sig.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig, nullptr);
#endif
    if (dlog.level() >= Log::Debug)
	dlog.buffer(true);
    if (!ht.start(threads, 32 * 1024)) {
	tcerr << T("httptest: unable to start ") << host << endl;
	return 1;
    }
    if (server && !ht.listen(sa)) {
	ht.stop();
	return 1;
    }
    htp = &ht;
    if (client) {
	dlogi(Log::mod(T("http")), Log::cmd(T("httptest")), Log::kv(T("addr"),
	    sa.str()), Log::kv(T("data"), path));
	dlog.flush();
	tcout << T("Op/Sec\t\tUs/Op\tErr") << endl;
	if (sa.host() == T("*"))
	    sa.host(T("localhost"));
	if (sync) {
	    for (uint u = 0; u < sockets; u++) {
		syncs.push_back(make_unique<SyncClient>(sa, tmt, nap,
		    stagger(u, sockets, delay, nap)));
		if (!syncs.back()->start()) {
		    tcerr << T("httptest: unable to start thread") << endl;
		    qflag = true;
		    break;
		}
	    }
	} else {
	    ht.connect(sa, sockets, delay, tmt, nap);
	}
	Thread::MainThread.priority(10);
	last = Timing::now();
	do {
	    ulong cnt;

	    ops = errs = 0U;
	    usecs = 0U;
	    ht.waitForMain(1000);
	    now = Timing::now();
	    cnt = ops + errs;
	    tcout << (timing_t)cnt * 1000000 / (now - last) << T("\t\t") <<
		(usecs / (cnt ? cnt : 1)) << '\t' << errs << endl;
	    last = now;
	} while (loops.load() > 0 && !qflag);
	// the server and clients must outlive all in flight requests
	for (const auto &t : syncs)
	    t->wait();
	for (int n = 0; active && n < 100; n++)
	    msleep(50);
    } else {
	ht.waitForMain();
    }
    ht.stop();
    htp = nullptr;
    delete [] dbuf;
    tcout << dtiming.data() << endl;
    return qflag ? -1 : 0;
}
