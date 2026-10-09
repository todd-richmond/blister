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

/*
 * uvechotest is a libuv-based echo client/server with the same command
 * line interface as echotest, so the two can be run side by side to
 * compare Dispatcher's shared-reactor model against libuv's one-loop-
 * per-thread model on identical workloads. Each worker thread owns an
 * independent uv_loop_t; when acting as a server every worker binds its
 * own listening socket with SO_REUSEPORT so the kernel load-balances
 * accepts across threads, and when acting as a client the requested
 * socket count is spread evenly across the worker loops.
 */

#include "stdapi.h"
#include <fcntl.h>
#include <random>
#include <signal.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif
#include "Log.h"
#include "Socket.h"
#include "Thread.h"
#include "Timing.h"
#include <uv.h>

constexpr ulong DELAY = 20;
constexpr ulong TIMEOUT = 10UL * 1000;
constexpr size_t MAXREAD = 8UL * 1024;
constexpr uint STACKSZ = 32 * 1024;
constexpr int BACKLOG = 128;

static char *dbuf;
static uint dsz;

static atomic<uint> gerrs, gops;
static atomic loops(LLONG_MAX);
static atomic qflag = false;
alignas(64) static atomic<usec_t> gusecs;

// consumes one unit of the shared loop budget; every completed round trip
// and every failed attempt counts as one unit, matching echotest's
// loop_exit() so -l compares apples to apples between the two tools
static bool loop_exit(void) {
    return loops.fetch_sub(1, memory_order_relaxed) <= 0 ||
	qflag.load(memory_order_relaxed);
}

// TCP and UNIX domain sockets are different libuv handle types that share the
// uv_stream_t prefix, so the stream calls take either one
union Handle {
    uv_tcp_t tcp;
    uv_pipe_t pipe;
};

static bool unixsock;		// -h unix:/path uses pipes instead of TCP
static int unixfd = -1;		// listening fd duplicated into every worker

struct Worker;

struct EchoClient: nocopy {
    Handle tcp;
    uv_timer_t timer;
    uv_connect_t connreq;
    uv_write_t writereq;
    uv_buf_t wbuf;
    Worker *worker;
    char *rbuf;
    uint in;
    timing_t begin;
    bool done;		// permanently stopped; loop budget is exhausted
    bool errorHandled;	// dedups a timed-out connect racing a late callback
    bool closingTcp;	// tcp close currently in flight
    bool tcpOpen;	// tcp has been uv_tcp_init'ed and not yet uv_close'd
    bool writePending;	// a uv_write on writereq hasn't completed yet
    bool nextRoundQueued;	// next round wants to start once it does

    explicit EchoClient(Worker *w): worker(w), rbuf(new char[dsz + MAXREAD]),
	in(0), begin(0), done(false), errorHandled(false), closingTcp(false),
	tcpOpen(false), writePending(false), nextRoundQueued(false) {}
    ~EchoClient() { delete [] rbuf; }
};

struct EchoServerConn: nocopy {
    Handle tcp;
    uv_write_t writereq;
    char *buf;
    uint writeLen;

    EchoServerConn(): buf(nullptr), writeLen(0) {}
    ~EchoServerConn() { delete [] buf; }
};

struct Worker {
    uv_loop_t loop {};
    uv_async_t stopper {};
    Handle listener {};
    Thread thread;
    vector<EchoClient *> clients;
    Sockaddr bindAddr;
    Sockaddr connectAddr;
    ulong tmt = TIMEOUT;
    ulong wait = 0;
    ulong delay = DELAY;
    uint base = 0;		// global stagger index of first client
    bool doServer = false;
    bool doClient = false;
};

static void startClient(EchoClient *c);

static void onStartTimer(uv_timer_t *t) {
    startClient((EchoClient *)t->data);
}

static void requestCloseTcp(EchoClient *c) {
    if (c->closingTcp || !c->tcpOpen)
	return;
    c->closingTcp = true;
    c->tcpOpen = false;
    uv_read_stop((uv_stream_t *)&c->tcp);
    uv_close((uv_handle_t *)&c->tcp, [](uv_handle_t *h) {
	EchoClient *cl = (EchoClient *)h->data;

	cl->closingTcp = false;
	if (!cl->done)
	    uv_timer_start(&cl->timer, onStartTimer, cl->worker->wait, 0);
    });
}

// like echotest, tell a connected server the test is over so it closes quietly
static void beginTeardown(EchoClient *c) {
    if (c->done)
	return;
    c->done = true;
    if (c->tcpOpen && !c->errorHandled &&
	uv_is_writable((uv_stream_t *)&c->tcp)) {
	uv_buf_t mark = uv_buf_init((char *)"", 1);

	uv_try_write((uv_stream_t *)&c->tcp, &mark, 1);
    }
    uv_timer_stop(&c->timer);
    uv_close((uv_handle_t *)&c->timer, [](uv_handle_t *) {});
    requestCloseTcp(c);
}

static void onIoError(EchoClient *c, const tchar *what, bool isTimeout =
    false) {
    if (c->done || c->errorHandled)
	return;
    c->errorHandled = true;
    gerrs.fetch_add(1, memory_order_relaxed);
    dtiming.add(T("error"), 0);
    dloge(what, isTimeout ? T("timeout") : T("close"));
    uv_timer_stop(&c->timer);
    if (loop_exit())
	beginTeardown(c);
    else
	requestCloseTcp(c);
}

static void onConnectTimeout(uv_timer_t *t) {
    onIoError((EchoClient *)t->data, T("client connect="), true);
}

// cppcheck-suppress constParameterCallback
static void allocClient(uv_handle_t *h, size_t, uv_buf_t *buf) {    // NOSONAR
    const EchoClient *c = (const EchoClient *)h->data;

    buf->base = c->rbuf + c->in;
    // read past the reply like a normal server so short reads skip re-arming
    buf->len = dsz + MAXREAD - c->in;
}

static void writeClient(EchoClient *c) {
    if (UNLIKELY(loops.load(memory_order_relaxed) <= 0 ||
	qflag.load(memory_order_relaxed))) {
	beginTeardown(c);
	return;
    }
    c->begin = Timing::now();
    c->writePending = true;
    c->wbuf = uv_buf_init(dbuf, (unsigned int)dsz);
    c->writereq.data = c;
    uv_write(&c->writereq, (uv_stream_t *)&c->tcp, &c->wbuf, 1,
	[](uv_write_t *req, int status) {
	EchoClient *cl = (EchoClient *)req->data;

	cl->writePending = false;
	if (status < 0) {
	    onIoError(cl, T("client write="));
	    return;
	}
	dlogt(T("client write="), dsz);
	if (cl->nextRoundQueued) {
	    cl->nextRoundQueued = false;
	    writeClient(cl);
	}
    });
}

// the echo response for a round can arrive and be processed before this
// same round's write completion callback has been dispatched by libuv, so
// starting the next round must wait for writePending to clear rather than
// reissuing a write on the still in-flight writereq
static void startNextRound(EchoClient *c) {
    if (c->writePending)
	c->nextRoundQueued = true;
    else
	writeClient(c);
}

static void onRepeatTimer(uv_timer_t *t) {
    startNextRound((EchoClient *)t->data);
}

static void onClientRead(uv_stream_t *s, ssize_t nread, const uv_buf_t *) {
    EchoClient *c = (EchoClient *)s->data;

    if (nread < 0) {
	onIoError(c, T("client read="));
	return;
    }
    if (nread == 0)
	return;
    c->in += (uint)nread;
    if (c->in < dsz) {
	dlogd(T("client partial read="), (uint)nread);
	return;
    }

    timing_t usec = Timing::now() - c->begin;

    c->in = 0;
    if (loop_exit()) {
	beginTeardown(c);
	return;
    }
    gops.fetch_add(1, memory_order_relaxed);
    gusecs.fetch_add(usec, memory_order_relaxed);
    dtiming.add(T("echo"), usec);
    dlogt(T("client read="), dsz);
    if (c->worker->wait) {
	static thread_local mt19937 rng(random_device {}());
	ulong wait = c->worker->wait;
	ulong jitter = wait < 2000 ? 0 :
	    uniform_int_distribution<ulong>(0, 49)(rng);

	uv_timer_start(&c->timer, onRepeatTimer, wait + jitter, 0);
    } else {
	startNextRound(c);
    }
}

static void onClientConnect(uv_connect_t *req, int status) {
    EchoClient *c = (EchoClient *)req->data;

    if (status < 0) {
	onIoError(c, T("client connect="));
	return;
    }
    if (c->errorHandled)	// superseded by a connect timeout already
	return;
    uv_timer_stop(&c->timer);
    if (!unixsock)
	uv_tcp_nodelay(&c->tcp.tcp, 1);
    uv_read_start((uv_stream_t *)&c->tcp, allocClient, onClientRead);
    writeClient(c);
}

// a leading NUL is a Linux abstract name that Sockaddr pads to the whole
// sun_path so match the length bound by the server
static void connectUnix(EchoClient *c, const Sockaddr &addr) {
    const char *name = ((const sockaddr_un *)addr)->sun_path;
    size_t len = *name ? strlen(name) : sizeof (sockaddr_un::sun_path);

    uv_pipe_connect2(&c->connreq, &c->tcp.pipe, name, len, 0,
	onClientConnect);
}

static void startClient(EchoClient *c) {
    Worker &w = *c->worker;

    c->in = 0;
    c->errorHandled = false;
    c->writePending = false;
    c->nextRoundQueued = false;
    if (unixsock)
	uv_pipe_init(&w.loop, &c->tcp.pipe, 0);
    else
	uv_tcp_init(&w.loop, &c->tcp.tcp);
    c->tcpOpen = true;
    c->tcp.tcp.data = c;
    c->connreq.data = c;
    dlogd(T("connecting"));
    uv_timer_start(&c->timer, onConnectTimeout, w.tmt, 0);
    if (unixsock)
	connectUnix(c, w.connectAddr);
    else
	uv_tcp_connect(&c->connreq, &c->tcp.tcp, w.connectAddr,
	    onClientConnect);
}

static void onServerConnClosed(uv_handle_t *h) {
    delete (EchoServerConn *)h->data;
}

static void closeServerConn(EchoServerConn *sc) {
    uv_read_stop((uv_stream_t *)&sc->tcp);
    uv_close((uv_handle_t *)&sc->tcp, onServerConnClosed);
}

static void allocServer(uv_handle_t *h, size_t, uv_buf_t *buf) {
    EchoServerConn *sc = (EchoServerConn *)h->data;

    if (!sc->buf)
	sc->buf = new char[MAXREAD];
    buf->base = sc->buf;
    buf->len = MAXREAD;
}

static void onServerRead(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    EchoServerConn *sc = (EchoServerConn *)s->data;

    if (nread < 0) {
	if (loops.load(memory_order_relaxed) > 0 &&
	    !qflag.load(memory_order_relaxed))
	    dloge(T("server read="), T("close"));
	closeServerConn(sc);
	return;
    }
    if (nread == 0)
	return;
    if (nread == 1 && buf->base[0] == '\0') {	// client end-of-test marker
	closeServerConn(sc);
	return;
    }

    uv_buf_t wbuf = uv_buf_init(buf->base, (unsigned int)nread);

    uv_read_stop(s);
    sc->writeLen = (uint)nread;
    sc->writereq.data = sc;
    uv_write(&sc->writereq, s, &wbuf, 1, [](uv_write_t *req, int status) {
	EchoServerConn *conn = (EchoServerConn *)req->data;

	if (status < 0) {
	    dloge(T("server write="), achartotchar(uv_strerror(status)));
	    closeServerConn(conn);
	} else {
	    dlogt(T("server write="), conn->writeLen);
	    uv_read_start((uv_stream_t *)&conn->tcp, allocServer, onServerRead);
	}
    });
}

static void onNewConnection(uv_stream_t *server, int status) {
    if (status < 0)
	return;

    auto *w = (Worker *)server->data;
    auto *sc = new EchoServerConn;

    if (unixsock)
	uv_pipe_init(&w->loop, &sc->tcp.pipe, 0);
    else
	uv_tcp_init(&w->loop, &sc->tcp.tcp);
    sc->tcp.tcp.data = sc;
    if (uv_accept(server, (uv_stream_t *)&sc->tcp) == 0) {
	if (!unixsock)
	    uv_tcp_nodelay(&sc->tcp.tcp, 1);
	uv_read_start((uv_stream_t *)&sc->tcp, allocServer, onServerRead);
    } else {
	uv_close((uv_handle_t *)&sc->tcp, onServerConnClosed);
    }
}

static void onStop(uv_async_t *a) {
    Worker *w = (Worker *)a->data;

    if (w->doServer)
	uv_close((uv_handle_t *)&w->listener, nullptr);
    for (EchoClient *c : w->clients)
	beginTeardown(c);
    uv_close((uv_handle_t *)a, nullptr);
}

// UV_TCP_REUSEPORT is only implemented by libuv on Linux, DragonFlyBSD,
// FreeBSD 12+, Solaris and AIX; on macOS uv_tcp_bind() returns UV_ENOTSUP,
// which the unchecked original code let fall through to an unbound listen()
// that autobinds an ephemeral port, so every client connect to the intended
// port was refused. Bind natively with SO_REUSEPORT instead so every worker
// still gets a duplicate listening socket load-balanced by the kernel.
#ifndef _WIN32
static void bindListener(Handle *listener, const Sockaddr &addr) {
    int fd = (int)socket(addr.family(), SOCK_STREAM, 0);
    int one = 1;

    if (fd == -1) {
	dloge(T("server socket="), achartotchar(strerror(errno)));
	return;
    }
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof (one));
    if (::bind(fd, addr, addr.size()) == -1) {
	dloge(T("server bind="), achartotchar(strerror(errno)));
	close(fd);
	return;
    }
    uv_tcp_open(&listener->tcp, fd);
}
#else
static void bindListener(Handle *listener, const Sockaddr &addr) {
    uv_tcp_bind(&listener->tcp, addr, 0);
}
#endif

static int runWorker(void *arg) {
    Worker *w = (Worker *)arg;

    uv_loop_init(&w->loop);
    uv_async_init(&w->loop, &w->stopper, onStop);
    w->stopper.data = w;

    if (w->doServer) {
	if (unixsock) {
	    uv_pipe_init(&w->loop, &w->listener.pipe, 0);
	    uv_pipe_open(&w->listener.pipe, dup(unixfd));
	} else {
	    uv_tcp_init(&w->loop, &w->listener.tcp);
	    bindListener(&w->listener, w->bindAddr);
	}
	w->listener.tcp.data = w;
	uv_listen((uv_stream_t *)&w->listener, BACKLOG, onNewConnection);
    }
    for (size_t i = 0; i < w->clients.size(); i++) {
	EchoClient *c = w->clients[i];
	ulong ms = (w->base + i) * w->delay;

	uv_timer_init(&w->loop, &c->timer);
	c->timer.data = c;
	uv_timer_start(&c->timer, onStartTimer, ms, 0);
    }

    uv_run(&w->loop, UV_RUN_DEFAULT);

    for (EchoClient *c : w->clients)
	delete c;
    uv_loop_close(&w->loop);
    return 0;
}

static void signalHandler(int) {
    qflag.store(true, memory_order_relaxed);
}

int tmain(int argc, const tchar * const argv[]) {
    bool client = true, server = true;
    ulong delay = DELAY, tmt = TIMEOUT, wait = 0;
    uint sockets = 20, threads = 20;
    const tchar *host = nullptr;
    const tchar *path = T("echo this short test string as quickly as possible");
    int fd, i;
    struct stat sbuf;

    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-c"))) {
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
	    dlog.level(dlog.level() >= Log::Debug ? Log::Trace : Log::Debug);
	} else if (!tstricmp(argv[i], T("-w")) && i + 1 < argc) {
	    wait = tstrtoul(argv[++i], nullptr, 10);
	} else if (*argv[i] != '-') {
	    path = argv[i];
	} else {
	    tcerr << T("Usage: uvechotest\n")
		T("\t[-c]\n")
		T("\t[-d delay]\n")
		T("\t[-h host[:port]]\n")
		T("\t[-e sockets]\n")
		T("\t[-l loops]\n")
		T("\t[-p threads]\n")
		T("\t[-s]\n")
		T("\t[-t timeout]\n")
		T("\t[-v]\n")
		T("\t[-w wait]\n")
		T("\tdatafile | datastr") << endl;
	    return 1;
	}
    }
    if (!threads)
	threads = 1;
    if ((fd = open(tchartoachar(path), O_CLOEXEC | O_RDONLY)) == -1) {
	if (access(tchartoachar(path), 0) == 0) {
	    tcerr << T("uvechotest: unable to open ") << path << endl;
	    return 1;
	} else {
	    dsz = (uint)(tstrlen(path) * sizeof (tchar));
	    dbuf = new char[dsz];
	    memcpy(dbuf, path, dsz);
	}
    } else {
	if (fstat(fd, &sbuf) == -1) {
	    close(fd);
	    tcerr << T("uvechotest: unable to stat ") << path << endl;
	    return 1;
	}
	dsz = (uint)sbuf.st_size;
	dbuf = new char[dsz];
	if ((dsz = (uint)read(fd, dbuf, dsz)) == (uint)-1) {
	    delete [] dbuf;
	    dbuf = nullptr;
	    dsz = 0;
	    close(fd);
	    tcerr << T("uvechotest: unable to read ") << path << endl;
	    return 1;
	}
	close(fd);
    }
    if (!host)
	host = T("unix:./socket");

    Sockaddr bindAddr;

    if (!bindAddr.set(host)) {
	tcerr << T("uvechotest: unknown host ") << host << endl;
	delete [] dbuf;
	return 1;
    }
    if (!bindAddr.port())
	bindAddr.port(8888);

    Sockaddr connectAddr(bindAddr);

    if (connectAddr.host() == T("*"))
	connectAddr.host(T("localhost"));

    signal(SIGINT, signalHandler);
#ifndef _WIN32
    unixsock = bindAddr.family() == AF_UNIX;
    if (unixsock && server) {
	sockaddr_un *sun = (sockaddr_un *)(const sockaddr_un *)bindAddr;

	unixfd = (int)socket(AF_UNIX, SOCK_STREAM, 0);
	if (sun->sun_path[0])
	    unlink(sun->sun_path);
	if (unixfd == -1 || ::bind(unixfd, bindAddr, bindAddr.size()) == -1) {
	    tcerr << T("uvechotest: unable to bind ") << host << endl;
	    delete [] dbuf;
	    return 1;
	}
    }
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

    vector<Worker> workers(threads);
    uint base = 0;

    for (uint u = 0; u < threads; u++) {
	Worker &w = workers[u];
	uint count = sockets / threads + (u < sockets % threads ? 1 : 0);

	w.doServer = server;
	w.doClient = client;
	w.tmt = tmt;
	w.wait = wait;
	w.delay = delay;
	w.base = base;
	w.bindAddr = bindAddr;
	w.connectAddr = connectAddr;
	if (client) {
	    for (uint j = 0; j < count; j++)
		w.clients.push_back(new EchoClient(&w));
	}
	base += count;
    }
    for (Worker &w : workers)
	w.thread.start(runWorker, &w, STACKSZ);

    if (client) {
	dlogi(Log::mod(T("uvecho")), Log::cmd(T("echo")), Log::kv(T("addr"),
	    connectAddr.str()), Log::kv(T("data"), path));
	dlog.flush();
	tcout << T("Op/Sec\t\tUs/Op\tErr") << endl;

	timing_t last = Timing::now();

	do {
	    msleep(1000);

	    ullong curOps = gops.exchange(0, memory_order_relaxed);
	    ullong curErrs = gerrs.exchange(0, memory_order_relaxed);
	    ullong curUsecs = gusecs.exchange(0, memory_order_relaxed);
	    timing_t now = Timing::now();
	    ullong cnt = curOps + curErrs;

	    tcout << (cnt * 1000000 / (now - last)) << T("\t\t") <<
		(curUsecs / (cnt ? cnt : 1)) << '\t' << curErrs << endl;
	    last = now;
	} while (loops.load(memory_order_relaxed) > 0 &&
	    !qflag.load(memory_order_relaxed));
    } else {
	while (!qflag.load(memory_order_relaxed))
	    msleep(200);
    }

    for (Worker &w : workers)
	uv_async_send(&w.stopper);
    for (Worker &w : workers)
	w.thread.wait();

    if (unixfd != -1) {
	close(unixfd);
	if (((const sockaddr_un *)bindAddr)->sun_path[0])
	    unlink(bindAddr.path());
    }
    delete [] dbuf;
    tcout << dtiming.data() << endl;
    return qflag.load(memory_order_relaxed) ? -1 : 0;
}
