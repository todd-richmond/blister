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
    bool error_handled;	// dedups a timed-out connect racing a late callback
    bool closing_tcp;	// tcp close currently in flight
    bool tcp_open;	// tcp has been uv_tcp_init'ed and not yet uv_close'd
    bool write_pending;	// a uv_write on writereq hasn't completed yet
    bool next_round_queued;	// next round wants to start once it does

    explicit EchoClient(Worker *w): worker(w), rbuf(new char[dsz + MAXREAD]),
	in(0), begin(0), done(false), error_handled(false), closing_tcp(false),
	tcp_open(false), write_pending(false), next_round_queued(false) {}
    ~EchoClient() { delete [] rbuf; }
};

struct EchoServerConn: nocopy {
    Handle tcp;
    uv_write_t writereq;
    char *buf;
    uint write_len;

    EchoServerConn(): buf(nullptr), write_len(0) {}
    ~EchoServerConn() { delete [] buf; }
};

struct Worker {
    uv_loop_t loop {};
    uv_async_t stopper {};
    Handle listener {};
    Thread thread;
    vector<EchoClient *> clients;
    Sockaddr bind_addr;
    Sockaddr connect_addr;
    ulong tmt = TIMEOUT;
    ulong wait = 0;
    ulong delay = DELAY;
    uint base = 0;		// global stagger index of first client
    bool do_server = false;
    bool do_client = false;
};

static void start_client(EchoClient *c);

static void start_timer(uv_timer_t *t) {
    start_client((EchoClient *)t->data);
}

static void request_close_tcp(EchoClient *c) {
    if (c->closing_tcp || !c->tcp_open)
	return;
    c->closing_tcp = true;
    c->tcp_open = false;
    uv_read_stop((uv_stream_t *)&c->tcp);
    uv_close((uv_handle_t *)&c->tcp, [](uv_handle_t *h) {
	EchoClient *cl = (EchoClient *)h->data;

	cl->closing_tcp = false;
	if (!cl->done)
	    uv_timer_start(&cl->timer, start_timer, cl->worker->wait, 0);
    });
}

// like echotest, tell a connected server the test is over so it closes quietly
static void begin_teardown(EchoClient *c) {
    if (c->done)
	return;
    c->done = true;
    if (c->tcp_open && !c->error_handled &&
	uv_is_writable((uv_stream_t *)&c->tcp)) {
	uv_buf_t mark = uv_buf_init((char *)"", 1);

	uv_try_write((uv_stream_t *)&c->tcp, &mark, 1);
    }
    uv_timer_stop(&c->timer);
    uv_close((uv_handle_t *)&c->timer, [](uv_handle_t *) {});
    request_close_tcp(c);
}

static void on_io_error(EchoClient *c, const tchar *what, bool is_timeout =
    false) {
    if (c->done || c->error_handled)
	return;
    c->error_handled = true;
    gerrs.fetch_add(1, memory_order_relaxed);
    dtiming.add(T("error"), 0);
    dloge(what, is_timeout ? T("timeout") : T("close"));
    uv_timer_stop(&c->timer);
    if (loop_exit())
	begin_teardown(c);
    else
	request_close_tcp(c);
}

static void on_connect_timeout(uv_timer_t *t) {
    on_io_error((EchoClient *)t->data, T("client connect="), true);
}

// cppcheck-suppress constParameterCallback
static void alloc_client(uv_handle_t *h, size_t, uv_buf_t *buf) {    // NOSONAR
    const EchoClient *c = (const EchoClient *)h->data;

    buf->base = c->rbuf + c->in;
    // read past the reply like a normal server so short reads skip re-arming
    buf->len = dsz + MAXREAD - c->in;
}

static void write_client(EchoClient *c) {
    if (UNLIKELY(loops.load(memory_order_relaxed) <= 0 ||
	qflag.load(memory_order_relaxed))) {
	begin_teardown(c);
	return;
    }
    c->begin = Timing::now();
    c->write_pending = true;
    c->wbuf = uv_buf_init(dbuf, (unsigned int)dsz);
    c->writereq.data = c;
    uv_write(&c->writereq, (uv_stream_t *)&c->tcp, &c->wbuf, 1,
	[](uv_write_t *req, int status) {
	EchoClient *cl = (EchoClient *)req->data;

	cl->write_pending = false;
	if (status < 0) {
	    on_io_error(cl, T("client write="));
	    return;
	}
	dlogt(T("client write="), dsz);
	if (cl->next_round_queued) {
	    cl->next_round_queued = false;
	    write_client(cl);
	}
    });
}

// the echo response for a round can arrive and be processed before this
// same round's write completion callback has been dispatched by libuv, so
// starting the next round must wait for write_pending to clear rather than
// reissuing a write on the still in-flight writereq
static void start_next_round(EchoClient *c) {
    if (c->write_pending)
	c->next_round_queued = true;
    else
	write_client(c);
}

static void on_repeat_timer(uv_timer_t *t) {
    start_next_round((EchoClient *)t->data);
}

static void on_client_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *) {
    EchoClient *c = (EchoClient *)s->data;

    if (nread < 0) {
	on_io_error(c, T("client read="));
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
	begin_teardown(c);
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

	uv_timer_start(&c->timer, on_repeat_timer, wait + jitter, 0);
    } else {
	start_next_round(c);
    }
}

static void on_client_connect(uv_connect_t *req, int status) {
    EchoClient *c = (EchoClient *)req->data;

    if (status < 0) {
	on_io_error(c, T("client connect="));
	return;
    }
    if (c->error_handled)	// superseded by a connect timeout already
	return;
    uv_timer_stop(&c->timer);
    if (!unixsock)
	uv_tcp_nodelay(&c->tcp.tcp, 1);
    uv_read_start((uv_stream_t *)&c->tcp, alloc_client, on_client_read);
    write_client(c);
}

// a leading NUL is a Linux abstract name that Sockaddr pads to the whole
// sun_path so match the length bound by the server
static void connect_unix(EchoClient *c, const Sockaddr &addr) {
    const char *name = ((const sockaddr_un *)addr)->sun_path;
    size_t len = *name ? strlen(name) : sizeof (sockaddr_un::sun_path);

    uv_pipe_connect2(&c->connreq, &c->tcp.pipe, name, len, 0,
	on_client_connect);
}

static void start_client(EchoClient *c) {
    Worker &w = *c->worker;

    c->in = 0;
    c->error_handled = false;
    c->write_pending = false;
    c->next_round_queued = false;
    if (unixsock)
	uv_pipe_init(&w.loop, &c->tcp.pipe, 0);
    else
	uv_tcp_init(&w.loop, &c->tcp.tcp);
    c->tcp_open = true;
    c->tcp.tcp.data = c;
    c->connreq.data = c;
    dlogd(T("connecting"));
    uv_timer_start(&c->timer, on_connect_timeout, w.tmt, 0);
    if (unixsock)
	connect_unix(c, w.connect_addr);
    else
	uv_tcp_connect(&c->connreq, &c->tcp.tcp, w.connect_addr,
	    on_client_connect);
}

static void on_server_conn_closed(uv_handle_t *h) {
    delete (EchoServerConn *)h->data;
}

static void close_server_conn(EchoServerConn *sc) {
    uv_read_stop((uv_stream_t *)&sc->tcp);
    uv_close((uv_handle_t *)&sc->tcp, on_server_conn_closed);
}

static void alloc_server(uv_handle_t *h, size_t, uv_buf_t *buf) {
    EchoServerConn *sc = (EchoServerConn *)h->data;

    if (!sc->buf)
	sc->buf = new char[MAXREAD];
    buf->base = sc->buf;
    buf->len = MAXREAD;
}

static void on_server_read(uv_stream_t *s, ssize_t nread, const uv_buf_t *buf) {
    EchoServerConn *sc = (EchoServerConn *)s->data;

    if (nread < 0) {
	if (loops.load(memory_order_relaxed) > 0 &&
	    !qflag.load(memory_order_relaxed))
	    dloge(T("server read="), T("close"));
	close_server_conn(sc);
	return;
    }
    if (nread == 0)
	return;
    if (nread == 1 && buf->base[0] == '\0') {	// client end-of-test marker
	close_server_conn(sc);
	return;
    }

    uv_buf_t wbuf = uv_buf_init(buf->base, (unsigned int)nread);

    uv_read_stop(s);
    sc->write_len = (uint)nread;
    sc->writereq.data = sc;
    uv_write(&sc->writereq, s, &wbuf, 1, [](uv_write_t *req, int status) {
	EchoServerConn *conn = (EchoServerConn *)req->data;

	if (status < 0) {
	    dloge(T("server write="), achartotchar(uv_strerror(status)));
	    close_server_conn(conn);
	} else {
	    dlogt(T("server write="), conn->write_len);
	    uv_read_start((uv_stream_t *)&conn->tcp, alloc_server, on_server_read);
	}
    });
}

static void on_new_connection(uv_stream_t *server, int status) {
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
	uv_read_start((uv_stream_t *)&sc->tcp, alloc_server, on_server_read);
    } else {
	uv_close((uv_handle_t *)&sc->tcp, on_server_conn_closed);
    }
}

static void on_stop(uv_async_t *a) {
    Worker *w = (Worker *)a->data;

    if (w->do_server)
	uv_close((uv_handle_t *)&w->listener, nullptr);
    for (EchoClient *c : w->clients)
	begin_teardown(c);
    uv_close((uv_handle_t *)a, nullptr);
}

// UV_TCP_REUSEPORT is only implemented by libuv on Linux, DragonFlyBSD,
// FreeBSD 12+, Solaris and AIX; on macOS uv_tcp_bind() returns UV_ENOTSUP,
// which the unchecked original code let fall through to an unbound listen()
// that autobinds an ephemeral port, so every client connect to the intended
// port was refused. Bind natively with SO_REUSEPORT instead so every worker
// still gets a duplicate listening socket load-balanced by the kernel.
#ifndef _WIN32
static void bind_listener(Handle *listener, const Sockaddr &addr) {
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
static void bind_listener(Handle *listener, const Sockaddr &addr) {
    uv_tcp_bind(&listener->tcp, addr, 0);
}
#endif

static int run_worker(void *arg) {
    Worker *w = (Worker *)arg;

    uv_loop_init(&w->loop);
    uv_async_init(&w->loop, &w->stopper, on_stop);
    w->stopper.data = w;

    if (w->do_server) {
	if (unixsock) {
	    uv_pipe_init(&w->loop, &w->listener.pipe, 0);
	    uv_pipe_open(&w->listener.pipe, dup(unixfd));
	} else {
	    uv_tcp_init(&w->loop, &w->listener.tcp);
	    bind_listener(&w->listener, w->bind_addr);
	}
	w->listener.tcp.data = w;
	uv_listen((uv_stream_t *)&w->listener, BACKLOG, on_new_connection);
    }
    for (size_t i = 0; i < w->clients.size(); i++) {
	EchoClient *c = w->clients[i];
	ulong ms = (w->base + i) * w->delay;

	uv_timer_init(&w->loop, &c->timer);
	c->timer.data = c;
	uv_timer_start(&c->timer, start_timer, ms, 0);
    }

    uv_run(&w->loop, UV_RUN_DEFAULT);

    for (EchoClient *c : w->clients)
	delete c;
    uv_loop_close(&w->loop);
    return 0;
}

static void signal_handler(int) {
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

    Sockaddr bind_addr;

    if (!bind_addr.set(host)) {
	tcerr << T("uvechotest: unknown host ") << host << endl;
	delete [] dbuf;
	return 1;
    }
    if (!bind_addr.port())
	bind_addr.port(8888);

    Sockaddr connect_addr(bind_addr);

    if (connect_addr.host() == T("*"))
	connect_addr.host(T("localhost"));

    signal(SIGINT, signal_handler);
#ifndef _WIN32
    unixsock = bind_addr.family() == AF_UNIX;
    if (unixsock && server) {
	const sockaddr_un *sun = bind_addr;

	unixfd = (int)socket(AF_UNIX, SOCK_STREAM, 0);
	if (sun->sun_path[0])
	    unlink(sun->sun_path);
	if (unixfd == -1 || ::bind(unixfd, bind_addr, bind_addr.size()) == -1) {
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

	w.do_server = server;
	w.do_client = client;
	w.tmt = tmt;
	w.wait = wait;
	w.delay = delay;
	w.base = base;
	w.bind_addr = bind_addr;
	w.connect_addr = connect_addr;
	if (client) {
	    for (uint j = 0; j < count; j++)
		w.clients.push_back(new EchoClient(&w));
	}
	base += count;
    }
    for (Worker &w : workers)
	w.thread.start(run_worker, &w, STACKSZ);

    if (client) {
	dlogi(Log::mod(T("uvecho")), Log::cmd(T("echo")), Log::kv(T("addr"),
	    connect_addr.str()), Log::kv(T("data"), path));
	dlog.flush();
	tcout << T("Op/Sec\t\tUs/Op\tErr") << endl;

	timing_t last = Timing::now();

	do {
	    msleep(1000);

	    ullong cur_ops = gops.exchange(0, memory_order_relaxed);
	    ullong cur_errs = gerrs.exchange(0, memory_order_relaxed);
	    ullong cur_usecs = gusecs.exchange(0, memory_order_relaxed);
	    timing_t now = Timing::now();
	    ullong cnt = cur_ops + cur_errs;

	    tcout << (cnt * 1000000 / (now - last)) << T("\t\t") <<
		(cur_usecs / (cnt ? cnt : 1)) << '\t' << cur_errs << endl;
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
	if (((const sockaddr_un *)bind_addr)->sun_path[0])
	    unlink(bind_addr.path());
    }
    delete [] dbuf;
    tcout << dtiming.data() << endl;
    return qflag.load(memory_order_relaxed) ? -1 : 0;
}
