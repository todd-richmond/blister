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
#include <random>
#include <signal.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif
#include "Config.h"
#include "Dispatch.h"
#include "Log.h"
#include "Timing.h"

const int DELAY = 20;
const int TIMEOUT = 10 * 1000;
const int MAXREAD = 8 * 1024;

class EchoTest: public Dispatcher {
public:
    using Dispatcher::Dispatcher;

    class EchoClientSocket: public DispatchClientSocket {
    public:
	EchoClientSocket(EchoTest &es, const Sockaddr &a, ulong t, ulong w):
	    DispatchClientSocket(es), sa(a), begin(0), in(0), out(0), tmt(t),
	    wait(w) {}

	void start(ulong msec) { timeout(start, msec); }

    protected:
	const Sockaddr &sa;
	timing_t begin;
	uint in, out;
	ulong tmt, wait;

	void onConnect(void) override;

	DSP_DECLARE(EchoClientSocket, input);
	DSP_DECLARE(EchoClientSocket, output);
	DSP_DECLARE(EchoClientSocket, repeat);
	DSP_DECLARE(EchoClientSocket, start);
    };

    class EchoServerSocket: public DispatchServerSocket {
    public:
	EchoServerSocket(Dispatcher &d, const Socket &sock):
	    DispatchServerSocket(d, sock), buf(nullptr), bufsz(0), in(0), out(0),
	    tmt(TIMEOUT) {}
	EchoServerSocket(const EchoServerSocket &) = delete;
	virtual ~EchoServerSocket() { delete [] buf; }

	void timeout(ulong timeout) { tmt = timeout; }
	static constexpr const tchar *section(void) { return T("echo"); }

	void start(void) override {
	    cork(false);
	    loopback(true);
	    nodelay(true);
	    readable(input, tmt);
	}

    private:
	char *buf;
	uint bufsz, in, out;
	ulong tmt;

	DSP_DECLARE(EchoServerSocket, input);
	DSP_DECLARE(EchoServerSocket, output);
    };

    class EchoListenSocket: public SimpleDispatchListenSocket<EchoTest,
	EchoServerSocket> {
    public:
	EchoListenSocket(EchoTest &d, ulong timeout):
	    SimpleDispatchListenSocket<EchoTest, EchoServerSocket>(d),
	    tmt(timeout) {}

	void start(EchoServerSocket &ess) { ess.timeout(tmt); ess.start(); }

    private:
	ulong tmt;
    };

    bool listen(const Sockaddr &sa, ulong timeout);
    void connect(const Sockaddr &sa, uint count, ulong delay, ulong tmt,
	ulong wait);
};

static char *dbuf;
static uint dsz;
static EchoTest *etp;
static atomic<uint> errs, ops;
static atomic loops(MAXLLONG);
static volatile bool qflag;
static atomic<usec_t> usecs;

static inline bool loop_exit(void) {
    return loops.fetch_sub(1, memory_order_relaxed) <= 0 || qflag;
}

void EchoTest::EchoClientSocket::onConnect(void) {
    if (error()) {
	if (loop_exit()) {
	    erase();
	} else {
	    errs.fetch_add(1, memory_order_relaxed);
	    dtiming.add(T("error"), 0);
	    dloge(T("client connect="), msg == DispatchTimeout ? T("timeout") :
		T("close"));
	    timeout(start, wait);
	}
    } else {
	cork(false);
	loopback(true);
	nodelay(true);
	begin = Timing::now();
	ready(output);
    }
}

void EchoTest::EchoClientSocket::input() {
    uint len;

    if (error() || ((len = (uint)read(dbuf + in, dsz - in)) == (uint)-1)) {
	if (loop_exit()) {
	    erase();
	} else {
	    errs.fetch_add(1, memory_order_relaxed);
	    dtiming.add(T("error"), 0);
	    dloge(T("client read="), msg == DispatchTimeout ? T("timeout") :
		T("close"));
	    timeout(start, wait);
	}
    } else if ((in += len) == dsz) {
	timing_t usec = Timing::now() - begin;

	if (loop_exit()) {
	    erase();
	} else {
	    ops.fetch_add(1, memory_order_relaxed);
	    usecs.fetch_add(usec, memory_order_relaxed);
	    dtiming.add(T("echo"), usec);
	    dlogt(T("client read="), len);
	    if (wait) {
		static thread_local mt19937 rng(random_device{}());

		timeout(repeat, wait + (wait < 2000 ? 0 :
		    uniform_int_distribution<uint>(0, 49)(rng)));
	    } else {
		in = out = 0;
		begin = Timing::now();
		ready(output);
	    }
	}
    } else if (loops.load(memory_order_relaxed) <= 0 || qflag) {
	erase();
    } else {
	dlogd(T("client partial read="), len);
	readable(input, tmt);
    }
}

void EchoTest::EchoClientSocket::output() {
    uint len;

    if (loops.load(memory_order_relaxed) <= 0 || qflag) {
	write("", 1);
	erase();
    } else if (error() || ((len = (uint)write(dbuf + out, dsz - out)) ==
	(uint)-1)) {
	if (loop_exit()) {
	    erase();
	} else {
	    errs.fetch_add(1, memory_order_relaxed);
	    dtiming.add(T("error"), 0);
	    dloge(T("client write="), msg == DispatchTimeout ? T("timeout") :
		T("close"));
	    timeout(start, wait);
	}
    } else if ((out += len) == dsz) {
	in = 0;
	dlogt(T("client write="), len);
	readable(input, tmt);
    } else {
	dlogd(T("client partial write="), len);
	writeable(output, tmt);
    }
}

void EchoTest::EchoClientSocket::repeat() {
    in = out = 0;
    begin = Timing::now();
    ready(output);
}

void EchoTest::EchoClientSocket::start() {
    in = out = 0;
    close();
    dlogd(T("connecting"));
    connect(sa, tmt);
}

#ifndef __clang__
#pragma GCC diagnostic ignored "-Wstack-usage="
#endif
void EchoTest::EchoServerSocket::input() {
    char tmp[MAXREAD];

    if (error() || ((in = (uint)read(tmp, sizeof (tmp))) == (uint)-1)) {
	if (loops.load() > 0 && !qflag)
	    dloge(T("server read="), msg == DispatchTimeout ? T("timeout") :
		T("close"));
	erase();
    } else if (in == 0) {
	readable(input);
    } else if (in == 1 && tmp[0] == '\0') {
	erase();
    } else if ((out = (uint)write(tmp, in)) == (uint)-1) {
	dloge(T("server write="), errstr());
	erase();
    } else if (in == out) {
	dlogt(T("server write="), out);
	readable(input);
    } else {
	dlogd(T("server partial write="), out);
	in -= out;
	if (bufsz < in) {
	    delete [] buf;
	    buf = new char[(size_t)in];
	    bufsz = in;
	}
	memcpy(buf, tmp + out, (size_t)in);
	out = 0;
	writeable(output);
    }
}

void EchoTest::EchoServerSocket::output() {
    uint len;

    if (error() || ((len = (uint)write(buf + out, in - out)) == (uint)-1)) {
	dloge(T("server write="), msg == DispatchTimeout ? T("timeout") :
	    T("close"));
	erase();
	return;
    }
    out += len;
    if (out == in) {
	dlogt(T("server write="), len);
	readable(input);
    } else {
	dlogd(T("server partial write="), len);
	writeable(output);
    }
}

void EchoTest::connect(const Sockaddr &sa, uint count, ulong delay, ulong tmt,
    ulong wait) {
    for (uint u = 0; u < count; u++) {
	EchoClientSocket *ecs = new EchoClientSocket(*this, sa, tmt, wait);

	ecs->detach();
	ecs->start(u * (!delay || count < wait / delay ? wait / count : delay));
    }
}

bool EchoTest::listen(const Sockaddr &sa, ulong timeout) {
    EchoListenSocket *els = new EchoListenSocket(*this, timeout);

    if (els->listen(sa)) {
	els->detach();
	return true;	// -V::773
    } else {
	delete els;
	return false;
    }
}

static void signal_handler(int) {
    qflag = true;
    if (!errs && !ops)
	etp->stop();
}

int tmain(int argc, const tchar * const argv[]) {
    bool client = true, server = true;
    ulong delay = DELAY, tmt = TIMEOUT, wait = 0;
    Config config;
    EchoTest et(config);
    int fd;
    const tchar *host = nullptr;
    int i;
    msec_t last, now;
    const tchar *path = T("echo this short test string as quickly as possible");
    Sockaddr sa;
    struct stat sbuf;
    uint sockets = 20, threads = 20;

    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-c"))) {
	    server = false;
	} else if (!tstricmp(argv[i], T("-d"))) {
	    delay = tstrtoul(argv[++i], NULL, 10);
	} else if (!tstricmp(argv[i], T("-e"))) {
	    sockets = (uint)tstrtoul(argv[++i], NULL, 10);
	} else if (!tstricmp(argv[i], T("-h"))) {
	    host = argv[++i];
	} else if (!tstricmp(argv[i], T("-l"))) {
	    loops = atoi<llong>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-p"))) {
	    threads = (uint)tstrtoul(argv[++i], NULL, 10);
	} else if (!tstricmp(argv[i], T("-s"))) {
	    client = false;
	} else if (!tstricmp(argv[i], T("-t"))) {
	    tmt = tstrtoul(argv[++i], NULL, 10);
	} else if (!tstricmp(argv[i], T("-v"))) {
	    dlog.level(dlog.level() >= Log::Debug ? Log::Trace : Log::Debug);
	} else if (!tstricmp(argv[i], T("-w"))) {
	    wait = tstrtoul(argv[++i], NULL, 10);
	} else if (*argv[i] != '-') {
	    path = argv[i];
	} else {
	    tcerr << T("Usage: echotest\n")
		T("\t[-c]\n")
		T("\t[-d delay]\n")
		T("\t[-h host[:port]]\n")
		T("\t[-e sockets]\n")
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
	    tcerr << T("echotest: unable to open ") << path << endl;
	    return 1;
	} else {
	    dsz = (uint)(tstrlen(path) * sizeof (tchar));
	    dbuf = new char[dsz];
	    memcpy(dbuf, path, dsz);
	}
    } else {
	(void)fstat(fd, &sbuf);
	dsz = (uint)sbuf.st_size;
	dbuf = new char[dsz];
	if ((dsz = (uint)read(fd, dbuf, dsz)) == (uint)-1) {
	    delete [] dbuf;
	    dbuf = nullptr;
	    dsz = 0;
	}
	close(fd);
    }
    if (!host)
	host = T("*:8888");
    if (!sa.set(host)) {
	tcerr << T("echo: unknown host ") << host << endl;
	return 1;
    }
    if (!sa.port())
	sa.port(8888);
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    struct rlimit rl;
    struct sigaction sig{};

    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur != rl.rlim_max) {
	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rl);
    }
    sig.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig, NULL);
#endif
    if (!et.start(threads, 32 * 1024)) {
	tcerr << T("echo: unable to start ") << host << endl;
	return 1;
    }
    if (server && !et.listen(sa, tmt))
	return 1;
    etp = &et;
    if (client) {
	dlogi(Log::mod(T("echo")), Log::cmd(T("echo")), Log::kv(T("addr"),
	    sa.str()), Log::kv(T("data"), path));
	tcout << T("Op/Sec\t\tUs/Op\tErr") << endl;
	if (sa.host() == T("*"))
	    sa.host(T("localhost"));
	et.connect(sa, sockets, delay, tmt, wait);
	Thread::MainThread.priority(10);
	last = Timing::now();
	do {
	    ulong cnt;

	    ops = errs = 0U;
	    usecs = 0U;
	    et.waitForMain(1000);
	    now = Timing::now();
	    cnt = ops + errs;
	    tcout << (timing_t)cnt * 1000000 / (now - last) << T("\t\t") <<
		(usecs / (cnt ? cnt : 1)) << '\t' << errs << endl;
	    last = now;
	} while (loops.load() > 0 && !qflag);
    } else {
	et.waitForMain();
    }
    et.stop();
    etp = nullptr;
    delete [] dbuf;
    tcout << dtiming.data() << endl;
    return qflag ? -1 : 0;
}
