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

#include "stdapi.h"
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif
#include "Config.h"
#include "Dispatch.h"
#include "Log.h"
#include "Timing.h"

const int TIMEOUT = 10 * 1000;
const int MAXREAD = 8 * 1024;

class EchoTest: public Dispatcher {
public:
    EchoTest(): Dispatcher(cfg) {}

    class EchoClientSocket: public DispatchClientSocket {
    public:
	EchoClientSocket(EchoTest &es, const Sockaddr &a, ulong t, ulong w):
	    DispatchClientSocket(es), sa(a), begin(0), in(0), out(0), tmt(t),
	    wait(w) {}

	virtual void start(ulong msec) { timeout(start, msec); }

    protected:
	const Sockaddr &sa;
	timing_t begin;
	uint in, out;
	ulong tmt, wait;

	virtual void onConnect(void);

	DSP_DECLARE(EchoClientSocket, input);
	DSP_DECLARE(EchoClientSocket, output);
	DSP_DECLARE(EchoClientSocket, repeat);
	DSP_DECLARE(EchoClientSocket, start);
    };

    class EchoServerSocket: public DispatchServerSocket {
    public:
	EchoServerSocket(Dispatcher &d, Socket &sock):
	    DispatchServerSocket(d, sock), buf(NULL), in(0), out(0),
	    tmt(TIMEOUT) {}
	virtual ~EchoServerSocket() { delete [] buf; }

	void timeout(ulong timeout) { tmt = timeout; }
	static const tchar *section(void) { return T("echo"); }

	virtual void start(void) {
	    cork(false);
	    nodelay(true);
	    readable(input, tmt);
	}

    private:
	char *buf;
	uint in, out;
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

private:
    Config cfg;
};

static char *dbuf;
static uint dsz;
static TSNumber<uint> errs, ops;
static TSNumber<long long> loops(MAXLLONG);
static volatile bool qflag;
static TSNumber<usec_t> usecs;

static inline bool loop_exit(void) { return --loops < 0 || qflag; }

void EchoTest::EchoClientSocket::onConnect(void) {
    if (error()) {
	if (loop_exit()) {
	    erase();
	} else {
	    ++errs;
	    dtiming.add(T("error"), 0);
	    dloge(T("client connect"), msg == DispatchTimeout ? T("timeout") :
		T("close"));
	    timeout(start, wait);
	}
    } else {
	cork(false);
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
	    ++errs;
	    dtiming.add(T("error"), 0);
	    dloge(T("client read"), msg == DispatchTimeout ? T("timeout") :
		T("close"));
	    timeout(start, wait);
	}
    } else if ((in += len) == dsz) {
	timing_t usec = Timing::now() - begin;

	if (loop_exit()) {
	    erase();
	} else {
	    ++ops;
	    usecs += usec;
	    dtiming.add(T("echo"), usec);
	    dlogt(T("client read"), len);
	    // coverity[dont_call : FALSE ]
	    timeout(repeat, wait + (wait < 2000 ? 0 : (uint)rand() % 50));
	}
    } else if (loops.load() <= 0 || qflag) {
	erase();
    } else {
	dlogd(T("client partial read"), len);
	readable(input, tmt);
    }
}

void EchoTest::EchoClientSocket::output() {
    uint len;

    if (loops.load() <= 0 || qflag) {
	write("", 1);
	erase();
    } else if (error() || ((len = (uint)write(dbuf + out, dsz - out)) ==
	(uint)-1)) {
	if (loop_exit()) {
	    erase();
	} else {
	    ++errs;
	    dtiming.add(T("error"), 0);
	    dloge(T("client write"), msg == DispatchTimeout ? T("timeout") :
		T("close"));
	    timeout(start, wait);
	}
    } else if ((out += len) == dsz) {
	in = 0;
	dlogt(T("client write"), len);
	readable(input, tmt);
    } else {
	dlogd(T("client partial write"), len);
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

#pragma GCC diagnostic ignored "-Wstack-usage="
void EchoTest::EchoServerSocket::input() {
    uint oldin = in;
    char tmp[MAXREAD];

    if (error() || ((in = (uint)read(tmp, sizeof (tmp))) == (uint)-1)) {
	if (loops.load() > 0 && !qflag)
	    dloge(T("server read"), msg == DispatchTimeout ? T("timeout") :
		T("close"));
	erase();
    } else if (in == 0) {
	readable(input);
    } else if (in == 1 && tmp[0] == '\0') {
	erase();
    } else if ((out = (uint)write(tmp, in)) == (uint)-1) {
	dloge(T("server write failed:"), errstr());
	erase();
    } else if (in == out) {
	dlogt(T("server write"), out);
	readable(input);
    } else {
	dlogd(T("server partial write"), out);
	in -= out;
	if (oldin < in) {
	    delete [] buf;
	    buf = new char[(size_t)in];
	}
	memcpy(buf, tmp + out, (size_t)in);
	out = 0;
	writeable(output);
    }
}

void EchoTest::EchoServerSocket::output() {
    uint len;

    if (error() || ((len = (uint)write(buf + out, (uint)(in - out))) ==
	(uint)-1)) {
	dloge(T("server write"), msg == DispatchTimeout ? T("timeout") :
	    T("close"));
	erase();
	return;
    }
    out += len;
    if (out == in) {
	dlogt(T("server write"), len);
	readable(input);
    } else {
	dlogd(T("server partial write"), len);
	writeable(output);
    }
}

void EchoTest::connect(const Sockaddr &sa, uint count, ulong delay, ulong tmt,
    ulong wait) {
    for (uint u = 0; u < count; u++) {
	EchoClientSocket *ecs = new EchoClientSocket(*this, sa, tmt, wait);

	ecs->detach();
	ecs->start(u * (count < wait / delay ? wait / count : delay));
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

static EchoTest et;

static void signal_handler(int) {
    qflag = true;
    if (!errs && !ops)
	et.stop();
}

int tmain(int argc, const tchar * const argv[]) {
    bool client = true, server = true;
    ulong delay = 20, tmt = TIMEOUT, wait = 0;
    int fd;
    const tchar *host = NULL;
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
	    loops = tstrtol(argv[++i], NULL, 10);
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
		T("\t[-v*]\n")
		T("\t[-t timeout]\n")
		T("\t[-w wait]\n")
		T("\tdatafile | datastr") << endl;
	    return 1;
	}
    }
    if ((fd = open(tchartoachar(path), O_RDONLY)) == -1) {
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
	dsz = (uint)read(fd, dbuf, dsz);
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
    struct sigaction sig;

    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur != rl.rlim_max) {
	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rl);
    }
    ZERO(sig);
    sig.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig, NULL);
#endif
    if (!et.start(threads, 32 * 1024)) {
	tcerr << T("echo: unable to start ") << host << endl;
	return 1;
    }
    if (server && !et.listen(sa, tmt))
	return 1;
    if (client) {
	dlogi(Log::mod(T("echo")), Log::cmd(T("echo")), Log::kv(T("addr"),
	    sa.str()), Log::kv(T("data"), path));
	tcout << T("Op/Sec\t\tUs/Op\tErr") << endl;
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
    delete [] dbuf;
    tcout << dtiming.data() << endl;
    return qflag ? -1 : 0;
}
