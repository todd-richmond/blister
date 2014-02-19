/*
 * Copyright 2001-2010 Todd Richmond
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

static const tchar *NAME = T("echo");

const int TIMEOUT = 10 * 1000;
const int MAXREAD = 12 * 1024;

class EchoTest: public Dispatcher {
public:
    EchoTest(): Dispatcher(cfg) {}
    virtual ~EchoTest() {}

    class EchoClientSocket: public DispatchClientSocket {
    public:
	EchoClientSocket(EchoTest &es, const Sockaddr &a, ulong t, ulong w):
	    DispatchClientSocket(es), addr(a), tmt(t), wait(w) {}
	virtual ~EchoClientSocket() {}

	virtual void start(ulong msec) { timeout(start, msec); }

    protected:
	const Sockaddr &addr;
	usec_t begin;
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
	EchoServerSocket(Dispatcher &dspr, Socket &sock):
	    DispatchServerSocket(dspr, sock), buf(NULL), in(0), out(0) {}
	virtual ~EchoServerSocket() { delete [] buf; }

	void timeout(ulong timeout) { tmt = timeout; }
	static const tchar *section(void) { return NAME; }

	virtual void start(void) {
	    nodelay(true);
	    readable(input, tmt);
	}

    private:
	char *buf;
	int in, out;
	ulong tmt;

	DSP_DECLARE(EchoServerSocket, input);
	DSP_DECLARE(EchoServerSocket, output);
    };

    class EchoListenSocket: public SimpleDispatchListenSocket<EchoTest,
	EchoServerSocket> {
    public:
	EchoListenSocket(EchoTest &dspr, ulong timeout):
	    SimpleDispatchListenSocket<EchoTest, EchoServerSocket>(dspr),
	    tmt(timeout) {}

	void start(EchoServerSocket &ess) { ess.timeout(tmt); ess.start(); }

    private:
	ulong tmt;
    };

    bool listen(const tchar *host, ulong timeout);
    void connect(const Sockaddr &a, uint count, ulong delay, ulong timeout,
	ulong wait);

private:
    Config cfg;
};

static char *data;
static uint dsz;
static TSNumber<uint> errs, ops;
static TSNumber<long> loops(-1);
static volatile bool qflag;
static TSNumber<usec_t> usecs;

void EchoTest::EchoClientSocket::onConnect(void) {
    if (msg == DispatchTimeout || msg == DispatchClose) {
	++errs;
	dloge(T("client connect"), msg == DispatchTimeout ? T("timeout") :
	    T("close"));
	erase();
    } else {
	nodelay(true);
	begin = microticks();
	output();
    }
}

void EchoTest::EchoClientSocket::start() {
    close();
    out = 0;
    dlogd(T("connecting"));
    connect(addr, tmt);
}

void EchoTest::EchoClientSocket::input() {
    int len;

    if (msg == DispatchTimeout || msg == DispatchClose) {
	++errs;
	dloge(T("client read"), msg == DispatchTimeout ? T("timeout") :
	    T("close"));
	timeout(start, wait);
	dtiming.add(T("error"), 0);
	return;
    }
    if ((len = read(data + in, dsz - in)) < 0) {
	++errs;
	dloge(T("client read failed:"), errstr());
	timeout(start, wait);
	return;
    }
    in += len;
    if (in == dsz) {
	usec_t usec = microticks() - begin;

	++ops;
	usecs += usec;
	dtiming.add(T("echo"), usec);
	dlogt(T("client read"), len);
	timeout(repeat, wait + (wait < 2000 ? 0 : rand() % 50));
    } else {
	dlogd(T("client partial read"), len);
	readable(input, tmt);
    }
}

void EchoTest::EchoClientSocket::output() {
    int len;

    if (!loops || qflag) {
	write("", 1);
	erase();
	return;
    }
    if (msg == DispatchTimeout || msg == DispatchClose) {
	++errs;
	loops.test_and_decr();
	dloge(T("client write"), msg == DispatchTimeout ? T("timeout") :
	    T("close"));
	timeout(start, wait);
	return;
    }
    if ((len = write(data + out, dsz - out)) < 0) {
	++errs;
	loops.test_and_decr();
	dloge(T("client write failed:"), errstr());
	timeout(start, wait);
	return;
    }
    out += len;
    if (out == dsz) {
	loops.test_and_decr();
	dlogt(T("client write"), len);
	in = 0;
	readable(input, tmt);
    } else {
	dlogd(T("client partial write"), len);
	writeable(output, tmt);
    }
}

void EchoTest::EchoClientSocket::repeat() {
    msg = DispatchNone;
    out = 0;
    begin = microticks();
    output();
}

void EchoTest::EchoServerSocket::input() {
    char tmp[MAXREAD];

    if (msg == DispatchTimeout || msg == DispatchClose) {
	if (loops && !qflag)
	    dloge(T("server read"), msg == DispatchTimeout ? T("timeout") :
		T("close"));
	erase();
    } else if ((in = read(tmp, sizeof (tmp))) < 0) {
	if (loops && !qflag)
	    dloge(T("server read failed:"), errstr());
	erase();
    } else if (in == 0) {
	readable(input);
    } else if (in == 1 && tmp[0] == '\0') {
	erase();
    } else if ((out = write(tmp, in)) < 0) {
	dloge(T("server write failed:"), errstr());
	erase();
    } else if (in == out) {
	dlogt(T("server write"), out);
	readable(input);
    } else {
	dlogd(T("server partial write"), out);
	delete [] buf;
	buf = new char[in - out];
	memcpy(buf, tmp + out, in - out);
	out = 0;
	writeable(output);
    }
}

void EchoTest::EchoServerSocket::output() {
    int len;

    if (msg == DispatchTimeout || msg == DispatchClose) {
	dloge(T("server write"), msg == DispatchTimeout ? T("timeout") :
	    T("close"));
	erase();
	return;
    }
    if ((len = write((char *)buf + out, in - out)) < 0) {
	dloge(T("server write failed:"), errstr());
	erase();
	return;
    }
    out += (uint)len;
    if (out != in) {
	dlogd(T("server partial write"), len);
	writeable(output);
    } else {
	dlogt(T("server write"), len);
	readable(input);
    }
}

void EchoTest::connect(const Sockaddr &addr, uint count, ulong delay, ulong tmt,
    ulong wait) {
    for (uint u = 0; u < count; u++) {
	EchoClientSocket *ecs = new EchoClientSocket(*this, addr, tmt, wait);

	ecs->detach();
	ecs->start(u * (count < wait / delay ? wait / count : delay));
    }
}

bool EchoTest::listen(const tchar *host, ulong timeout) {
    EchoListenSocket *els = new EchoListenSocket(*this, timeout);

    if (!els->listen(host)) {
	dlog << Log::Err << T("mod=") << NAME << T(" cmd=listen addr=") <<
	    els->address().str() << ' ' << tstrerror(els->err()) << endlog;
	delete els;
	return false;
    }
    return true;
}

static void signal_handler(int) { qflag = true; }

int tmain(int argc, tchar *argv[]) {
    Sockaddr addr;
    bool client = true, server = true;
    EchoTest ec;
    int fd;
    const tchar *host = NULL;
    int i;
    const tchar *path = T("echo this short test string as quickly as possible");
    msec_t last, now;
    struct stat sbuf;
    ulong delay = 20, tmt = TIMEOUT, wait = 0;
    uint sockets = 20, threads = 20;

    if (argc == 1 || !tstrcmp(argv[1], T("-?"))) {
	tcerr << T("Usage: echotest [-c] [-d delay] [-h host[:port]] [-e sockets]\n")
	    T("\t[-l loops] [-p threads] [-s] [-v*] [-t timeout] [-w wait] data | datafile") <<
	    endl;
	return 1;
    }
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    struct rlimit rl;

    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur != rl.rlim_max) {
	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rl);
    }
#endif
    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-c"))) {
	    server = false;
	} else if (!tstricmp(argv[i], T("-d"))) {
	    delay = (ulong)ttol(argv[++i]);
	} else if (!tstricmp(argv[i], T("-e"))) {
	    sockets = (uint)ttol(argv[++i]);
	} else if (!tstricmp(argv[i], T("-h"))) {
	    host = argv[++i];
	} else if (!tstricmp(argv[i], T("-l"))) {
	    loops = ttol(argv[++i]);
	} else if (!tstricmp(argv[i], T("-p"))) {
	    threads = (uint)ttol(argv[++i]);
	} else if (!tstricmp(argv[i], T("-s"))) {
	    client = false;
	} else if (!tstricmp(argv[i], T("-t"))) {
	    tmt = (ulong)ttol(argv[++i]);
	} else if (!tstricmp(argv[i], T("-v"))) {
	    dlog.level(dlog.level() >= Log::Debug ? Log::Trace : Log::Debug);
	} else if (!tstricmp(argv[i], T("-w"))) {
	    wait = (ulong)ttol(argv[++i]);
	} else if (*argv[i] != '-') {
	    path = argv[i];
	}
    }
    if (access(tchartoachar(path), 0) == 0) {
	ZERO(sbuf);
	if ((fd = open(tchartoachar(path), O_RDONLY)) == -1 || fstat(fd,
	    &sbuf)) {
	    tcerr << T("echotest: unable to open ") << path << endl;
	    return 1;
	}
	dsz = (uint)sbuf.st_size;
	data = new char[dsz];
	read(fd, data, dsz);
	close(fd);
    } else {
	dsz = (uint)tstrlen(path);
	data = new char[(dsz + 1) * sizeof (tchar)];
	memcpy(data, path, dsz * sizeof (tchar));
    }
    if (!host)
	host = T("localhost:8888");
    if (!addr.set(host)) {
	tcerr << T("echo: unknown host ") << host << endl;
	return 1;
    }
    if (!ec.start(threads, 32 * 1024)) {
	tcerr << T("echo: unable to start ") << host << endl;
	return 1;
    }
    if (server && !ec.listen(host, tmt))
	return 1;
    if (client) {
	dlog << Log::Info << T("echo ") << host << T(" ") << path << endlog;
	tcout << T("Op/Sec\t\tUs/Op\tErr") << endl;
	ec.connect(addr, sockets, delay, tmt, wait);
	Thread::MainThread.priority(10);
	last = microticks();
	do {
	    ops = errs = 0;
	    usecs = 0;
	    msleep(1000);
	    now = microticks();
	    tcout << ((uint64)(ops + errs) * 1000000 / (now - last)) <<
		T("\t\t") << (ulong)(usecs / (ops ? (uint)ops : (uint)errs +
		1)) << '\t' << errs << endl;
	    last = now;
	} while (!qflag && loops);
    } else {
	while (!qflag)
	    msleep(1000);
    }
    ec.stop();
    delete [] data;
    tcout << dtiming.data() << endl;
    return qflag ? -1 : 0;
}
