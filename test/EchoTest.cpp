/*
 * Copyright 2001 - 2009 Todd Richmond
 *
 * This file is part of Blister - a light weight, scalable, high performance
 * C++ server infrastructure.
 *
 * Blister is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or any later version.
 *
 * Blister is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Blister. If not, see <http://www.gnu.org/licenses/>.
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
const int MAXREAD = 16 * 1024;

class EchoTest: public Dispatcher {
public:
    EchoTest(): Dispatcher(cfg) {}
    virtual ~EchoTest() {}

    class EchoClientSocket: public DispatchClientSocket {
    public:
	EchoClientSocket(EchoTest &es, const Sockaddr &a, ulong t, ulong w):
	    DispatchClientSocket(es), addr(a), tmt(t), wait(w) {}
	virtual ~EchoClientSocket() {}

	virtual void start(uint tmt) { timeout(start, tmt); }

    protected:
	const Sockaddr &addr;
	usec_t begin;
	uint in, out, tmt, wait;

	virtual void onConnect(void) { begin = uticks(); output(); }

	DSP_DECLARE(EchoClientSocket, input);
	DSP_DECLARE(EchoClientSocket, output);
	DSP_DECLARE(EchoClientSocket, repeat);
	DSP_DECLARE(EchoClientSocket, start);
    };

    class EchoServerSocket: public DispatchServerSocket {
    public:
	EchoServerSocket(Dispatcher &dspr, Socket &sock):
	    DispatchServerSocket(dspr, sock), buf(NULL) {}
	virtual ~EchoServerSocket() { delete [] buf; }

	void timeout(ulong timeout) { tmt = timeout; }
	static const tchar *section(void) { return NAME; }

	virtual void start(void) {
	    nagle(false);
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
	    SimpleDispatchListenSocket<EchoTest, EchoServerSocket>(dspr, SOCK_STREAM, false),
	    tmt(timeout) {}

	void start(EchoServerSocket &ess) { ess.timeout(tmt); ess.start(); }

    private:
	ulong tmt;
    };

    bool listen(const tchar *host, ulong timeout);
    void connect(const Sockaddr &a, ulong count, ulong delay, ulong timeout,
	ulong wait);

private:
    Config cfg;
};

static int loops = -1;
static char *data;
static ulong dsz;
static volatile bool qflag;
static TSNumber<uint> ops, errs;
static TSNumber<usec_t> usecs;

void EchoTest::EchoClientSocket::start() {
    close();
    out = 0;
    dlogd(T("connecting"));
    connect(addr, tmt);
    nagle(false);
}

void EchoTest::EchoClientSocket::output() {
    int len;

    if (!loops || qflag) {
	write(T(""), 1);
	erase();
	return;
    }
    if (loops != -1)
	loops--;
    if (msg == Dispatcher::Timeout || msg == Dispatcher::Close) {
	errs++;
	dloge(T("client write"), msg == Dispatcher::Timeout ? T("timeout") :
	    T("close"));
	timeout(start, wait);
	return;
    }
    if ((len = write(data + out, dsz - out)) < 0) {
	errs++;
	dloge(T("client write failed"), len);
	timeout(start, wait);
	return;
    }
    out += len;
    if (out == dsz) {
	dlogt(T("client write"), len);
	in = 0;
	readable(input, tmt);
    } else {
	dlogd(T("client partial write"), len);
	writeable(output, tmt);
    }
}

void EchoTest::EchoClientSocket::input() {
    int len;

    if (msg == Dispatcher::Timeout || msg == Dispatcher::Close) {
	errs++;
	dloge(T("client read"), msg == Dispatcher::Timeout ? T("timeout") :
	    T("close"));
	timeout(start, wait);
	dtiming.add(T("error"), 0);
	return;
    }
    if ((len = read(data + in, dsz - in)) < 0) {
	errs++;
	dloge(T("client read failed"), len);
	timeout(start, wait);
	return;
    }
    in += len;
    if (in == dsz) {
	ops++;
	usecs += uticks() - begin;
	dtiming.add(T("echo"), uticks() - begin);
	dlogt(T("client read"), len);
	timeout(repeat, wait + (wait < 2000 ? 0 : rand() % 50));
    } else {
	dlogd(T("client partial read"), len);
	readable(input, tmt);
    }
}

void EchoTest::EchoClientSocket::repeat() {
    msg = Dispatcher::Nomsg;
    out = 0;
    begin = uticks();
    output();
}

void EchoTest::EchoServerSocket::input() {
    char tmp[MAXREAD];

    if (msg == Dispatcher::Timeout || msg == Dispatcher::Close) {
	dloge(T("server read"), msg == Dispatcher::Timeout ? T("timeout") :
	    T("close"));
	erase();
    } else if ((in = read(tmp, sizeof (tmp))) < 0) {
	dloge(T("server read failed:"), err() == EOF ? T("EOF") :
	    tstrerror(err()));
	erase();
    } else if (in == 0) {
	readable(input);
    } else if (in == 1 && tmp[0] == '\0') {
	erase();
    } else if ((out = write(tmp, in)) < 0) {
	dloge(T("server write failed:"), err() == EOF ? T("EOF") :
	    tstrerror(err()));
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

    if (msg == Dispatcher::Timeout || msg == Dispatcher::Close) {
	dloge(T("server write"), msg == Dispatcher::Timeout ? T("timeout") :
	    T("close"));
	erase();
	return;
    }
    if ((len = write((char *)buf + out, in - out)) < 0) {
	dloge(T("server write failed:"), err() == EOF ? T("EOF") :
	    tstrerror(err()));
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

void EchoTest::connect(const Sockaddr &addr, ulong count, ulong delay,
    ulong tmt, ulong wait) {
    for (uint u = 0; u < count; u++) {
	EchoClientSocket *ec = new EchoClientSocket(*this, addr, tmt, wait);

	ec->start(u * (count < wait / delay ? wait / count : delay));
    }
}

bool EchoTest::listen(const tchar *host, ulong timeout) {
    EchoListenSocket *els = new EchoListenSocket(*this, timeout);

    if (!els->listen(host)) {
	dlog << Log::Err << T("mod=") << NAME << T(" cmd=listen addr=") <<
	    els->address().str() << ' ' << tstrerror(els->err()) << endlog;
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
    tstring s;
    struct stat sbuf;
    ulong delay = 20, sockets = 20, tmt = TIMEOUT, wait = 0;

    if (argc == 1 || !tstrcmp(argv[1], T("-?"))) {
	tcerr << T("Usage: echotest [-c] [-d delay] [-h host[:port]] [-e sockets]\n")
	    T("\t[-l loops] [-s] [-v*] [-t timeout] [-w wait] data | datafile") <<
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
	dsz = (ulong)sbuf.st_size;
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
    ec.start(8, 32 * 1024);
    if (server && !ec.listen(host, tmt))
	return 1;
    if (client) {
	dlog << Log::Info << T("echo ") << host << T(" ") << path << endlog;
	tcout << T("Op/Sec\t\tUs/Op\tErr") << endl;
	ec.connect(addr, sockets, delay, tmt, wait);
	Thread::priority(THREAD_HDL(), 10);
	last = uticks();
	do {
	    ops = errs = 0;
	    usecs = 0;
	    msleep(1000);
	    now = uticks();
	    tcout << ((uint64)(ops + errs) * 1000000 / (now - last)) <<
		T("\t\t") << (ulong)(usecs / (ops ? (uint)ops : (uint)errs +
		1)) << '\t' << errs << endl;
	    last = now;
	} while (!qflag && loops);
	msleep(1000);
    } else {
	while (!qflag)
	    msleep(1000);
    }
    ec.stop();
    delete [] data;
    tcout << dtiming.data() << endl;
    return qflag ? -1 : 0;
}
