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

static const tchar *NAME = "echo";

const int TIMEOUT = 10 * 1000;
const int MAXREAD = 16 * 1024;

class EchoTest: public Dispatcher {
public:
    EchoTest(): Dispatcher(cfg), els(NULL) {}
    virtual ~EchoTest() { delete els; }

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

    bool listen(const char *host, ulong timeout);
    void connect(const Sockaddr &a, ulong count, ulong delay, ulong timeout,
	ulong wait);

private:
    Config cfg;
    EchoListenSocket *els;
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
    dlogd("connecting");
    connect(addr, tmt);
    nagle(false);
}

void EchoTest::EchoClientSocket::output() {
    int len;

    if (!loops || qflag) {
	write("", 1);
	erase();
	return;
    }
    if (loops != -1)
	loops--;
    if (msg == Dispatcher::Timeout || msg == Dispatcher::Close) {
	errs++;
	dloge("client write", msg == Dispatcher::Timeout ? "timeout" : "close");
	timeout(start, wait);
	return;
    }
    if ((len = write(data + out, dsz - out)) < 0) {
	errs++;
	dloge("client write failed", len);
	timeout(start, wait);
	return;
    }
    out += len;
    if (out == dsz) {
	dlogt("client write", len);
	in = 0;
	readable(input, tmt);
    } else {
	dlogd("client partial write", len);
	writeable(output, tmt);
    }
}

void EchoTest::EchoClientSocket::input() {
    int len;

    if (msg == Dispatcher::Timeout || msg == Dispatcher::Close) {
	errs++;
	dloge("client read", msg == Dispatcher::Timeout ? "timeout" : "close");
	timeout(start, wait);
	return;
    }
    if ((len = read(data + in, dsz - in)) < 0) {
	errs++;
	dloge("client read failed", len);
	timeout(start, wait);
	return;
    }
    in += len;
    if (in == dsz) {
	ops++;
	usecs += uticks() - begin;
	dlogt("client read", len);
	timeout(repeat, wait + (wait < 2000 ? 0 : rand() % 50));
    } else {
	dlogd("client partial read", len);
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
	dloge("server read", msg == Dispatcher::Timeout ? "timeout" : "close");
	erase();
    } else if ((in = read(tmp, sizeof (tmp))) < 0) {
	dloge("server read failed:", err() == EOF ? "EOF" : strerror(err()));
	erase();
    } else if (in == 0) {
	readable(input);
    } else if (in == 1 && tmp[0] == '\0') {
	erase();
    } else if ((out = write(tmp, in)) < 0) {
	dloge("server write failed:", err() == EOF ? "EOF" : strerror(err()));
	erase();
    } else if (in == out) {
	dlogt("server write", out);
	readable(input);
    } else {
	dlogd("server partial write", out);
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
	dloge("server write", msg == Dispatcher::Timeout ? "timeout" : "close");
	erase();
	return;
    }
    if ((len = write(buf + out, in - out)) < 0) {
	dloge("server write failed:", err() == EOF ? "EOF" : strerror(err()));
	erase();
	return;
    }
    out += (uint)len;
    if (out != in) {
	dlogd("server partial write", len);
	writeable(output);
    } else {
	dlogt("server write", len);
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

bool EchoTest::listen(const char *host, ulong timeout) {
    els = new EchoListenSocket(*this, timeout);
    if (!els->listen(host)) {
	dlog << Log::Err << "mod=" << NAME << " cmd=listen addr=" <<
	    els->address().str() << ' ' << strerror(els->err()) << endlog;
	return false;
    }
    return true;
}

static void signal_handler(int) { qflag = true; }

int main(int argc, char *argv[]) {
    Sockaddr addr;
    bool client = true, server = true;
    EchoTest ec;
    int fd;
    const char *host = NULL;
    int i;
    const char *path = "echo this short test string as quickly as possible";
    msec_t last, now;
    string s;
    struct stat sbuf;
    ulong delay = 20, sockets = 20, tmt = TIMEOUT, wait = 0;

    if (argc == 1 || !strcmp(argv[1], "-?")) {
	cerr << "Usage: echotest [-c] [-d delay] [-h host[:port]] [-e sockets]\n"
	    "\t[-l loops] [-s] [-v*] [-t timeout] [-w wait] data | datafile" <<
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
	if (!stricmp(argv[i], "-c")) {
	    server = false;
	} else if (!stricmp(argv[i], "-d")) {
	    delay = (ulong)atol(argv[++i]);
	} else if (!stricmp(argv[i], "-e")) {
	    sockets = (uint)atol(argv[++i]);
	} else if (!stricmp(argv[i], "-h")) {
	    host = argv[++i];
	} else if (!stricmp(argv[i], "-l")) {
	    loops = atol(argv[++i]);
	} else if (!stricmp(argv[i], "-s")) {
	    client = false;
	} else if (!stricmp(argv[i], "-t")) {
	    tmt = (ulong)atol(argv[++i]);
	} else if (!stricmp(argv[i], "-v")) {
	    dlog.level(dlog.level() >= Log::Debug ? Log::Trace : Log::Debug);
	} else if (!stricmp(argv[i], "-w")) {
	    wait = (ulong)atol(argv[++i]);
	} else if (*argv[i] != '-') {
	    path = argv[i];
	}
    }
    if (access(path, 0) == 0) {
	if ((fd = open(path, O_RDONLY)) == -1 || fstat(fd, &sbuf)) {
	    cerr << "echotest: unable to open " << path << endl;
	    return 1;
	}
	dsz = (ulong)sbuf.st_size;
	data = new char[dsz];
	read(fd, data, dsz);
	close(fd);
    } else {
	dsz = strlen(path) + 1;
	data = new char[dsz];
	memcpy(data, path, dsz);
    }
    if (!host)
	host = "localhost:8888";
    if (!addr.set(host)) {
	cerr << "echo: unknown host " << host << endl;
	return 1;
    }
    ec.start(8, 32 * 1024);
    if (server && !ec.listen(host, tmt))
	return 1;
    if (client) {
	dlog << Log::Info << "echo " << host << " " << path << endlog;
	cout << "Op/Sec\t\tUs/Op\tErr" << endl;
	ec.connect(addr, sockets, delay, tmt, wait);
	Thread::priority(THREAD_HDL(), 10);
	last = uticks();
	do {
	    ops = errs = 0;
	    usecs = 0;
	    msleep(1000);
	    now = uticks();
	    cout << ((uint64)(ops + errs) * 1000000 / (now - last)) << "\t\t" <<
		(ulong)(usecs / (ops ? (uint)ops : (uint)errs + 1)) << '\t' <<
		errs << endl;
	    last = now;
	} while (!qflag && loops);
	msleep(1000);
    } else {
	while (!qflag)
	    msleep(1000);
    }
    ec.stop();
    delete [] data;
    return qflag ? -1 : 0;
}
