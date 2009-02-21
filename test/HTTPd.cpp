#include "stdapi.h"
#include "HTTPServer.h"
#include "Log.h"

class HTTPDaemonSocket: public HTTPServerSocket {
public:
    HTTPDaemonSocket(Dispatcher &dspr, Socket &sock): HTTPServerSocket(dspr,
	sock) {}

    static void pause(bool p) { paused = p; }

protected:
    static bool paused;

    void exec(void) {
	if (paused)
	    return error(503);
	HTTPServerSocket::exec();
    }
};

class HTTPDaemon: public Daemon {
public:
    HTTPDaemon(const tchar *service, const tchar *name):
	Daemon(service, name), dspr(cfg) {}

protected:
    Dispatcher dspr;

    virtual void onPause(void) { HTTPDaemonSocket::pause(true); }
    virtual void onResume(void) { HTTPDaemonSocket::pause(false); }
    virtual int onStart(int argc, const tchar * const *argv);
    virtual void onStop(bool fast) { dspr.stop(); Daemon::onStop(fast); }
};

int HTTPDaemon::onStart(int argc, const tchar * const *argv) {
    int ret = Daemon::onStart(argc, argv);
    SimpleDispatchListenSocket<Dispatcher, HTTPDaemonSocket> *hsock;

    if (ret)
	return ret;
    if (!dspr.start()) {
	dlog << Log::Err << name << T(" unable to start") << endlog;
	return -1;
    }
    hsock = new SimpleDispatchListenSocket<Dispatcher, HTTPDaemonSocket>(dspr);
    if (!hsock->listen("*:8080")) {
	dspr.stop();
	dlog << Log::Info << "mod=" << HTTPDaemonSocket::section() <<
	    " cmd=listen addr=" << hsock->address().str() << ' ' <<
	    strerror(hsock->err()) << endlog;
    }
    setids();
    running();
    dspr.waitForMain();
    return 0;
}

bool HTTPDaemonSocket::paused = false;

int main(int argc, char **argv) {
    HTTPDaemon hd(T("httpd"), T("Test HTTP Server"));

    return hd.execute(argc, argv);
}
