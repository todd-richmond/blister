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
