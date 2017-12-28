/*
 * Copyright 2001-2017 Todd Richmond
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
#include "HTTPServer.h"
#include "Log.h"

class HTTPDaemonSocket: public HTTPServerSocket {
public:
    HTTPDaemonSocket(Dispatcher &d, Socket &s): HTTPServerSocket(d, s) {}

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
    HTTPDaemon(const tchar *svc_name, const tchar *display):
	Daemon(svc_name, display), dspr(cfg) {}

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
	dloge(name, Log::error( T("unable to start")));
	return -1;
    }
    hsock = new SimpleDispatchListenSocket<Dispatcher, HTTPDaemonSocket>(dspr);
    if (hsock->listen(T("*:8080"))) {
	hsock->detach();
    } else {
	delete hsock;
	dspr.stop();
        dspr.waitForMain();
        return -1;
    }
    setids();
    running();
    dspr.waitForMain();
    // cppcheck-suppress memleak
    return 0;
}

bool HTTPDaemonSocket::paused = false;

int tmain(int argc, tchar *argv[]) {
    HTTPDaemon hd(T("httpd"), T("Test HTTP Server"));

    return hd.execute(argc, argv);
}
