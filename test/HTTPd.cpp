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
#include "Log.h"
#include "TLSSocket.h"

class HTTPDaemonSocket: public HTTPTLSServer {
public:
    using HTTPTLSServer::HTTPTLSServer;

    static void pause(bool p) { paused = p; }

protected:
    static inline atomic paused = false;

    void exec(void) override {
	if (paused) {
	    error(503);
	    return;
	}
	HTTPTLSServer::exec();
    }
};

class HTTPDaemon: public Daemon {
public:
    HTTPDaemon(const tchar *svc_name, const tchar *display):
	Daemon(svc_name, display), dspr(cfg) {}

protected:
    Dispatcher dspr;

    void onPause(void) override {
	HTTPDaemonSocket::pause(true);
	Daemon::onPause();
    }
    void onResume(void) override {
	HTTPDaemonSocket::pause(false);
	Daemon::onResume();
    }
    int onStart(int argc, const tchar * const *argv) override;
    void onStop(bool fast) override { dspr.stop(); Daemon::onStop(fast); }
};

int HTTPDaemon::onStart(int argc, const tchar * const *argv) {
    tchar buf[32];
    tstring err;
    ushort port = 8080;
    int ret = Daemon::onStart(argc, argv);

    if (ret)
	return ret;
    for (int i = 1; i < argc; ++i) {
	if (!tstrcmp(argv[i], T("-p")) && i < argc - 1)
	    port = (ushort)ttoi(argv[++i]);
	else if (!tstrcmp(argv[i], T("-s")))
	    cfg.set(T("tls.enable"), true, HTTPServerSocket::section());
    }
    if (!HTTPTLSServer::tlsctx.init(cfg, HTTPServerSocket::section(),
	err)) {
	dloge(name, Log::error(err));
	return -1;
    }
    tsprintf(buf, T("*:%u"), (uint)port);
    if (!dspr.start()) {
	dloge(name, Log::error(T("unable to start")));
	return -1;
    }

    auto *hsock = new SimpleDispatchListenSocket<Dispatcher,
	HTTPDaemonSocket>(dspr);

    if (!hsock->listen(buf)) {
	delete hsock;
	dspr.stop();
	return -1;
    }
    setids();
    running();
    dspr.waitForMain();
    // cppcheck-suppress memleak
    return 0;	//-V773
}

int tmain(int argc, const tchar * const argv[]) {
    HTTPDaemon hd(T("httpd"), T("Test HTTP Server"));

    return hd.execute(argc, argv);
}
