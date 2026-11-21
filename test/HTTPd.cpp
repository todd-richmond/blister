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
#include "MPHTTPServer.h"
#include "TLSSocket.h"

// -p port, -s for TLS; fills addr and loads the TLS context
static bool init(Config &cfg, int argc, const tchar * const *argv,
    tchar (&addr)[32]) {
    tstring err;

    tstrcpy(addr, T("*:8080"));
    for (int i = 1; i < argc; ++i) {
	if (!tstrcmp(argv[i], T("-p")) && i < argc - 1) {
	    tsprintf(addr, T("*:%u"), (uint)(ushort)ttoi(argv[++i]));
	    // after httpd.cfg loads, so -p wins over its host key
	    cfg.set(T("host"), addr, HTTPServerSocket::section());
	} else if (!tstrcmp(argv[i], T("-s"))) {
	    cfg.set(T("tls.enable"), true, HTTPServerSocket::section());
	}
    }
    if (!HTTPTLSServer::tlsctx.init(cfg, HTTPServerSocket::section(), err)) {
	dloge(Log::mod(T("httpd")), Log::error(err));
	return false;
    }
    return true;
}

/*
 * Files plus MPHTTPServer endpoints, GET /pid naming the worker and POST
 * replies with the body size and checksum, over TLS with -s.
 * httpd.worker.count > 1 starts prefork workers sharing the listen socket
 */
class HTTPDaemonSocket: public ShMemHTTPSocket {
public:
    using ShMemHTTPSocket::ShMemHTTPSocket;

protected:
    void get(bool head) override {
	static constexpr const char *mppaths[] = {
	    "/check", "/metrics", "/timing", "/version"
	};

	if (!strcmp(path, "/pid")) {
	    status(200, "text/plain", 0, nullptr, mpdspr().complete());
	    *this << getpid();
	    reply();
	} else if (ranges::any_of(mppaths, [this](const char *p) {
	    return !strcmp(path, p);
	})) {
	    MPHTTPSocket::get(head);
	} else {
	    // skip MPHTTPSocket's 404 to serve files
	    // NOLINTNEXTLINE(bugprone-parent-virtual-call)
	    HTTPServerSocket::get(head);
	}
    }
    bool onPost(const char *name, void *mem, ulong len) override {
	const auto *p = (const uchar *)mem;
	ulong sum = 0;

	for (ulong u = 0; u < len; ++u)
	    sum += p[u];
	status(200, "text/plain", 0, nullptr, mpdspr().complete());
	*this << name << ' ' << len << ' ' << sum;
	reply();
	return true;
    }
};

class HTTPDaemon: public MPHTTPDaemon {
public:
    HTTPDaemon(const tchar *svc_name, const tchar *display):
	MPHTTPDaemon(svc_name, display, mpd), mpd(cfg) {
	nworkers = 1;
    }

protected:
    MPHTTPDispatcher mpd;

    int command(const tchar *cmd, int argc, const tchar * const *argv)
	override {
	(void)argc; (void)argv;
	if (tstreq(cmd, T("help")) || tstreq(cmd, T("?")))
	    tcout << T("args:\t[start] [-p port] [-s]") << endl;
	return -1;
    }
    // watcher binds once; workers share or inherit its socket
    int onInit(int argc, const tchar * const *argv) override {
	tchar buf[32];

	return init(cfg, argc, argv, buf) && mpd.listen(new
	    SimpleMPHTTPListenSocket<MPHTTPDispatcher, HTTPDaemonSocket>(mpd),
	    buf) ? 0 : -1;
    }
};

int tmain(int argc, const tchar * const argv[]) {
    vector<const tchar *> av(argv, argv + argc);
    HTTPDaemon hd(T("httpd"), T("Test HTTP Server"));

    // no command or bare -p/-s: run in the console
    if (argc == 1 || !tstrcmp(argv[1], T("-p")) || !tstrcmp(argv[1], T("-s")))
	av.insert(av.begin() + 1, {T("console"), T("start")});
    return hd.execute((int)av.size(), av.data());
}
