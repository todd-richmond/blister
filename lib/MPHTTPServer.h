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

#ifndef MPHTTPServer_h
#define MPHTTPServer_h

#include "TLSSocket.h"

/*
 * Prefork HTTP or HTTPS server. The Daemon watcher runs onInit() to bind the
 * listen socket and load shared state once, then forks worker.count workers
 * that all accept on it. A worker exits after worker.maxrequests and the
 * watcher replaces it, so leaks and engine state never build up. Windows
 * workers are spawned processes that inherit the socket and rerun onInit()
 */
class MPHTTPDaemon;
class MPHTTPListenSocket;

class BLISTERTLS MPHTTPDispatcher: public Dispatcher {
public:
    using Dispatcher::Dispatcher;

    bool acceptmany(void) const { return many; }
    // listen address, nullptr before listen()
    const Sockaddr *address(void) const;
    bool complete(void) const {
	uint m = maxreq;

	return retired || (m && totreq >= m);
    }
    uint connections(void) const { return curcon; }
    // binds without accepting: the watcher calls this from onInit()
    bool listen(MPHTTPListenSocket *ls, const tchar *host = T("*:8080"));
    virtual void metrics(PrometheusWriter &) const {}
    void refresh(bool recycle);
    uint remaining(void) const;
    // exit once idle, as after maxrequests
    void retire(void);
    bool start(void);

private:
    atomic<uint> curcon = 0, maxreq = 0, totreq = 0;
    atomic<bool> draining = false, quitting = false, retired = false;
#ifdef _WIN32
    MPHTTPDaemon *daemon = nullptr;
    socket_t insock = SOCK_INVALID;	// worker: inherited listen socket
#endif
    MPHTTPListenSocket *lsock = nullptr;
    bool many = true;
#ifdef _WIN32
    HANDLE timer = nullptr;
#endif

    void closed(void);
    void drain(void);
    void opened(void) { ++curcon; }
    void quit(void);
    void request(void) {
	if (++totreq == maxreq)
	    drain();
    }
#ifdef _WIN32
    static void __stdcall drained(void *d, BOOLEAN);
#endif

    friend class MPHTTPDaemon;
    friend class MPHTTPSocket;
};

class BLISTERTLS MPHTTPSocket: public HTTPTLSServer {
public:
    MPHTTPSocket(MPHTTPDispatcher &d, const Socket &sock);
    ~MPHTTPSocket() override;

protected:
    MPHTTPDispatcher &mpdspr(void) const { return (MPHTTPDispatcher &)dspr; }
    void exec(void) override;
    // /check, /metrics, /timing and /version
    void get(bool head) override;
    void metrics(PrometheusWriter &w) const override {
	HTTPServerSocket::metrics(w);
	mpdspr().metrics(w);
    }
};

/*
 * POST body from the request, a file named by X-File or a SysV shared memory
 * segment (file mapping name on Windows) named by X-Shm-Id and X-Shm-Size,
 * for large local transfers
 */
class BLISTERTLS ShMemHTTPSocket: public MPHTTPSocket {
public:
    using MPHTTPSocket::MPHTTPSocket;
    ~ShMemHTTPSocket() override { cleanup(true); }

protected:
    unique_ptr<char[]> out;		// reply buffer freed after reply
    void *shm = nullptr;
#ifdef _WIN32
    string shmname;
#else
    int shmid = -1;
#endif
    bool shmout = false;		// reply is in shm so keep it attached
    ulong shmsz = 0;

    void cleanup(bool force = false);
    virtual bool onPost(const char *name, void *mem, ulong len) = 0;
    void post(void) override;
    void replydone(DispatchObjCB cb) override;
};

class BLISTERTLS MPHTTPListenSocket: public DispatchListenSocket {
public:
    explicit MPHTTPListenSocket(MPHTTPDispatcher &d): DispatchListenSocket(d) {}

protected:
    // queued connections are left for other workers once complete()
    DSP_DECLARE(MPHTTPListenSocket, accepted);

    friend class MPHTTPDispatcher;
};

template<class D, class C>
class SimpleMPHTTPListenSocket: public MPHTTPListenSocket {
public:
    explicit SimpleMPHTTPListenSocket(D &d): MPHTTPListenSocket(d) {}

protected:
    void onAccept(Socket &sock) override {
	C *c = new(nothrow) C((D &)dspr, sock);

	if (c == nullptr) {
	    sock.close();
	} else {
	    c->detach();
	    c->start();
	}
    }
};

class BLISTERTLS MPHTTPDaemon: public Daemon {
public:
    MPHTTPDaemon(const tchar *svc, const tchar *display, MPHTTPDispatcher &d):
	Daemon(svc, display, true), dspr(d) {
	nworkers = 2;
#ifdef _WIN32
	d.daemon = this;
#endif
    }

protected:
    MPHTTPDispatcher &dspr;

    // GET /check on the listen socket, TLS when http.tls.enable is set
    bool check(Status status, tstring &err) override;
    // override onInit() to call dspr.listen() and load shared state
    void onPause(void) override;
    bool onRefresh(void) override;
    void onResume(void) override;
#ifdef _WIN32
    // passes the listen socket to workers
    void onSpawn(vector<HANDLE> &handles) override;
#endif
    int onStart(int argc, const tchar * const *argv) override;
    void onStop(bool fast) override;
    void onTimer(ulong timer) override;
    // in each worker before its dispatcher starts
    virtual void onWorker(void) {}

    friend class MPHTTPDispatcher;
};

#endif // MPHTTPServer_h
