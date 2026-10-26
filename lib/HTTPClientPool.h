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

#ifndef HTTPClientPool_h
#define HTTPClientPool_h

#include "HTTPClient.h"

/*
 * Pool of AsyncHTTPClient connections to weighted servers. Failed servers back
 * off and their requests retry elsewhere. It must outlive its Requests, which
 * must not be destroyed while in flight. Config keys under the refresh()
 * prefix: servers = host:port[*weight],... minconnections, pathprefix,
 * connecttimeout and iotimeout (msec)
 */
class BLISTER HTTPClientPool: nocopy {
    // a server and its connections - Requests share it so it outlives removal
    struct Conn {
	Conn(const Sockaddr &sa, double w, tstring_view prefix):
	    addr(sa), path_prefix(prefix), weight(w) {}

	bool active = true;
	Sockaddr addr;
	usec_t backoff = 0, down_until = 0;
	vector<unique_ptr<AsyncHTTPClient>> clients;
	uint errors = 0;
	tstring path_prefix;
	double weight;
    };

public:
    class BLISTER Request: public AsyncHTTPClient::Request {
    public:
	Request(Dispatcher &d, HTTPClientPool &p): AsyncHTTPClient::Request(d),
	    pool(p) {}
	Request(DispatchObj &parent, HTTPClientPool &p):
	    AsyncHTTPClient::Request(parent), pool(p) {}

	// address of the server that last handled the request
	const Sockaddr &addr(void) const;
	// the server is working so clear its error backoff
	void markgood(void);
	// resend after a bad response - false if out of tries
	bool retry(DispatchObjCB cb, DispatchObj &co);
	// data must remain valid until the callback is called
	void send(DispatchObjCB cb, DispatchObj &co, const tchar *op,
	    const tchar *path, const tchar *headers = nullptr,
	    const void *data = nullptr, ulong datasz = 0);

    private:
	void send(DispatchObjCB, DispatchObj &, AsyncHTTPClient &,
	    const tchar *, const tchar *, const void *, ulong) = delete;

	static constexpr uint maxtries = 5;

	bool dispatch(void);
	void penalize(void);
	bool resend(void) override;

	shared_ptr<Conn> conn;
	tstring hdrs, op, path;
	uint ntries = 0;
	HTTPClientPool &pool;
	Sockaddr saddr;
	DispatchObj *ucaller = nullptr;
	DispatchObjCB ucb = nullptr;
	const void *udata = nullptr;
	ulong udatasz = 0;
    };

    explicit HTTPClientPool(Dispatcher &d): dsp(d) {}

    uint getnumreqs(void) const { return numreqs; }
    // pooltype is unused and kept for source compatibility
    bool refresh(const tchar *cfgprefix, const tchar *pooltype = nullptr);
    // add or reactivate the listed servers and deactivate the rest
    bool refreshservers(tstring_view list, const tchar *path_prefix = nullptr);
    void status(tostream &out, uint indent, const tchar *name) const;
    void timingdata(tostream &out, bool sort_by_key = false) const {
	out << timing.data(sort_by_key);
    }

private:
    void addConn(const Sockaddr &addr, double weight, tstring_view prefix);
    AsyncHTTPClient *select(shared_ptr<Conn> &conn, tstring &prefix);

    // timing is used by the clients so it must outlive them
    Timing timing;
    vector<shared_ptr<Conn>> conns;
    atomic<uint> cto = 30 * 1000, minconns = 16, numreqs = 0, rto = 90 * 1000;
    Dispatcher &dsp;
    mutable SpinLock lck;
};

#endif // HTTPClientPool_h
