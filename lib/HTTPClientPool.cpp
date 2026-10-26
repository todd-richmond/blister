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
#include <random>
#include "HTTPClientPool.h"

static constexpr usec_t InitialBackoff = 125UL * 1000;
static constexpr usec_t MaxBackoff = 5UL * 60 * 1000 * 1000;

static void addhost(vector<pair<Sockaddr, double>> &out, tstring_view item) {
    const size_t star = item.find(T('*'));
    tstring_view host = item.substr(0, star);
    double weight = 1.0;
    ushort port;
    const size_t colon = host.rfind(T(':'));

    if (star != tstring_view::npos)
	weight = max(0.0, atod<double>(tstring(item.substr(star + 1)).c_str()));
    if (colon == tstring_view::npos || colon + 1 == host.size() ||
	from_chars(host.data() + colon + 1, host.data() + host.size(),
	port).ec != errc()) {
	dlogw(Log::mod(T("http")), Log::cmd(T("server")), Log::kv(T("invalid"),
	    tstring(item)));
	return;
    }
    host = host.substr(0, colon);
    if (host.size() > 1 && host.front() == T('[') && host.back() == T(']'))
	host = host.substr(1, host.size() - 2);
    for (const auto &sa : SockaddrList(tstring(host).c_str(), port))
	out.emplace_back(sa.val, weight);
}

bool HTTPClientPool::refresh(const tchar *prefix, const tchar *) {
    const Config &cfg = dsp.config();
    const tstring list(cfg.get(T("servers"), T(""), prefix));
    const tstring path(cfg.get(T("pathprefix"), T(""), prefix));

    minconns = cfg.get(T("minconnections"), minconns.load(), prefix);
    cto = cfg.get(T("connecttimeout"), cto.load(), prefix);
    rto = cfg.get(T("iotimeout"), rto.load(), prefix);
    {
	SpinLocker lkr(lck);

	for (const auto &c : conns) {
	    for (const auto &cl : c->clients)
		cl->timeout(cto, rto);
	}
    }
    return refreshservers(list, path.c_str());
}

bool HTTPClientPool::refreshservers(tstring_view list, const tchar *prefix) {
    vector<pair<Sockaddr, double>> servers;

    // resolve names before taking the lock
    for (size_t pos = 0; pos < list.size(); ) {
	size_t end = list.find(T(','), pos);

	if (end == tstring_view::npos)
	    end = list.size();
	addhost(servers, list.substr(pos, end - pos));
	pos = end + 1;
    }

    vector<AsyncHTTPClient *> retired;

    {
	SpinLocker lkr(lck);

	for (const auto &c : conns)
	    c->active = false;
	for (const auto &[sa, weight] : servers)
	    addConn(sa, weight, prefix ? prefix : T(""));
	// requests keep a removed server alive so only its clients need to go
	for (const auto &c : conns) {
	    if (!c->active) {
		for (auto &cl : c->clients)
		    retired.push_back(cl.release());
		c->clients.clear();
	    }
	}
	erase_if(conns, [](const auto &c) { return !c->active; });
    }
    // each deletes itself once its requests are complete
    for (auto *cl : retired)
	cl->release();
    return true;
}

void HTTPClientPool::addConn(const Sockaddr &sa, double weight,
    tstring_view prefix) {
    for (const auto &c : conns) {
	if (c->addr == sa) {
	    c->active = true;
	    c->path_prefix = prefix;
	    c->weight = weight;
	    return;
	}
    }
    conns.push_back(make_shared<Conn>(sa, weight, prefix));
}

void HTTPClientPool::status(tostream &out, uint indent, const tchar *name)
    const {
    struct Server {
	Sockaddr addr;
	bool active;
	uint errors;
	usec_t backoff, down_until;
	vector<tstring> clients;
    };
    vector<Server> servers;
    const usec_t now = uticks();
    const tstring pad(indent, T(' ')), pad2(indent + 2, T(' ')),
	pad4(indent + 4, T(' '));

    {
	SpinLocker lkr(lck);

	for (const auto &c : conns) {
	    Server &sv = servers.emplace_back(c->addr, c->active, c->errors,
		c->backoff, c->down_until);

	    for (const auto &cl : c->clients) {
		tostringstream os;

		cl->status(os, indent + 6);
		sv.clients.push_back(os.str());
	    }
	}
    }
    out << pad << T("<httppool name=\"") << name << T("\">\n");
    for (const auto &sv : servers) {
	out << pad2 << T("<server name=\"") << sv.addr.ipstr() <<
	    T("\" active=\"") << (sv.active ? 't' : 'f') << T("\">\n");
	for (const auto &cl : sv.clients)
	    out << pad4 << T("<connection>\n") << cl << pad4 <<
		T("</connection>\n");
	out << pad4 << T("<errors>") << sv.errors << T("</errors>\n") << pad4 <<
	    T("<backoff>") << (double)sv.backoff / 1e6 << T("</backoff>\n") <<
	    pad4 << T("<downleft>") << (now < sv.down_until ?
	    (double)(sv.down_until - now) / 1e6 : 0.0) << T("</downleft>\n") <<
	    pad2 << T("</server>\n");
    }
    out << pad << T("</httppool>\n");
}

AsyncHTTPClient *HTTPClientPool::select(shared_ptr<Conn> &sel,
    tstring &prefix) {
    static thread_local mt19937 rng(random_device {}());
    const usec_t now = uticks();
    double total = 0, downtotal = 0;
    uint avail = 0, ndown = 0;
    shared_ptr<Conn> pick;
    AsyncHTTPClient *best = nullptr;

    {
	SpinLocker lkr(lck);

	for (const auto &c : conns) {
	    if (!c->active)
		continue;
	    downtotal += c->weight;
	    ndown++;
	    if (c->down_until < now) {
		total += c->weight;
		avail++;
	    }
	}

	const bool usedown = !avail;

	if (usedown) {
	    total = downtotal;
	    avail = ndown;
	}
	if (total <= 0)
	    return nullptr;

	double choice = uniform_real_distribution<double>(0, total)(rng);

	for (const auto &c : conns) {
	    if (!c->active || (!usedown && c->down_until >= now))
		continue;
	    pick = c;
	    if ((choice -= c->weight) < 0)
		break;
	}
	if (!pick)
	    return nullptr;

	// spread the connections evenly and add more only while all are busy
	const size_t maxclients = max((minconns + avail - 1) / avail, 1U);

	for (const auto &cl : pick->clients) {
	    if (!best || cl->numPending() < best->numPending())
		best = cl.get();
	}
	if (!best || (best->numPending() &&
	    pick->clients.size() < maxclients)) {
	    pick->clients.push_back(make_unique<AsyncHTTPClient>(dsp,
		pick->addr, &timing));
	    best = pick->clients.back().get();
	    best->timeout(cto, rto);
	}
	// reserve it so selects balance and a refresh cannot retire it
	best->acquire();
	prefix = pick->path_prefix;
    }
    sel = std::move(pick);
    return best;
}

const Sockaddr &HTTPClientPool::Request::addr(void) const {
    return saddr;
}

bool HTTPClientPool::Request::dispatch(void) {
    tstring prefix;
    AsyncHTTPClient *cl = pool.select(conn, prefix);

    if (!cl) {
	reset();
	sockerr = ESRCH;
	return false;
    }

    HTTPClientPool &p = pool;

    saddr = cl->address();
    if (!hdrs.empty())
	headers(hdrs);
    // setup readies the caller on error so this may be destroyed after it
    if (setup(ucb, *ucaller, *cl, op.c_str(), (prefix + path).c_str(),
	udata, udatasz)) {
	queue();
    } else {
	cl->release();
	p.numreqs--;
    }
    return true;
}

void HTTPClientPool::Request::markgood(void) {
    if (!conn)
	return;

    SpinLocker lkr(pool.lck);

    conn->errors = 0;
    conn->backoff = conn->down_until = 0;
}

void HTTPClientPool::Request::penalize(void) {
    if (!conn || (!sockerr && sts == 408))
	return;

    const usec_t now = uticks();
    SpinLocker lkr(pool.lck);

    if (conn->down_until <= now) {
	conn->errors++;
	conn->backoff = conn->backoff ? min(conn->backoff * 2, MaxBackoff) :
	    InitialBackoff;
	conn->down_until = now + conn->backoff;
    }
}

// called by the client when done - true if the request was sent again
bool HTTPClientPool::Request::resend(void) {
    if (sockerr) {
	dlogi(logprefix, Log::mod(T("http")), Log::kv(T("server"),
	    saddr.ipstr()), Log::error(errstr()));
    } else {
	dlogl(sts < 300 ? Log::Trace : Log::Info, logprefix,
	    Log::mod(T("http")), Log::kv(T("server"), saddr.ipstr()),
	    Log::status(sts));
    }
    // bad arguments will not succeed elsewhere
    if ((sockerr || sts == 408) && sockerr != EINVAL && ++ntries < maxtries) {
	penalize();
	if (dispatch())
	    return true;
    }
    pool.numreqs--;
    return false;
}

bool HTTPClientPool::Request::retry(DispatchObjCB cb, DispatchObj &co) {
    if (ntries >= maxtries)
	return false;
    ntries++;
    ucb = cb;
    ucaller = &co;
    pool.numreqs++;
    penalize();
    if (!dispatch()) {
	pool.numreqs--;
	co.ready(cb);
    }
    return true;
}

void HTTPClientPool::Request::send(DispatchObjCB cb, DispatchObj &co, const
    tchar *o, const tchar *p, const tchar *h, const void *data, ulong len) {
    ucb = cb;
    ucaller = &co;
    udata = data;
    udatasz = len;
    op = o;
    path = p;
    // keep headers so they are sent again if the request is retried
    hdrs.assign(hstrm.str(), (size_t)hstrm.size());
    hstrm.reset();
    if (h)
	hdrs += h;
    ntries = 0;
    conn = nullptr;
    set_logprefix(dlog.prefix());
    pool.numreqs++;
    if (!dispatch()) {
	pool.numreqs--;
	co.ready(cb);
    }
}
