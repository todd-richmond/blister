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
#include "Load.h"
#include "TLSSocket.h"

static bool dbg = false, ka = false;
static ulong chunksz = 0;

class HTTPLoad: public Load {
public:
    static bool parse(tchar *cmd, uint line);

private:
    class HTTPCmd: public LoadCmd {
    public:
	HTTPCmd(const tchar *c, const tchar *a, const URL &u, const tchar *d,
	    const tchar *s, const tchar *v, bool b): LoadCmd(c, a),
	    data(d ? d : T("")), full(u.fullpath()), method(c),
	    path(u.relpath()), value(v ? v : T("")), status((ushort)ttoi(s)),
	    body(b), tls(u.prot().starts_with(T("https"))),
	    vars(path.contains(T("$("))) {
	    for (auto &ch : method)
		ch = (tchar)totupper(ch);
	}

	Sockaddr addr;
	tstring data, full, method, path, value;
	ushort status;
	bool body;			// request has a body
	bool tls;
	bool vars;			// path has $() for per request values
    };

    tchar buf[1024]{}, data[4096]{};
    vector<tstring> cookies;
    tofstream fs;
    HTTPTLSClient hc;
    const tchar *path = nullptr;
    static inline attrmap hdrs;
    static inline bool ctype = false;	// hdrs has a content-type

    bool send(const HTTPCmd &cmd, const void *d, ulong len);

    void begin(void) override;
    bool exec(LoadCmd &lc, usec_t &io) override;
    bool check(LoadCmd &lc, bool ret, ulong diff) override;
    void end(void) override {
	if (!ka)
	    hc.close();
	cookies.clear();
    }
};

bool HTTPLoad::parse(tchar *cmd, uint line) {
    static constexpr pair<tstring_view, bool> methods[] = {
	{ T("delete"), false }, { T("get"), false }, { T("head"), false },
	{ T("options"), false }, { T("patch"), true }, { T("post"), true },
	{ T("put"), true }
    };
    const tchar *arg, *data = nullptr, *status, *value;
    URL url;

    if (!tstricmp(cmd, T("hdr"))) {
	if (!setattr(hdrs, line))
	    return false;
	ctype = ranges::any_of(hdrs, [](const auto &h) {
	    return !tstricmp(h.first.c_str(), T("content-type"));
	});
	return true;
    }

    const auto *m = ranges::find_if(methods, [&](const auto &p) {
	return !tstricmp(p.first.data(), cmd);
    });

    if (m == ranges::end(methods)) {
	tcerr << T("invalid cmd: line ") << line << endl;
	return false;
    }
    arg = tstrtok(nullptr, T(" \t"));
    if (!url.set(tstrtok(nullptr, T(" \t")))) {
	tcerr << T("invalid url: line ") << line << endl;
	return false;
    }
    if (m->second) {
	data = tstrtok(nullptr, T(" \t"));
	if (data && !tstrcmp(data, T("-")))	// body file
	    data = nullptr;
	if (!data && bodies.empty()) {
	    tcerr << T("missing body file for ") << cmd << endl;
	    return false;
	}
    }
    status = tstrtok(nullptr, T(" \t"));
    if (!status)
	status = T("200");
    value = tstrtok(nullptr, T(""));

    auto lcmd = make_unique<HTTPCmd>(cmd, arg, url, data, status, value,
	m->second);

    if (!lcmd->addr.set(url.host().c_str(), url.port())) {
	tcerr << T("invalid host: line ") << line << endl;
	return false;
    }
    need(lcmd->path);
    need(lcmd->data);
    cmds.push_back(std::move(lcmd));
    return true;
}

void HTTPLoad::begin(void) {
    // threads would overwrite each other's output
    if (dbg && !id)
	fs.open("debug.out", ios::trunc | ios::out);
    hc.timeout(to, to);
}

bool HTTPLoad::exec(LoadCmd &lc, usec_t &io) {
    const auto &cmd = static_cast<const HTTPCmd &>(lc);
    bool ret;

    path = cmd.path.c_str();
    if (fs.is_open())
	fs << T("\n\n******* ") << cmd.cmd << T(" ") << cmd.arg << T(" ") <<
	    cmd.full << T(" *******") << endl;
    hc.tls(cmd.tls);
    if ((ret = hc.connect(cmd.addr, ka, to)) == true) {
	if (!cookies.empty()) {
	    tstring s;

	    for (const auto &c : cookies) {
		if (!s.empty())
		    s += T("; ");
		s += c;
	    }
	    hc.header(T("cookie"), s);
	    if (fs.is_open())
		fs << T("SEND Cookie: ") << s << endl;
	}
	for (const auto &[key, value] : hdrs)
	    hc.header(key, value);
    } else {
	path = cmd.full.c_str();
    }
    if (ret && cmd.vars && (ret = subst(cmd.path, buf, size(buf))) == true)
	path = buf;
    if (!ret)
	return false;
    if (!cmd.body)
	return hc.cmd(cmd.method.c_str(), path);
    if (cmd.data.empty()) {
	unique_ptr<char[]> rbuf;
	uint u = pick();
	const char *d = load(u, io, rbuf);

	if (!ctype)
	    hc.header(T("content-type"), T("application/octet-stream"));
	return d && send(cmd, d, bodies[u].size);
    }
    if (!subst(cmd.data, data, size(data)))
	return false;
    if (!ctype)
	hc.header(T("content-type"), T("application/x-www-form-urlencoded"));
    return send(cmd, data, (ulong)(tstrlen(data) * sizeof (tchar)));
}

// -u sends the body chunked; an early reply ends the upload
bool HTTPLoad::send(const HTTPCmd &cmd, const void *d, ulong len) {
    if (!chunksz)
	return hc.cmd(cmd.method.c_str(), path, d, len);
    if (!hc.sendbegin(cmd.method.c_str(), path))
	return false;
    for (ulong off = 0; off < len; off += chunksz) {
	if (!hc.sendchunk((const char *)d + off, min(chunksz, len - off)))
	    break;
    }
    return hc.sendend();
}

bool HTTPLoad::check(LoadCmd &lc, bool ret, ulong diff) {
    auto &cmd = static_cast<HTTPCmd &>(lc);

    if (!ret || (cmd.status && hc.status() != cmd.status) ||
	(!cmd.status && hc.status() != 200 && hc.status() != 302)) {
	if (ret)
	    fail(cmd);
	dlog << Log::Err << T("cmd=") << cmd.cmd << T(" arg=") << path <<
	    T(" status=") << hc.status() << T(" expected=") << cmd.status <<
	    T(" duration=") << (diff / 1000) << endlog;
	return false;
    }
    if (fs.is_open())
	fs << cmd.cmd << T(" status: ") << hc.status() << endl << endl;
    for (const auto &[key, val] : hc.responses()) {
	if (key == T("set-cookie")) {
	    tstring s(val);
	    tstring::size_type pos;

	    if ((pos = s.find_first_of(T(';'))) != string::npos)
		s.erase(pos);
	    if (s != T("invalid"))
		cookies.push_back(s);
	}
	if (fs.is_open())
	    fs << key << ": " << val << endl;
    }
#ifndef UNICODE	// TODO
    if (fs.is_open()) {
	fs << endl;
	fs.write(hc.data(), (streamsize)hc.size());
	fs.flush();
    }
    if (!cmd.value.empty() && !tstring_view(hc.data(),
	hc.size()).contains(cmd.value)) {
	dlog << Log::Err << T("cmd=") << cmd.cmd << T(" arg=") << path <<
	    T(" invalid return data") << endlog;
	fail(cmd);
	return false;
    }
#endif
    if (dlog.level() >= Log::Info)
	dlog << Log::Info << T("cmd=") << cmd.cmd << T(" arg=") << path <<
	    T(" status=") << hc.status() << T(" duration=") << (diff / 1000) <<
	    endlog;
    return true;
}

int tmain(int argc, tchar *argv[]) {
    Config cfg;
    tstring err;

    // test servers use self-signed certs
    cfg.set(T("tls.verify"), false);
    (void)TLSContext::client().init(cfg, nullptr, err);
    return Load::run<HTTPLoad>(argc, argv, T("http.wld"), T("localhost:80"),
	T("[-d] [-k] [-u[chunksize]]"), [](const tchar *arg) {
	if (!tstricmp(arg, T("-d")))
	    dbg = true;
	else if (!tstricmp(arg, T("-k")))
	    ka = true;
	else if (!tstrncmp(arg, T("-u"), 2))
	    return (chunksz = arg[2] ? atoi<ulong>(arg + 2) : 64UL * 1024) != 0;
	else
	    return false;
	return true;
    });
}
