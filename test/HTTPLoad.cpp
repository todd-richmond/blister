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
#include "HTTPClient.h"
#include "Load.h"

static bool dbg = false, ka = false;

class HTTPLoad: public Load {
public:
    static bool parse(tchar *cmd, uint line);

private:
    enum class Op: uchar { Get, Post };

    class HTTPCmd: public LoadCmd {
    public:
	HTTPCmd(const tchar *c, const tchar *a, const URL &u, const tchar *d,
	    const tchar *s, const tchar *v): LoadCmd(c, a), data(d ? d : T("")),
	    full(u.fullpath()), path(u.relpath()), value(v ? v : T("")),
	    op(!tstricmp(c, T("get")) ? Op::Get : Op::Post),
	    status((ushort)ttoi(s)), vars(path.contains(T("$("))) {}

	Sockaddr addr;
	tstring data, full, path, value;
	Op op;
	ushort status;
	bool vars;			// path has $() for per request values
    };

    tchar buf[1024]{}, data[4096]{};
    vector<tstring> cookies;
    tofstream fs;
    HTTPClient hc;
    const tchar *path = nullptr;
    static inline attrmap hdrs;

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
    const tchar *arg, *data = nullptr, *status, *value;
    URL url;

    if (!tstricmp(cmd, T("hdr")))
	return setattr(hdrs, line);
    if (tstricmp(cmd, T("get")) && tstricmp(cmd, T("post"))) {
	tcerr << T("invalid cmd: line ") << line << endl;
	return false;
    }
    arg = tstrtok(nullptr, T(" \t"));
    if (!url.set(tstrtok(nullptr, T(" \t")))) {
	tcerr << T("invalid url: line ") << line << endl;
	return false;
    }
    if (!tstricmp(cmd, T("post"))) {
	data = tstrtok(nullptr, T(" \t"));
	if (!data && bodies.empty()) {
	    tcerr << T("missing body file for ") << cmd << endl;
	    return false;
	}
    }
    status = tstrtok(nullptr, T(" \t"));
    if (!status)
	status = T("200");
    value = tstrtok(nullptr, T(""));

    auto lcmd = make_unique<HTTPCmd>(cmd, arg, url, data, status, value);

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
    if (cmd.op == Op::Get)
	return hc.get(path);
    if (cmd.data.empty()) {
	unique_ptr<char[]> rbuf;
	uint u = pick();
	const char *d = load(u, io, rbuf);

	hc.header(T("content-type"), T("application/octet-stream"));
	return d && hc.post(path, d, bodies[u].size);
    }
    if (!subst(cmd.data, data, size(data)))
	return false;
    hc.header(T("content-type"), T("application/x-www-form-urlencoded"));
    return hc.post(path, data, (ulong)(tstrlen(data) * sizeof (tchar)));
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
    return Load::run<HTTPLoad>(argc, argv, T("http.wld"), T("localhost:80"),
	T("[-d] [-k]"), [](const tchar *arg) {
	if (!tstricmp(arg, T("-d")))
	    dbg = true;
	else if (!tstricmp(arg, T("-k")))
	    ka = true;
	else
	    return false;
	return true;
    });
}
