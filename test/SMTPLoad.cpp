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
#include "SMTPClient.h"

static bool dflag = false, pflag = false;

class SMTPLoad: public Load {
public:
    static bool parse(tchar *cmd, uint line);

private:
    enum class Op: uchar {
	Auth, Bcc, Body, Cc, Cmd, Connect, Data, Ehlo, From, Header, Helo,
	Lhlo, Quit, Rcpt, Rset, Subject, Vrfy, Xclient
    };

    class SMTPCmd: public LoadCmd {
    public:
	SMTPCmd(const tchar *command, const tchar *argument):
	    LoadCmd(command, argument), vars(arg.contains(T("$("))) {
	    for (auto &c : cmd)
		c = (tchar)totlower(c);

	    const auto *it = ranges::find(ops, tstring_view(cmd),
		&pair<tstring_view, Op>::first);

	    op = it == ranges::end(ops) ? Op::Cmd : it->second;
	}

	Sockaddr addr;			// connect only
	Op op;
	static constexpr pair<tstring_view, Op> ops[] = {
	    { T("auth"), Op::Auth }, { T("bcc"), Op::Bcc },
	    { T("body"), Op::Body }, { T("cc"), Op::Cc },
	    { T("connect"), Op::Connect }, { T("data"), Op::Data },
	    { T("ehlo"), Op::Ehlo }, { T("from"), Op::From },
	    { T("hdr"), Op::Header }, { T("header"), Op::Header },
	    { T("helo"), Op::Helo }, { T("lhlo"), Op::Lhlo },
	    { T("quit"), Op::Quit }, { T("rcpt"), Op::Rcpt },
	    { T("rset"), Op::Rset }, { T("subj"), Op::Subject },
	    { T("subject"), Op::Subject }, { T("to"), Op::Rcpt },
	    { T("vrfy"), Op::Vrfy }, { T("xclient"), Op::Xclient }
	};
	bool vars;			// arg has $() for per message values
    };

    tchar buf[1024]{};
    SMTPClient sc;
    const tchar *arg = nullptr;

    void begin(void) override { sc.chunking(!dflag); }
    bool exec(LoadCmd &lc, usec_t &io) override;
    bool check(LoadCmd &lc, bool ret, ulong diff) override;
    void end(void) override { sc.close(); }
};

bool SMTPLoad::parse(tchar *cmd, uint line) {
    const tchar *a = tstrtok(nullptr, T(""));
    auto lcmd = make_unique<SMTPCmd>(cmd, a);

    if (bodies.empty() && (lcmd->op == Op::Data || (lcmd->op == Op::Body &&
	!a))) {
	tcerr << T("missing body file for ") << cmd << endl;
	return false;
    }
    if (lcmd->op == Op::Connect &&
	!lcmd->addr.set(vars[T("host")].c_str())) {
	tcerr << T("invalid host: line ") << line << T(": ") <<
	    vars[T("host")] << endl;
	return false;
    }
    need(lcmd->arg);
    cmds.push_back(std::move(lcmd));
    return true;
}

bool SMTPLoad::exec(LoadCmd &lc, usec_t &io) {
    const auto &cmd = static_cast<const SMTPCmd &>(lc);

    arg = cmd.arg.c_str();
    if (cmd.vars) {
	if (!subst(cmd.arg, buf, size(buf)))
	    return false;
	arg = buf;
    }
    switch (cmd.op) {
    case Op::Auth:
	if (const tchar *p = tstrchr(arg, ' '); p) {
	    tstring user(arg, p);

	    while (istspace(*p))
		p++;
	    return sc.auth(user.c_str(), p);
	}
	return false;
    case Op::Bcc:
	return sc.bcc(arg);
    case Op::Body:
	if (*arg || bodies.empty())
	    return sc.data(false, arg) && sc.enddata();
	[[fallthrough]];
    case Op::Data: {
	unique_ptr<char[]> rbuf;
	uint u = pick();
	const char *d = load(u, io, rbuf);

	return d && (cmd.op == Op::Body ? sc.data(false, achartotchar(d)) :
	    sc.data(d, bodies[u].size)) && sc.enddata();
    }
    case Op::Cc:
	return sc.cc(arg);
    case Op::Cmd:
	return sc.cmd(cmd.cmd.c_str(), *arg ? arg : nullptr);
    case Op::Connect:
	return sc.connect(cmd.addr, to);
    case Op::Ehlo:
	return sc.ehlo(arg);
    case Op::From:
	if (pflag)
	    sc.pipeline();
	return sc.from(arg);
    case Op::Header:
	sc.header(arg);
	return true;
    case Op::Helo:
	return sc.helo(arg);
    case Op::Lhlo:
	return sc.lhlo(arg);
    case Op::Quit:
	return sc.quit();
    case Op::Rcpt:
	return sc.to(arg);
    case Op::Rset:
	return sc.rset();
    case Op::Subject:
	sc.subject(arg);
	return true;
    case Op::Vrfy:
	return sc.vrfy(arg);
    case Op::Xclient:
	return sc.xclient(arg);
    }
    return false;
}

bool SMTPLoad::check(LoadCmd &lc, bool ret, ulong diff) {
    const auto &cmd = static_cast<const SMTPCmd &>(lc);

    if (ret && pflag && (cmd.op == Op::Body || cmd.op == Op::Data)) {
	for (const auto &r : sc.rejected())
	    dlog << Log::Warn << Log::cmd(T("rcpt")) << Log::kv(T("arg"),
		r.first) << Log::kv(T("result"), r.second) << endlog;
    }
    if (!ret) {
	dlog << Log::Err << Log::cmd(cmd.cmd) << Log::kv(T("arg"), arg) <<
	    Log::kv(T("status"), sc.code()) << Log::kv(T("message"),
	    sc.message()) << Log::kv(T("duration"), (diff / 1000)) <<
	    Log::kv(T("result"), sc.result()) << endlog;
    } else if (dlog.level() >= Log::Info) {
	dlog << Log::Info << Log::cmd(cmd.cmd) << Log::kv(T("arg"), arg) <<
	    Log::kv(T("status"), sc.code()) << Log::kv(T("message"),
	    sc.message()) << Log::kv(T("duration"), (diff / 1000)) << endlog;
    }
    return ret;
}

int tmain(int argc, tchar *argv[]) {
    return Load::main<SMTPLoad>(argc, argv, T("smtp.wld"), T("localhost:25"),
	T("[-d] [-p]"), [](const tchar *a) {
	if (!tstricmp(a, T("-d")))
	    dflag = true;
	else if (!tstricmp(a, T("-p")))
	    pflag = true;
	else
	    return false;
	return true;
    });
}
