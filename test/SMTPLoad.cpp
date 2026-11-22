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

static bool dflag = false, pflag = false;

class SMTPLoad: public Load {
public:
    static bool parse(tchar *cmd, uint line);

private:
    enum class Op: uchar {
	Attach, Auth, Bcc, Body, Cc, Cmd, Connect, Data, Ehlo, End, From,
	Header, Helo, Lhlo, Mime, Quit, Rcpt, Rset, Starttls, Subject, Vrfy,
	Xclient
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
	int code = 250;			// cmd only
	Op op;
	bool qp = false;		// attach only
	tstring type;			// attach only
	bool vars;			// arg has $() for per message values
	static constexpr pair<tstring_view, Op> ops[] = {
	    { T("attach"), Op::Attach }, { T("auth"), Op::Auth },
	    { T("bcc"), Op::Bcc }, { T("body"), Op::Body }, { T("cc"), Op::Cc },
	    { T("connect"), Op::Connect }, { T("data"), Op::Data },
	    { T("ehlo"), Op::Ehlo }, { T("end"), Op::End },
	    { T("enddata"), Op::End }, { T("from"), Op::From },
	    { T("hdr"), Op::Header }, { T("header"), Op::Header },
	    { T("helo"), Op::Helo }, { T("lhlo"), Op::Lhlo },
	    { T("mime"), Op::Mime }, { T("quit"), Op::Quit },
	    { T("rcpt"), Op::Rcpt },
	    { T("rset"), Op::Rset }, { T("starttls"), Op::Starttls },
	    { T("subj"), Op::Subject },
	    { T("subject"), Op::Subject }, { T("to"), Op::Rcpt },
	    { T("vrfy"), Op::Vrfy }, { T("xclient"), Op::Xclient }
	};
    };

    const tchar *arg = nullptr;
    tchar buf[1024]{};
    SMTPTLSClient sc;

    void begin(void) override {
	sc.chunking(!dflag);
	sc.timeout(to, to);
    }
    bool check(LoadCmd &lc, bool ret, ulong diff) override;
    void end(void) override { sc.close(); }
    bool exec(LoadCmd &lc, usec_t &io) override;
    static const tchar *address(const tchar *str, tstring &who);
};

bool SMTPLoad::parse(tchar *cmd, uint line) {
    const tchar *a = tstrtok(nullptr, T(""));
    auto lcmd = make_unique<SMTPCmd>(cmd, a);

    if (bodies.empty() && (lcmd->op == Op::Attach || lcmd->op == Op::Data ||
	(lcmd->op == Op::Body && !a))) {
	tcerr << T("missing body file for ") << cmd << endl;
	return false;
    }
    if (lcmd->op == Op::Connect &&
	!lcmd->addr.set(vars[T("host")].c_str())) {
	tcerr << T("invalid host: line ") << line << T(": ") <<
	    vars[T("host")] << endl;
	return false;
    }
    if (lcmd->op == Op::Attach) {
	// [type [base64|qp]]
	tstring tok(lcmd->arg);
	const tchar *type = tstrtok(tok.data(), T(" \t"));
	const tchar *enc = tstrtok(nullptr, T(" \t"));

	lcmd->type = type ? type : T("application/octet-stream");
	lcmd->qp = enc && !tstricmp(enc, T("qp"));
    } else if (lcmd->op == Op::Cmd) {
	// a trailing =NNN is the expected reply code
	tstring &s = lcmd->arg;
	const size_t pos = s.find_last_of(T(" \t")) + 1;

	if (s.size() - pos == 4 && s[pos] == '=' && istdigit(s[pos + 1]) &&
	    istdigit(s[pos + 2]) && istdigit(s[pos + 3])) {
	    lcmd->code = ttoi(s.c_str() + pos + 1);
	    s.erase(pos);
	    s.erase(s.find_last_not_of(T(" \t")) + 1);
	}
    }
    need(lcmd->arg);
    cmds.push_back(std::move(lcmd));
    return true;
}

// "address [parameters]": a bracketed address may contain spaces
const tchar *SMTPLoad::address(const tchar *str, tstring &who) {
    const tchar *gt = tstrrchr(str, '>');
    const tchar *parms = gt ? gt + 1 : str + tstrcspn(str, T(" \t"));

    who.assign(str, parms);
    while (istspace(*parms))
	parms++;
    return *parms ? parms : nullptr;
}

bool SMTPLoad::exec(LoadCmd &lc, usec_t &io) {
    const auto &cmd = static_cast<const SMTPCmd &>(lc);
    const tchar *parms;
    tstring who;

    arg = cmd.arg.c_str();
    if (cmd.vars) {
	if (!subst(cmd.arg, buf, size(buf)))
	    return false;
	arg = buf;
    }
    switch (cmd.op) {
    using enum Op;
    case Attach: {
	unique_ptr<char[]> rbuf, enc;
	uint u = pick();
	const char *d = load(u, io, rbuf);
	const tstring &path = bodies[u].path;
	char *out = nullptr;
	size_t outsz = 0;

	if (!d)
	    return false;
	(cmd.qp ? qpencode : base64encode)(d, bodies[u].size, out, outsz);
	enc.reset(out);
	return sc.data(out, outsz, cmd.type.c_str(), nullptr, cmd.qp ?
	    T("quoted-printable") : T("base64"), T("attachment"), path.c_str() +
	    (path.find_last_of(T("/\\")) + 1));
    }
    case Auth:
	if (const tchar *p = tstrchr(arg, ' '); p) {
	    tstring user(arg, p);

	    while (istspace(*p))
		p++;
	    return sc.auth(user.c_str(), p);
	}
	return false;
    case Bcc:
	parms = address(arg, who);
	return sc.bcc(who.c_str(), parms);
    case Body:
	if (*arg || bodies.empty())
	    return sc.data(false, arg) && sc.enddata();
	[[fallthrough]];
    case Data: {
	unique_ptr<char[]> rbuf;
	uint u = pick();
	const char *d = load(u, io, rbuf);

	return d && sc.data(d, bodies[u].size) && sc.enddata();
    }
    case Cc:
	parms = address(arg, who);
	return sc.cc(who.c_str(), parms);
    case Cmd:
	return sc.cmd(cmd.cmd.c_str(), *arg ? arg : nullptr, cmd.code);
    case Connect:
	sc.tls(!tstricmp(arg, T("tls")));
	return sc.connect(cmd.addr, to);
    case Ehlo:
	return sc.ehlo(arg);
    case End:
	return sc.enddata();
    case From:
	parms = address(arg, who);
	if (pflag)
	    sc.pipeline();
	return sc.from(RFC822Addr(who.c_str(), true), parms);
    case Header:
	sc.header(arg);
	return true;
    case Helo:
	return sc.helo(arg);
    case Lhlo:
	return sc.lhlo(arg);
    case Mime:
	return sc.data(true, *arg ? arg : nullptr);
    case Quit:
	return sc.quit();
    case Rcpt:
	parms = address(arg, who);
	return sc.to(who.c_str(), parms);
    case Rset:
	return sc.rset();
    case Starttls:
	return sc.starttls();
    case Subject:
	sc.subject(arg);
	return true;
    case Vrfy:
	parms = address(arg, who);
	return sc.vrfy(who.c_str(), parms);
    case Xclient:
	return sc.xclient(arg);
    }
    return false;
}

bool SMTPLoad::check(LoadCmd &lc, bool ret, ulong diff) {
    const auto &cmd = static_cast<const SMTPCmd &>(lc);

    if (ret && (cmd.op == Op::Body || cmd.op == Op::Data || cmd.op ==
	Op::End)) {
	for (const auto &[rcpt, why] : sc.rejected())
	    dlog << Log::Warn << Log::cmd(T("rcpt")) << Log::kv(T("arg"),
		rcpt) << Log::kv(T("result"), why) << endlog;
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
    Config cfg;
    tstring err;

    // test servers use self-signed certs
    cfg.set(T("tls.verify"), false);
    if (!TLSContext::client().init(cfg, nullptr, err))
	tcerr << T("TLS disabled: ") << err << endl;
    return Load::run<SMTPLoad>(argc, argv, T("smtp.wld"), T("localhost:25"),
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
