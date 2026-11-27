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
#include <errno.h>
#include <signal.h>
#ifndef _WIN32
#include <sys/wait.h>
#endif
#include "Log.h"
#include "Service.h"

class WatchDaemon: public Daemon {
public:
    explicit WatchDaemon(vector<const tchar *> &args);

protected:
    bool onRefresh(void) override;
    int onStart(int argc, const tchar * const *argv) override;
    void onStop(bool fast) override;

private:
    Lock childlock;
#ifdef _WIN32
    HANDLE proc = nullptr;
#else
    pid_t cpid = 0;
#endif
    ulong interval = 60, maxmem = 0;

    bool overlimit(pid_t child) const;
    void stopchild(bool fast);
    int waitchild(void);

    static bool flagopt(const tchar *p) {
	return tstreq(p, T("console")) || tstreq(p, T("daemon"));
    }
    static int firstoption(int argc, const tchar * const *argv);
};

int WatchDaemon::firstoption(int argc, const tchar * const *argv) {
    int ac;

    for (ac = 1; ac < argc && *argv[ac] == '-'; ++ac) {
	const tchar *p = argv[ac] + tstrspn(argv[ac], T("-"));

	if (!flagopt(p))
	    ++ac;
#ifdef _WIN32
	if (tstreq(p, T("worker")))
	    break;
#endif
    }
    return ac + 1;
}

bool WatchDaemon::overlimit(pid_t child) const {
    struct pidstat ps;

    if (pidstat(child, &ps) || ps.pss <= maxmem)
	return false;
    dlog.warn(Log::mod(name), Log::kv(T("pid"), child),
	Log::kv(T("pss"), ps.pss), Log::kv(T("maxmem"), maxmem));
    return true;
}

void WatchDaemon::stopchild(bool fast) {
    FastLocker lkr(childlock);

#ifdef _WIN32
    (void)fast;
    if (proc)
	(void)TerminateProcess(proc, 1);
#else
    if (cpid > 0)
	(void)kill(cpid, fast ? SIGTERM : SIGINT);
#endif
}

WatchDaemon::WatchDaemon(vector<const tchar *> &args): Daemon(T("")) {
    const int argc = (int)args.size();
    const tchar *const *argv = args.data();
    bool separator = false;
    int ac;

    for (ac = firstoption(argc, argv); ac < argc; ++ac) {
	const tchar *p = argv[ac];

	if (*p != '-')
	    break;
	if (tstreq(p, T("--"))) {
	    separator = true;
	    ++ac;
	    break;
	}
	p += tstrspn(p, T("-"));
	if (tstreq(p, T("check")) && ac + 1 < argc)
	    interval = atoi<ulong>(argv[++ac]);
	else if (tstreq(p, T("maxmem")) && ac + 1 < argc)
	    maxmem = atoi<ulong>(argv[++ac]);
	else if (tstreq(p, T("name")) && ac + 1 < argc)
	    name = argv[++ac];
	else if (!flagopt(p))
	    ++ac;
    }
    if (ac >= argc) {
	tstring_view prog(argv[0]);

	prog.remove_prefix(prog.find_last_of(T("/\\")) + 1);
	tcout << T("usage:\t") << prog << endl <<
	    T("\tstart [--check seconds] [--maxmem kb] [--name str] cmd ...") <<
	    endl <<
	    T("\tcontinue|exit|pause|refresh|status|stop [--name str] cmd") <<
	    endl;
	exit(1);
    }
    if (name.empty()) {
	name = argv[ac];
	if (auto i = name.find_last_of(T("/\\")); i != name.npos)
	    name.erase(0, i + 1);
	if (auto i = name.find_last_of(T('.')); i != name.npos)
	    name.erase(i);
    }
    if (!separator)
	args.insert(args.begin() + ac, T("--"));
}

bool WatchDaemon::onRefresh(void) {
    if (!Daemon::onRefresh())
	return false;
    if (interval)
	cfg.set(T("watch.interval"), interval);
    else
	cfg.set(T("watch.enable"), false);
    return true;
}

int WatchDaemon::onStart(int argc, const tchar * const *argv) {
    const tchar *const *end = argv + argc, *const *cmd = argv + 1;
    tstring args;
    int ret;

    while (cmd < end && !tstreq(*cmd, T("--"))) {
	const tchar *opt = *cmd + tstrspn(*cmd, T("-"));

	cmd += !flagopt(opt) && end - cmd > 1 ? 2 : 1;
    }
    if (cmd == end || ++cmd == end) {
	dloge(Log::mod(name), Log::cmd(T("exec")), Log::error(T("no command")));
	return -1;
    }
    if ((ret = Daemon::onStart(argc, argv)) != 0)
	return ret;

    vector<const tchar *> childargs(cmd, end);

    childargs.push_back(nullptr);
    for (const tchar *const *p = cmd + 1; p != end; ++p) {
	if (!args.empty())
	    args += ' ';
	args += *p;
    }
    running();
    dlogi(Log::mod(name), Log::cmd(T("exec")), Log::kv(T("file"), *cmd),
	Log::kv(T("args"), args));
    // The child cannot wait on a flusher that only exists in the parent.
    dlog.stop();
    (void)dlog.close();
#ifdef _WIN32
    const intptr_t hdl = tspawnvp(P_NOWAIT, *cmd, (tchar *const *)childargs.data());
    const bool started = hdl != -1;
#else
    struct sigaction sa {};

    // Keep the child PID reserved until we reap it.
    sa.sa_handler = SIG_DFL;
    sigaction(SIGCHLD, &sa, nullptr);
    const pid_t child = fork();
    const bool started = child > 0;

    if (child == 0) {
	unsetsignal();
	texecvp(*cmd, (tchar *const *)childargs.data());	// NOSONAR
	constexpr char error[] = "daemonize: exec failed\n";

	[[maybe_unused]] const auto written = write(STDERR_FILENO, error,
	    sizeof (error) - 1);
	_exit(127);
    }
#endif
    const int err = errno;

    dlog.start();
    if (!started) {
	dloge(Log::mod(name), Log::cmd(T("exec")), Log::kv(T("file"), *cmd),
	    Log::error(tstrerror(err)));
	return -1;
    }
    {
	FastLocker lkr(childlock);

#ifdef _WIN32
	proc = (HANDLE)hdl;
#else
	cpid = child;
#endif
    }
    if (const Quit quit = qflag; quit != None)
	stopchild(quit == Fast);
    return waitchild();
}

void WatchDaemon::onStop(bool fast) {
    Daemon::onStop(fast);
    stopchild(fast);
}

int WatchDaemon::waitchild(void) {
    const msec_t period = maxmem ? (msec_t)interval * 1000 : 0;
#ifdef _WIN32
    DWORD sts = (DWORD)-1, ret;
    DWORD delay = period ? (DWORD)(min)(period, (msec_t)INFINITE - 1) :
	INFINITE;
    const pid_t child = (pid_t)GetProcessId(proc);

    while ((ret = WaitForSingleObject(proc, delay)) == WAIT_TIMEOUT) {
	if (child && overlimit(child)) {
	    stopchild(true);
	    delay = INFINITE;
	}
    }
    FastLocker lkr(childlock);

    if (ret == WAIT_OBJECT_0)
	(void)GetExitCodeProcess(proc, &sts);
    CloseHandle(proc);
    proc = nullptr;
    return (int)sts;
#else
    const pid_t child = cpid;
    msec_t due = period ? mticks() + period : 0;
    int sts;

    for (;;) {
	pid_t ret;
	int flags = WNOHANG;

#ifdef WNOWAIT
	if (!due) {
	    siginfo_t si {};

	    // Leave the PID reserved until we can reap it under childlock.
	    do {
		ret = waitid(P_PID, (id_t)child, &si, WEXITED | WNOWAIT);
	    } while (ret == -1 && errno == EINTR);
	    if (!ret)
		flags = 0;
	}
#endif
	{ // NOLINT(whitespace/braces)
	    FastLocker lkr(childlock);

	    do {
		ret = waitpid(child, &sts, flags);
	    } while (ret == -1 && errno == EINTR);
	    if (ret != 0)
		cpid = 0;
	}
	if (ret != 0)
	    return ret == -1 ? -1 : WIFSIGNALED(sts) ? 128 + WTERMSIG(sts) :
		WIFEXITED(sts) ? WEXITSTATUS(sts) : -1;
	const msec_t now = due ? mticks() : 0;

	if (due && now >= due) {
	    if (overlimit(child)) {
		(void)kill(child, SIGKILL);
		due = 0;
	    } else {
		due = now + period;
	    }
	} else {
	    msleep(due ? (ulong)(min)(due - now, (msec_t)100) : 100);
	}
    }
#endif
}

int tmain(int argc, const tchar * const argv[]) {
    vector<const tchar *> args(argv, argv + argc);
    WatchDaemon wd(args);

    args.push_back(nullptr);
    return wd.execute((int)args.size() - 1, args.data());
}
