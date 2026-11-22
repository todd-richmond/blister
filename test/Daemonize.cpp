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
    WatchDaemon(int argc, const tchar * const *argv);

protected:
    atomic<pid_t> cpid = 0;		// read by onStop on the signal thread
    ulong interval = 60, maxmem = 0;

    bool onRefresh(void) override;
    int onStart(int argc, const tchar * const *argv) override;
    void onStop(bool fast) override;

private:
    static int cmdindex(int argc, const tchar * const *argv);
    // options without a value; every other option is followed by one
    static bool flagopt(const tchar *p) {
	return tstreq(p, T("console")) || tstreq(p, T("daemon"));
    }
    void stopchild(bool fast) const;
};

// index of the command word after global options
int WatchDaemon::cmdindex(int argc, const tchar * const *argv) {
    int ac;

    for (ac = 1; ac < argc && *argv[ac] == '-'; ++ac) {
	if (!flagopt(argv[ac] + tstrspn(argv[ac], T("-"))))
	    ++ac;
    }
    return ac;
}

void WatchDaemon::stopchild(bool fast) const {
#ifdef _WIN32
    (void)fast;
    kill(cpid, SIGKILL);	// console Ctrl-C can't target one process
#else
    kill(cpid, fast ? SIGTERM : SIGINT);
#endif
}

WatchDaemon::WatchDaemon(int argc, const tchar * const *argv):
    Daemon(T("")) {
    int ac;

    for (ac = cmdindex(argc, argv) + 1; ac < argc; ++ac) {
	const tchar *p = argv[ac];

	if (*p != '-')
	    break;
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
}

bool WatchDaemon::onRefresh(void) {
    if (!Daemon::onRefresh())
	return false;
    if (interval)
	cfg.set(T("watch.interval"), interval);
    else
	cfg.set(T("watch.enable"), false);
    cfg.set(T("watch.maxpss"), maxmem);
    return true;
}

int WatchDaemon::onStart(int argc, const tchar * const *argv) {
    int ac;
    tstring args;
#ifdef _WIN32
    intptr_t hdl;
#else
    pid_t child;
#endif
    int ret = Daemon::onStart(argc, argv);

    if (ret)
	return ret;
    if ((ac = cmdindex(argc, argv)) >= argc) {
	dloge(Log::mod(name), Log::cmd(T("exec")),
	    Log::error(T("no command")));
	return -1;
    }
    for (int i = ac + 1; i < argc; ++i) {
	if (!args.empty())
	    args += ' ';
	args += argv[i];
    }
    running();
    dlogi(Log::mod(name), Log::cmd(T("exec")), Log::kv(T("file"), argv[ac]),
	Log::kv(T("args"), args));
    // a buffered log's flush thread isn't forked so the child can't wait on it
    dlog.stop();
    (void)dlog.close();
#ifdef _WIN32
    hdl = tspawnvp(P_NOWAIT, argv[ac], (tchar *const *)&argv[ac]);
    dlog.start();
    if (hdl != -1) {
	DWORD sts;

	cpid = (pid_t)GetProcessId((HANDLE)hdl);
	if (qflag != None)		// stop arrived before cpid was set
	    stopchild(qflag == Fast);
	WaitForSingleObject((HANDLE)hdl, INFINITE);
	cpid = 0;
	if (!GetExitCodeProcess((HANDLE)hdl, &sts))
	    sts = (DWORD)-1;
	CloseHandle((HANDLE)hdl);
	return (int)sts;
    }
#else
    if ((child = fork()) == 0) {
	unsetsignal();
	texecvp(argv[ac], (tchar *const *)&argv[ac]);	// NOSONAR
	dloge(Log::mod(name), Log::cmd(T("exec")), Log::kv(T("file"),
	    argv[ac]), Log::error(tstrerror(errno)));
	dlog.flush();
	_exit(127);
    }
    dlog.start();
    if (child > 0) {
	int sts;

	cpid = child;
	if (qflag != None)		// stop arrived before cpid was set
	    stopchild(qflag == Fast);
	while ((ret = waitpid(child, &sts, 0)) == -1 && errno == EINTR)
	    ;
	cpid = 0;
	if (ret != -1)
	    return WIFSIGNALED(sts) ? 128 + WTERMSIG(sts) : WEXITSTATUS(sts);
    }
#endif
    dloge(Log::mod(name), Log::cmd(T("exec")), Log::kv(T("file"), argv[ac]),
	Log::error(tstrerror(errno)));
    return -1;
}

void WatchDaemon::onStop(bool fast) {
    Daemon::onStop(fast);
    if (cpid)
	stopchild(fast);
}

int tmain(int argc, const tchar * const argv[]) {
    WatchDaemon wd(argc, argv);

    return wd.execute(argc, argv);
}
