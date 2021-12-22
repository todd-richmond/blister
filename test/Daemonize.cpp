/*
 * Copyright 2001-2019 Todd Richmond
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
    WatchDaemon(int argc, const tchar * const *argv, const tchar *name = NULL);

protected:
    ulong interval, maxmem;
    pid_t cpid;

    virtual bool onRefresh(void);
    virtual int onStart(int argc, const tchar * const *argv);
    virtual void onStop(bool fast);
};

WatchDaemon::WatchDaemon(int argc, const tchar * const *argv, const tchar
    *dname): Daemon(dname ? dname : T("")), interval(60), maxmem(0), cpid(0) {
    int ac;

    for (ac = 2; ac < argc; ++ac) {
	const tchar *p = argv[ac];

	if (*p != '-')
	    break;
	while (*p == '-')
	    ++p;
	if (!tstrcmp(p, T("check")))
	    interval = tstrtoul(argv[++ac], NULL, 10);
	else if (!tstrcmp(p, T("maxmem")))
	    maxmem = tstrtoul(argv[++ac], NULL, 10);
	else if (!tstrcmp(p, T("name")))
	    name = argv[++ac];
	else if (tstrcmp(p, T("console")) && tstrcmp(p, T("daemon")))
	    ++ac;
    }
    if (ac >= argc) {
	const tchar *prog = tstrrchr(argv[0], '/');

	if (!prog && (prog = tstrrchr(argv[0], '\\')) == NULL)
	    prog = argv[0];
	else
	    prog++;
	cout << "usage:\t" << prog << endl <<
	    T("\tstart [--check seconds] [--maxmem kb] [--name str] cmd ...") <<
	    endl <<
	    T("\tcontinue|exit|pause|refresh|status|stop [--name str] cmd") <<
	    endl;
	exit(1);
    }
    if (name.empty()) {
	tstring::size_type i;

	name = argv[ac];
	if ((i = name.find_last_of(T('.'))) != name.npos)
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
    cfg.set(T("watch.maxmem"), maxmem);
    return true;
}

int WatchDaemon::onStart(int argc, const tchar * const *argv) {
    int ac;
    tstring args;
    int ret = Daemon::onStart(argc, argv);

    if (ret)
	return ret;
    for (ac = 1; ac < argc; ac += 2) {
        if (argv[ac][0] != '-')
            break;
    }
    for (int i = ac + 1; i < argc; ++i) {
        if (!args.empty())
            args += ' ';
        args += argv[i];
    }
    running();
    dlogi(Log::mod(name), Log::cmd(T("exec")), Log::kv(T("file"), argv[0]),
	Log::kv(T("args"), args));
    dlog.close();
#ifdef _WIN32
    if (tspawnvp(P_WAIT, argv[ac], (tchar **)&argv[ac]) == 0)
	return 0;
#else
    cpid = fork();
    if (cpid == 0) {
	unsetsignal();
        texecvp(argv[ac], (tchar **)&argv[ac]);
    } else if (cpid > 0) {
        int sts;

	waitpid(cpid, &sts, 0);
	return WEXITSTATUS(sts);
    }
#endif
    dloge(Log::mod(name), Log::cmd(T("exec")), Log::kv(T("file"), argv[0]),
	Log::error(tstrerror(errno)));
    return -1;
}

void WatchDaemon::onStop(bool fast) {
    if (cpid)
	kill(cpid, fast ? SIGTERM : SIGINT);
}

int tmain(int argc, const tchar * const argv[]) {
    WatchDaemon wd(argc, argv);

    return wd.execute(argc, argv);
}
