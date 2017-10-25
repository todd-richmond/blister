/*
 * Copyright 2001-2017 Todd Richmond
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

#ifndef Service_h
#define Service_h

#ifdef _WIN32
#include <windows.h>
#include <winperf.h>
#include <winsvc.h>

#else

const int SERVICE_CONTROL_START = 0;
const int SERVICE_CONTROL_PAUSE = 1;
const int SERVICE_CONTROL_CONTINUE = 2;
const int SERVICE_CONTROL_STOP = 3;

enum ServiceStatus {
    SERVICE_PAUSE_PENDING, SERVICE_PAUSED, SERVICE_CONTINUE_PENDING,
    SERVICE_RUNNING, SERVICE_START_PENDING, SERVICE_STOP_PENDING,
    SERVICE_STOPPED
};

#endif

#include "Config.h"

const int SERVICE_CONTROL_REFRESH = 128;
const int SERVICE_CONTROL_ABORT = 129;
const int SERVICE_CONTROL_EXIT = 130;
const int SERVICE_CONTROL_SIGUSR1 = 131;
const int SERVICE_CONTROL_SIGUSR2 = 132;

class Service: nocopy {
public:
    enum Status { Error, Starting, Refreshing, Pausing, Paused, Resuming,
	 Stopping, Running, Stopped };

    Service(const tchar *name, const tchar *host);
    Service(const tchar *name, bool pauseable = false);
    virtual ~Service();

    long error(void) const { return errnum; }
    tstring errstr(void) const;
    const tstring &version(void) const { return ver; }
    void version(const tstring &s) { ver = s; }
    Status status(void);
    bool install(const tchar *path = NULL, const tchar *desc = NULL,
	const tchar * const *depend = NULL, bool manual = false);
    bool uninstall(void);
    int execute(int argc, const tchar * const *argv);
    bool start(int argc, const tchar * const *argv);
    bool stop(bool fast = false) { return send(fast ? SERVICE_CONTROL_EXIT :
	SERVICE_CONTROL_STOP); }
    bool pause(void) { return send(SERVICE_CONTROL_PAUSE); }
    bool resume(void) { return send(SERVICE_CONTROL_CONTINUE); }
    bool refresh(void) { return send(SERVICE_CONTROL_REFRESH); }
    bool sigusr1(void) { return send(SERVICE_CONTROL_SIGUSR1); }
    bool sigusr2(void) { return send(SERVICE_CONTROL_SIGUSR2); }
    bool abort(void) { return send(SERVICE_CONTROL_ABORT); }
    bool send(int sig);

    static void setsignal(bool abrt = false);
    static const tchar *status(Status status);

protected:
    bool bPause;
    long errnum;
    gid_t gid;
    tstring installdir, lckfile, logfile, outfile;
    tstring name;
    tstring path;
    pid_t pid;
    Status stStatus;
    uid_t uid;
    static bool aborted, console, exiting, restart;
    static Service *service;
    static volatile pid_t sigpid;
    static tstring ver, srvcpath;

    void *open(uint mapsz);
    void exit(int code);
    void handle(ulong sig);
    bool running(void) { return update(Running); }
    virtual int command(const tchar *cmd, int argc, const tchar * const *argv) {
	(void)cmd; (void)argc; (void)argv;
	return -1;
    }
    virtual int onStart(int argc, const tchar * const *argv);
    virtual void onAbort(void) { tcerr << T("abnormal termination") << endl; }
    virtual void onStop(bool fast = false) { (void)fast; }
    virtual void onPause(void) {}
    virtual bool onRefresh(void) { return true; }
    virtual void onResume(void) {}
    virtual void onSigusr1(void) {}
    virtual void onSigusr2(void) {}
    virtual void onSignal(ulong sig) { (void)sig; }
    virtual bool update(Status status);
    static void null_handler(int sig);
    static int run(int argc = 0, const tchar * const *argv = NULL);

 private:
    bool close(void);
    bool open(const tchar *file = NULL);
    void set_files(void);
    static void splitpath(const tchar *path, const tchar *name, tstring &root,
	tstring &prog);

#ifdef _WIN32
    typedef void (__stdcall *service_ctrl_t)(ulong cmd);

    tstring host;
    HANDLE maphdl;
    void *map;
    uint mapsz;
    SERVICE_STATUS ssStatus;
    SERVICE_STATUS_HANDLE hStatus;
    service_ctrl_t ctrlfunc;
    ulong checkpoint;
    SC_HANDLE hService, hSCManager;
    static int __stdcall ctrl_handler(ulong sig);
    static long __stdcall exception_handler(_EXCEPTION_POINTERS *info);
    static void __stdcall service_handler(ulong sig);
    static void __stdcall srv_main(ulong argc, tchar **argv);
#else
    Thread sigthread;

    static int ctrl_handler(void *);
#endif
    static void signal_handler(int sig);
};

#ifdef _WIN32
class ServiceData: nocopy {
public:
    ServiceData(const tchar *service, uint ctrs, uint size);

    virtual DWORD open(LPWSTR lpDeviceNames);
    virtual DWORD close(void);
    virtual DWORD collect(LPCWSTR value, LPVOID *data, LPDWORD total, LPDWORD
	types);
    void add(uint size = 4, uint type = PERF_COUNTER_RAWCOUNT, uint level =
	PERF_DETAIL_NOVICE);

private:
    volatile int count;
    uint counter;
    char *data;
    uint ctrs, datasz, mapsz;
    uint help;
    bool init;
    uint last, offset;
    void *map;
    tstring name;
};
#endif

class Daemon: public Service {
public:
    enum Quit { None, Slow, Fast };

    Daemon(const tchar *name, const tchar *display = NULL, bool pauseable =
	false);
    virtual ~Daemon();

    volatile Quit qflag;

    Config &config(void) { return cfg; }

protected:
    Config cfg;
    tstring cfgfile, instance;
    pid_t child;
    int lckfd;
    bool refreshed;
    time_t start;
    bool watch;

    bool setids(void);

    virtual bool check(string &err) { (void)err; return true; }
    virtual int onStart(int argc, const tchar * const *argv);
    virtual void onAbort(void);
    virtual void onPause(void);
    virtual void onResume(void);
    virtual bool onRefresh(void);
    virtual void onStop(bool fast);
    virtual void onSigusr1(void);
    virtual bool update(Status status);

private:
    static void watch_handler(int sig);
};

class WatchDaemon: public Daemon {
public:
    WatchDaemon(int argc, const tchar * const *argv, const tchar *name = NULL);

protected:
    ulong interval, maxmem;

    virtual int onStart(int argc, const tchar * const *argv);
    virtual bool onRefresh(void);
};


#endif // Service_h
