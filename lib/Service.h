/*
 * Copyright 2001 - 2009 Todd Richmond
 *
 * This file is part of Blister - a light weight, scalable, high performance
 * C++ server infrastructure.
 *
 * Blister is free software: you can redistribute it and/or modify it under the
 * terms of the GNU Lesser General Public License as published by the Free
 * Software Foundation, either version 3 of the License, or any later version.
 *
 * Blister is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
 * A PARTICULAR PURPOSE. See the GNU Lesser General Public License for details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with Blister. If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef Service_h
#define Service_h

#if defined(_WIN32) && !defined(_WIN32_WCE)
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

    Service(const tchar *service, const tchar *host);
    Service(const tchar *service, bool pauseable = false);
    virtual ~Service();

    long error(void) const { return errnum; }
    tstring errstr(void) const;
    string version(void) const { return ver; }
    void version(string s) { ver = ver; }
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
    tstring name;
    tstring path;
    int pid;
    Status stStatus;
    uid_t uid;
    static bool aborted, console, exiting, restart;
    static Service *service;
    static volatile int sigpid;
    static string ver, srvcpath;

    void *open(uint mapsz);
    void exit(int code);
    void handle(ulong sig);
    bool running(void) { return update(Running); }
    virtual int command(const char *cmd, int argc, const char * const *argv)
	{ return -1; }
    virtual int onStart(int argc, const tchar * const *argv);
    virtual void onAbort(void) { fprintf(stderr, "abnormal termination\n"); }
    virtual void onStop(bool fast = false) {}
    virtual void onPause(void) {}
    virtual bool onRefresh(void) { return true; }
    virtual void onResume(void) {}
    virtual void onSigusr1(void) {}
    virtual void onSigusr2(void) {}
    virtual void onSignal(ulong sig) {}
    virtual bool update(Status status);
    static void null_handler(int sig);
    static int run(int argc = 0, const tchar * const *argv = NULL);

 private:
    bool open(void);
    bool close(void);

#ifdef _WIN32
    typedef void (__stdcall *service_ctrl_t)(ulong cmd);

    tstring host;
#ifndef _WIN32_WCE
    HANDLE maphdl;
    void *map;
    uint mapsz;
    SERVICE_STATUS ssStatus;
    SERVICE_STATUS_HANDLE hStatus;
    service_ctrl_t ctrlfunc;
    ulong checkpoint;
    SC_HANDLE hService, hSCManager;
#endif
    static void __stdcall srv_main(ulong argc, tchar **argv);
    static int __stdcall ctrl_handler(ulong sig);
    static void __stdcall service_handler(ulong sig);
    static long __stdcall exception_handler(_EXCEPTION_POINTERS *info);
#else
    Thread sigthread;

    static int ctrl_handler(void *);
#endif
    static void signal_handler(int sig);
};

#if defined(_WIN32) && !defined(_WIN32_WCE)
class ServiceData: nocopy {
public:
    ServiceData(const tchar *service, uint ctrs, uint size);

    virtual DWORD open(LPWSTR lpDeviceNames);
    virtual DWORD close(void);
    virtual DWORD collect(LPWSTR value, LPVOID *data, LPDWORD total,
	LPDWORD types);
    void add(uint size = 4, uint type = PERF_COUNTER_RAWCOUNT,
	uint level = PERF_DETAIL_NOVICE);

private:
    tstring name;
    uint counter;
    uint help;
    uint datasz, mapsz, ctrs;
    uint last, offset;
    volatile int count;
    bool init;
    void *map;
    tchar *data;
};
#endif

class Daemon: public Service {
public:
    enum Quit { None, Slow, Fast };

    Daemon(const tchar *service, const tchar *displayname = NULL,
	bool pauseable = false);
    virtual ~Daemon();

    volatile Quit qflag;

    Config &config(void) { return cfg; }

protected:
    Config cfg;
    tstring cfgfile, instance, installdir;
    pid_t child;
    int lckfd;
    string lckfile;
    bool refreshed;
    time_t start;
    bool watch;

    bool setids(void);

    virtual bool check(string &err) { return true; }
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
