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

#ifndef Service_h
#define Service_h

#ifdef _WIN32
#include <Windows.h>
#include <winperf.h>
#include <winsvc.h>

#else
#include <signal.h>

constexpr int SERVICE_CONTROL_START = 0;
constexpr int SERVICE_CONTROL_PAUSE = 1;
constexpr int SERVICE_CONTROL_CONTINUE = 2;
constexpr int SERVICE_CONTROL_STOP = 3;

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

class BLISTER Service: nocopy {
public:
    enum Status { Error, Pausing, Paused, Refreshing, Resuming, Running,
	Starting, Stopping, Stopped };		// NOSONAR

    class BLISTER Timer: nocopy {
    public:
	explicit Timer(ulong msec = 0);
	~Timer() { cancel(); }

	void cancel(void);

	static ulong dmsec;

    private:
	timer_t timer;
    };

    // lock bytes: watcher held, up but not serving, per worker status ranges
    static constexpr uint Watching = 20;
    static constexpr uint Unavailable = 21;
    static constexpr uint Slots = 32;
    static constexpr uint SlotSize = 16;

    Service(const tchar *name, const tchar *host);
    explicit Service(const tchar *name, bool pauseable = false);
    virtual ~Service();

    long error(void) const { return errnum; }
    tstring errstr(void) const;
    Status status(void);
    bool install(const tchar *path = nullptr, const tchar *desc = nullptr,
	const tchar * const *depend = nullptr, bool manual = false);
    bool uninstall(void);
    int execute(int argc, const tchar * const *argv);
    int start(int argc, const tchar * const *argv);
    bool stop(bool fast = false) {
	return send(fast ? SERVICE_CONTROL_EXIT : SERVICE_CONTROL_STOP);
    }
    bool abort(void) { return send(SERVICE_CONTROL_ABORT); }
    bool pause(void) { return send(SERVICE_CONTROL_PAUSE); }
    bool refresh(void) { return send(SERVICE_CONTROL_REFRESH); }
    bool resume(void) { return send(SERVICE_CONTROL_CONTINUE); }
    bool sigusr1(void) { return send(SERVICE_CONTROL_SIGUSR1); }
    bool sigusr2(void) { return send(SERVICE_CONTROL_SIGUSR2); }
    bool send(int sig);

    static void setsignal(bool abrt = false);
    static const tchar *status(Status status);
    static void unsetsignal(void);
    static const tstring &version(void) { return ver; }
    static void version(const tstring &s) { ver = s; }

protected:
    bool bPause = false;
    long errnum = 0;
    gid_t gid = 0;
    tstring installdir, lckfile, logfile, outfile;
    tstring name;
    tstring path;
    pid_t pid = 0;
    atomic<Status> stStatus = Stopped;
    uid_t uid = 0;
#ifdef _WIN32
    tstring wkrarg;			// --worker: slot and inherited handles
#endif
    static bool aborted;
    static atomic<bool> aborting;
    static bool console;
    static bool exiting;
    static bool restart;
    static Service *service;
    static atomic<pid_t> sigpid;
    static tstring srvcpath;
    static tstring ver;
    static atomic<pid_t> watchpid;

#ifdef _WIN32
    void *open(uint mapsz);
#endif
    [[noreturn]] void exit(int code);
    void handle(ulong sig);
    bool running(void) { return update(Running); }
    virtual int command(const tchar *cmd, int argc, const tchar * const *argv) {
	(void)cmd; (void)argc; (void)argv;
	return -1;
    }
    virtual void onAbort(void) { tcerr << T("abnormal termination") << endl; }
    virtual void onPause(void) {}
    virtual bool onRefresh(void) { return true; }
    virtual void onResume(void) {}
    virtual void onSigusr1(void) {}
    virtual void onSigusr2(void) {}
    virtual void onSignal(ulong sig) { (void)sig; }
    virtual int onStart(int argc, const tchar * const *argv);
    virtual void onStop(bool fast) { (void)fast; }
    virtual void onTimer(ulong timer);
#ifdef _WIN32
    // true when a watcher queued ctl for its workers
    virtual bool onWatch(ulong ctl) { (void)ctl; return false; }
#endif
    virtual bool update(Status status);
    static void null_handler(int sig);
#ifndef _WIN32
    static void sigalrm(void (*fn)(int));
#endif
    static int run(int argc = 0, const tchar * const *argv = nullptr);

private:
    bool close(void);
    bool open(const tchar *file = nullptr);
    void set_files(void);
    static void splitpath(const tchar *path, const tchar *name, tstring &root,
	tstring &prog);

#ifdef _WIN32
    using service_ctrl_t = void (__stdcall *)(ulong cmd);

    service_ctrl_t ctrlfunc = nullptr;
    ulong checkpoint = 0;
    tstring host;
    SC_HANDLE hService = 0, hSCManager = 0;
    SERVICE_STATUS_HANDLE hStatus = 0;
    void *map = nullptr;
    HANDLE maphdl = 0;
    uint mapsz = 0;
    SERVICE_STATUS ssStatus{};
    static int __stdcall ctrl_handler(ulong sig);
    static long __stdcall exception_handler(_EXCEPTION_POINTERS *info);
    static void __stdcall service_handler(ulong sig);
    static void signal_handler(int sig);
    static void __stdcall srv_main(ulong argc, tchar **argv);
#else
    Thread sigthread;

    static void abort_handler(void);
    static void abort_handler(int) { abort_handler(); }
#if defined(__linux__) || defined(__FreeBSD__)
    static void abort_handler(sigval) { abort_handler(); }
#endif
    static int ctrl_handler(void *);
    static void init_sigset(sigset_t &sigs);
    static void signal_handler(int sig, siginfo_t *si, void *context);
#endif
};

#ifdef _WIN32
class BLISTER ServiceData: nocopy {
public:
    ServiceData(const tchar *service, uint ctrs, uint size);
    virtual ~ServiceData() = default;

    virtual DWORD open(LPWSTR lpDeviceNames);
    virtual DWORD close(void);
    virtual DWORD collect(LPCWSTR value, LPVOID *data, LPDWORD total, LPDWORD
	types);
    void add(uint size = 4, uint type = PERF_COUNTER_RAWCOUNT, uint level =
	PERF_DETAIL_NOVICE);

private:
    atomic_int count = 0;
    uint counter = 0;
    char *data = nullptr;
    uint ctrs, datasz = 0, mapsz;
    uint help = 0;
    bool init = false;
    uint last = 0, offset = 0;
    void *map = nullptr;
    tstring name;
    static Lock lock;
};
#endif

class BLISTER Daemon: public Service {
public:
    enum Quit { None, Slow, Fast };

    using Service::Service;
    explicit Daemon(const tchar *name, const tchar *display = nullptr,
	bool pauseable = false);
    virtual ~Daemon();

    atomic<Quit> qflag = None;

    Config &config(void) { return cfg; }

protected:
    ConfigFile cfg;
    tstring cfgfile, instance;
    Lock forklock;			// held to refresh or fork workers
    int lckfd = -1;
    msec_t msec = mticks();
    uint nworkers = 1;			// worker.count default
    bool refreshed = false;
    int slot = -1;			// worker index, -1 outside a worker
    bool watch = false;

    bool setids(void);
    void unavailable(bool state);
    bool worker(void) const { return slot >= 0; }

    virtual bool check(Status status, tstring &err) {
	(void)status; (void)err;
	return true;
    }
    int onStart(int argc, const tchar * const *argv) override;
    void onAbort(void) override;
    // runs once before workers fork so they share its state, such as listen
    // sockets (in each worker on Windows); must not leave threads running
    virtual int onInit(int argc, const tchar * const *argv) {
	(void)argc; (void)argv;
	return 0;
    }
    void onPause(void) override;
    // around each worker fork: parent before, then parent and child after
    virtual void onPostFork(bool child) { (void)child; }
    virtual void onPreFork(void) {}
#ifdef _WIN32
    // watcher: handles a new worker inherits; worker: them, before onInit()
    virtual void onSpawn(vector<HANDLE> &handles) { (void)handles; }
#endif
    void onResume(void) override;
    bool onRefresh(void) override;
    void onStop(bool fast) override;
    void onSigusr1(void) override;
    bool update(Status status) override;
    static ulong addTimer(ulong msec = 0);

private:
    struct Worker {
	msec_t kill;		// next SIGKILL after a stop, 0 if none
	msec_t since;		// last status change
	msec_t start;
	pid_t pid;
	uint slot;
	Status status;
	bool first;		// started with the service
	bool ran;		// seen serving
#ifdef _WIN32
	HANDLE ctl;		// control pipe write end
	HANDLE proc;
	PTP_WAIT wait;		// sets wakeev on exit
#endif
    };

#ifdef _WIN32
    static constexpr uint MaxSlots = 4096;

    Lock ctllck;
    HANDLE ctlpipe = nullptr;		// worker: read end from the watcher
    vector<ulong> ctls;			// controls to forward
    HANDLE job = nullptr;		// kills workers when the watcher exits
    atomic<uchar> *stmap = nullptr;	// per slot worker status + 1
    HANDLE stmaphdl = nullptr;
    vector<const tchar *> wargs;	// watcher args passed to workers
    atomic<HANDLE> wakeev = nullptr;
#else
    atomic<uint64_t> sigpend = 0;	// forwarded signal mask
    atomic<uint64_t> sigsrc[NSIG] = {};	// sender uid << 32 | pid
    int wakefd[2] = {-1, -1};
#endif
    vector<Worker> wkrs;

    void configfile(int argc, const tchar * const *argv);
#ifdef _WIN32
    bool onWatch(ulong ctl) override;
    bool spawn(Worker &w);
    int spawned(int argc, const tchar * const *argv);
#endif
    int slotstatus(uint s) const;
    int watchloop(void);
#ifdef _WIN32
    static ulong __stdcall ctlread(void *);
#endif
    static uint swap_pct(void);
#ifndef _WIN32
    static void watch_handler(int sig, siginfo_t *si, void *context);
#endif
};

#endif // Service_h
