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
#include <fcntl.h>
#include <ranges>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include "Log.h"
#include "Service.h"

#ifdef _WIN32
#include <process.h>

#pragma comment(lib, "advapi32.lib")

#define DWORD_MULTIPLE(x) ((((x) + sizeof (DWORD) - 1 ) / sizeof (DWORD)) * \
    sizeof (DWORD))
#define SERVICE_PREFIX T("service_")
#endif

static constexpr uint STATUS_LOOPS = 400;
// the watcher's default stop wait plus time to kill hung workers
static constexpr uint STOP_LOOPS = 750;

ulong Service::Timer::dmsec = 120000;
bool Service::aborted;
atomic<bool> Service::aborting;
bool Service::console;
bool Service::exiting;
bool Service::restart;
tstring Service::srvcpath;
Service *Service::service;
atomic<pid_t> Service::sigpid, Service::watchpid;
tstring Service::ver(T(__DATE__) T(" ") T(__TIME__));

void Service::splitpath(const tchar *full, const tchar *id, tstring &root,
    tstring &prog) {
    tchar buf[PATH_MAX + 2];
    const tchar *p = tgetenv(T("installdir"));
    tstring::size_type pos;
    const tchar *sep;

    (void)id;
    if (p) {
	root = p;
    } else {
	if (full[0] == '.' && full[1] == '/')
	    full += 2;
	if (full[0] != '/' && (!full[0] || full[1] != ':') &&
	    tgetcwd(buf, size(buf))) {
	    root = buf;
	    root += '/';
	    root += full;
	} else {
	    root = full;
	}
	if ((pos = root.find_last_of('/')) == root.npos &&
	    (pos = root.find_last_of('\\')) == root.npos)
	    pos = 0;
	else if (pos >= 4 && (root[pos - 4] == '/' || root[pos - 4] == '\\') &&
	    !tstrnicmp(root.c_str() + pos - 3, T("bin"), 3))
	    pos -= 4;
	else if (pos >= 6 && (root[pos - 6] == '/' || root[pos - 6] == '\\') &&
	    !tstrnicmp(root.c_str() + pos - 5, T(".libs"), 5))
	    pos -= 6;
	root.erase(pos);
    }
#ifdef _WIN32
    if (service) {
	HKEY key;
	DWORD size;
	DWORD type;

	tsprintf(buf, T("SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters"),
	    id ? id : T("Service"));
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
	    buf, 0L, KEY_QUERY_VALUE, &key) == ERROR_SUCCESS) {
	    size = sizeof (buf);
	    if (RegQueryValueEx(key, T("Install Directory"), 0L, &type,
		(LPBYTE)&buf, &size)) {
		dlog.warn(Log::mod(id), Log::error(T("install key missing")));
	    } else {
		full = buf;
	    }
	    RegCloseKey(key);
	}
    }
#endif
    if ((p = tstrrchr(full, '/')) == nullptr &&
	(p = tstrrchr(full, '\\')) == nullptr)
	p = full;
    else
	p++;
    if ((sep = tstrrchr(full, '.')) != nullptr &&
	!tstrnicmp(sep, T(".exe"), 4))
	prog.assign(p, (tstring::size_type)(sep - p));
    else
	prog = p;
}

#ifdef _WIN32

Service::Timer::Timer(ulong msec): timer(NULL) {
    (void)msec;
    (void)timer;
}

void Service::Timer::cancel() {}		// NOSONAR

Service::Service(const tchar *servicename, const tchar *h):
    name(servicename) {
    if (h)
	host = h;
}

Service::Service(const tchar *servicename, bool pauseable): bPause(pauseable),
    name(servicename), ctrlfunc(&service_handler) {
    service = this;
}

Service::~Service() {
    if (ctrlfunc)
	service = nullptr;
    close();
}

bool Service::open(const tchar *file) {
    const tchar *s = host.c_str();

    (void)file;
    if (!hSCManager)
	hSCManager = OpenSCManager(*s ? s : NULL, NULL,	SC_MANAGER_ALL_ACCESS);
    if (hSCManager) {
	if (!hService)
	    hService = OpenService(hSCManager, name.c_str(), SERVICE_ALL_ACCESS);
	if (hService)
	    return true;
    }
    errnum = GetLastError();
    return false;
}

bool Service::close() {
    if (map) {
	UnmapViewOfFile(map);
	map = nullptr;
    }
    if (maphdl) {
	CloseHandle(maphdl);
	maphdl = 0;
    }
    if (hService) {
	CloseServiceHandle(hService);
	hService = nullptr;
    }
    if (hSCManager) {
	CloseServiceHandle(hSCManager);
	hSCManager = nullptr;
	return true;
    }
    return false;
}

int __stdcall Service::ctrl_handler(ulong sig) {
    ulong ctl = sig == CTRL_C_EVENT ? SERVICE_CONTROL_STOP : sig ==
	CTRL_BREAK_EVENT ? SERVICE_CONTROL_REFRESH : sig == CTRL_CLOSE_EVENT ||
	sig == CTRL_SHUTDOWN_EVENT ? SERVICE_CONTROL_EXIT : 0;

    if (ctl && service->onWatch(ctl)) {
	return 1;
    } else if (sig == CTRL_BREAK_EVENT) {
	if (!service->onRefresh())
	    service->onStop(false);
    } else if (sig == CTRL_C_EVENT) {
	service->onStop(false);
    } else if (sig == CTRL_SHUTDOWN_EVENT || sig == CTRL_CLOSE_EVENT) {
	service->onStop(true);
#ifndef NDEBUG
    } else {
	DebugBreak();
#endif
    }
    dlog.flush();
    return 1;
}

void Service::signal_handler(int sig) {
    if (!aborted && (sig == SIGABRT || sig == SIGFPE || sig == SIGILL || sig ==
	SIGSEGV))
	service->onAbort();
    _exit(sig);
}

long Service::exception_handler(_EXCEPTION_POINTERS *) {
    if (!aborted)
	service->onAbort();
    _exit(1);
}

void Service::setsignal(bool abrt) {
    if (console)
	SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOOPENFILEERRORBOX |
	    SEM_NOGPFAULTERRORBOX);
    if (abrt) {
	signal(SIGABRT, signal_handler);
	signal(SIGFPE, signal_handler);
	signal(SIGILL, signal_handler);
	signal(SIGSEGV, signal_handler);
	SetUnhandledExceptionFilter(exception_handler);
    }
    SetProcessShutdownParameters(0x380, 0);
    SetConsoleCtrlHandler(ctrl_handler, TRUE);
}

int Service::run(int argc, const tchar * const *argv) {
    int ret;

    sigpid = getpid();
    if (console) {
	ret = service->onStart(argc, argv);
	exiting = true;
	dlog.stop();
    } else {
	SERVICE_TABLE_ENTRY entry[] = {
	    { service->name.data(), srv_main },
	    { NULL, NULL }
	};

	FreeConsole();
	AllocConsole();
	ret = StartServiceCtrlDispatcher(entry) == FALSE;
    }
    return ret;
}

void __stdcall Service::srv_main(DWORD argc, tchar **argv) {
    tchar *arg0 = argv[0];
    bool debug = false;
    tchar modulename[PATH_MAX];
    int ret = 0;

    if (service->name == argv[0])
	service->hStatus = RegisterServiceCtrlHandler(service->name.c_str(),
	    service->ctrlfunc);
    else if (!service->hStatus)
	return;
    GetModuleFileName(NULL, modulename, (DWORD)size(modulename));
    argv[0] = modulename;
    service->ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    service->ssStatus.dwServiceSpecificExitCode = 0;
    service->ssStatus.dwWin32ExitCode = 0;
    for (uint u = 1; u < argc; u++) {
	if (tstreq(T("debug"), argv[u])) {
	    debug = true;
	    break;
	}
    }
    if (service->update(Starting)) {
	if (debug) {
	    service->update(Running);
	    DebugBreak();
	}
	ret = service->onStart(argc, argv);
    }
    argv[0] = arg0;
    service->ssStatus.dwWin32ExitCode = ret;
    dlog.stop();
    if (!console)
	setsignal(true);
    service->update(Stopped);
}

void __stdcall Service::service_handler(ulong sig) {
    service->handle(sig);
}

void Service::handle(ulong sig) {
    if (sig != SERVICE_CONTROL_ABORT && sig != SERVICE_CONTROL_INTERROGATE &&
	onWatch(sig))
	return;
    switch (sig) {
    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
	update(Stopping);
	GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0); // -V549
	break;
    case SERVICE_CONTROL_ABORT:
	onAbort();
	_exit(1);
	break;
    case SERVICE_CONTROL_EXIT:
	update(Stopping);
	onStop(true);
	break;
    case SERVICE_CONTROL_PAUSE:
	update(Pausing);
	onPause();
	update(Paused);
	break;
    case SERVICE_CONTROL_CONTINUE:
	update(Resuming);
	onResume();
	update(Running);
	break;
    case SERVICE_CONTROL_INTERROGATE:
	update(stStatus);
	break;
    case SERVICE_CONTROL_REFRESH:
	update(Refreshing);
	GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, 0);
	update(Running);
	break;
    case SERVICE_CONTROL_SIGUSR1:
	onSigusr1();
	break;
    case SERVICE_CONTROL_SIGUSR2:
	onSigusr2();
	break;
    default:
	onSignal(sig);
	break;
    }
    dlog.flush();
}

bool Service::update(Status status) {
    DWORD state;

    stStatus = status;
    switch (status) {
    case Starting:
	state = SERVICE_START_PENDING;
	break;
    case Refreshing:
	return true;
    case Pausing:
	state = SERVICE_PAUSE_PENDING;
	break;
    case Paused:
	state = SERVICE_PAUSED;
	break;
    case Resuming:
	state = SERVICE_CONTINUE_PENDING;
	break;
    case Stopping:
	state = SERVICE_STOP_PENDING;
	break;
    case Running:
	state = SERVICE_RUNNING;
	break;
    case Stopped:
	state = SERVICE_STOPPED;
	break;
    default:
	return false;
    }
    ssStatus.dwCurrentState = state;
    ssStatus.dwWaitHint = 3000;
    if (state == SERVICE_STOPPED)
	ssStatus.dwControlsAccepted = 0;
    else
	ssStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN |
	    SERVICE_ACCEPT_STOP | (bPause && state != SERVICE_START_PENDING ?
	    SERVICE_ACCEPT_PAUSE_CONTINUE : 0);
    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED)
	ssStatus.dwCheckPoint = checkpoint = 0;
    else
	ssStatus.dwCheckPoint = ++checkpoint;
    return SetServiceStatus(hStatus, &ssStatus) != FALSE;
}

bool Service::install(const tchar *file, const tchar *desc, const tchar * const
    *depend, bool manual) {
    tchar buf[PATH_MAX];
    size_t i;
    tchar *p = nullptr;
    tstring prog;

    if (uninstall())
	open();
    if (!file) {
	GetModuleFileName(NULL, buf, (DWORD)size(buf));
	file = buf;
    }
    if (!desc) {
	tstring root;

	splitpath(file, NULL, root, prog);
	prog[0] = (tchar)totupper(prog[0]);
	for (i = 1; i < prog.size(); i++)
	    prog[i] = (tchar)totlower(prog[i]);
	desc = prog.c_str();
    }
    if (depend) {
	tchar *pp;
	size_t sz = 0;

	for (i = 0; depend[i]; i++)
	    sz += tstrlen(depend[i]) + 1;
	pp = p = new tchar[sz + 1];
	for (i = 0; depend[i]; i++) {
	    tstrcpy(pp, depend[i]);
	    pp += tstrlen(pp);
	    *pp++ = '\0';
	}
	*pp = '\0';
    }
    hService = CreateService(hSCManager, name.c_str(),
	desc, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
	manual ? SERVICE_DEMAND_START : SERVICE_AUTO_START,
	SERVICE_ERROR_NORMAL, file, NULL, NULL, p, NULL, NULL);
    errnum = GetLastError();
    delete [] p;
    return hService != nullptr;
}

bool Service::uninstall() {
    stop();
    if (DeleteService(hService)) {
	close();
	return true;
    }
    return false;
}

int Service::start(int argc, const tchar *const *argv) {
    if (!open())
	return (int)errnum;
    errnum = StartService(hService, argc - 1, (LPCTSTR *)&argv[1]) ? // NOSONAR
	0 : GetLastError();
    return errnum;
}

bool Service::send(int sig) {
    const DWORD newstate = sig == SERVICE_CONTROL_STOP ||
	sig == SERVICE_CONTROL_ABORT || sig == SERVICE_CONTROL_EXIT ?
	SERVICE_STOPPED : sig == SERVICE_CONTROL_PAUSE ? SERVICE_PAUSED :
	SERVICE_RUNNING;
    SERVICE_STATUS status;

    if (!open())
	return false;
    if (!ControlService(hService, (DWORD)sig, &status)) {
	errnum = GetLastError();
	return sig == SERVICE_CONTROL_STOP &&
	    (errnum == ERROR_SERVICE_NOT_ACTIVE ||
	    errnum == ERROR_SERVICE_CANNOT_ACCEPT_CTRL);
    } else {
	int cnt = 0;

	while (status.dwCurrentState != newstate) {
	    if (++cnt == STATUS_LOOPS)
		return false;
	    msleep(100);
	    (void)QueryServiceStatus(hService, &status);
	}
    }
    return true;
}

Service::Status Service::status() {
    SERVICE_STATUS ss;

    if (!open() || !QueryServiceStatus(hService, &ss)) {
	errnum = GetLastError();
	return Error;
    }
    switch (ss.dwCurrentState) {
    case SERVICE_STOP_PENDING:
	return Stopping;
    case SERVICE_STOPPED:
	return Stopped;
    case SERVICE_PAUSE_PENDING:
	return Pausing;
    case SERVICE_PAUSED:
	return Paused;
    case SERVICE_CONTINUE_PENDING:
	return Resuming;
    case SERVICE_START_PENDING:
	return Starting;
    case SERVICE_RUNNING:
	return Running;
    default:
	return Error;
    }
}

[[noreturn]] void Service::exit(int code) {
    ssStatus.dwWin32ExitCode = code;
    update(Stopped);
    _exit(code);
}

tstring Service::errstr() const {
    tchar *msg = nullptr;
    tstring s(T("Service Error"));

    if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
	FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL,
	errnum, LANG_NEUTRAL, (tchar *)&msg, 0, NULL)) {
	s = msg;
	LocalFree((HLOCAL)msg);
    }
    return s;
}

void *Service::open(uint size) {
    tstring s(SERVICE_PREFIX + name);

    mapsz = size;
    if ((maphdl = CreateFileMapping((HANDLE)-1, NULL, PAGE_READWRITE, 0, mapsz,
	s.c_str())) == nullptr)
	return nullptr;
    if ((map = MapViewOfFile(maphdl, FILE_MAP_WRITE, 0, 0, mapsz)) == nullptr) {
	CloseHandle(maphdl);
	maphdl = 0;
	return nullptr;
    }
    return map;
}

Lock ServiceData::lock;

ServiceData::ServiceData(const tchar *service, uint num, uint size):
    ctrs(num), mapsz(size), name(service) {}

DWORD ServiceData::open(LPWSTR lpDeviceNames) {
    FastLocker lkr(lock);

    (void)lpDeviceNames;
    if (!init) {
	HANDLE hdl;
	LONG status;
	HKEY key;
	DWORD size;
	DWORD type;
	DWORD namesz;
	PERF_INSTANCE_DEFINITION *pid;
	PERF_COUNTER_BLOCK *pcb;

	tstring s(T("SYSTEM\\CurrentControlSet\\Services\\") + name +
	    T("\\Performance"));

	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
	    s.c_str(), 0L, KEY_QUERY_VALUE, &key) != ERROR_SUCCESS) {
	    dlog.err(Log::mod(name), Log::error(
		T("unable to open performance registry")));
	    return 1;
	}
	size = sizeof (counter);
	status = RegQueryValueEx(key, T("First Counter"), 0L, &type,
	    (LPBYTE)&counter, &size);
	size = sizeof (help);
	if (!status)
	    status = RegQueryValueEx(key, T("First Help"), 0L,
		&type, (LPBYTE)&help, &size);
	if (status) {
	    dlog.err(Log::mod(name), Log::error(
		T("unable to read performance counters")));
	    RegCloseKey(key);
	    return 1;
	}
	RegCloseKey(key);
	s = SERVICE_PREFIX + name;
	if ((hdl = OpenFileMapping(FILE_MAP_READ, FALSE, s.c_str())) == nullptr)
	    return 1;
	if ((map = MapViewOfFile(hdl, FILE_MAP_READ, 0, 0, mapsz)) == nullptr) {
	    CloseHandle(hdl);
	    return 1;
	}
	CloseHandle(hdl);
	namesz = (DWORD)name.length() * 2;
	if (namesz)
	    namesz += sizeof (WCHAR);
	size = (DWORD)(sizeof (PERF_OBJECT_TYPE) +
	    ctrs * sizeof (PERF_COUNTER_DEFINITION));
	datasz = (uint)(size + sizeof (PERF_INSTANCE_DEFINITION) + DWORD_MULTIPLE(
	    namesz) + sizeof (PERF_COUNTER_BLOCK));
	data = new char[datasz]();
	PERF_OBJECT_TYPE *pot = (PERF_OBJECT_TYPE *)data;
	pot->TotalByteLength = datasz + mapsz;
	pot->DefinitionLength = size;
	pot->HeaderLength = sizeof (PERF_OBJECT_TYPE);
	pot->DetailLevel = PERF_DETAIL_NOVICE;
	pot->NumCounters = ctrs;
	pot->NumInstances = 1;
	pot->ObjectNameTitleIndex = counter;
	pot->ObjectHelpTitleIndex = help;
	pid = (PERF_INSTANCE_DEFINITION *)(data + size);
	pid->ByteLength = (DWORD)(sizeof (PERF_INSTANCE_DEFINITION) +
	    DWORD_MULTIPLE(namesz) + 4);
	pid->ParentObjectTitleIndex = 0;
	pid->ParentObjectInstance = 0;
	pid->UniqueID = PERF_NO_UNIQUE_ID;
	pid->NameOffset = sizeof (PERF_INSTANCE_DEFINITION);
	pid->NameLength = namesz;
#ifdef _UNICODE
	wcscpy((wchar_t *)(pid + 1), name.c_str());
#else
	mbstowcs((wchar_t *)(pid + 1), name.c_str(), name.length() + 1);
#endif
	pcb = (PERF_COUNTER_BLOCK *)((char *)pid + pid->ByteLength);
	pcb->ByteLength = (DWORD)(sizeof (PERF_COUNTER_BLOCK) + mapsz);
	init = true;
    }
    count++;
    return 0;
}

DWORD ServiceData::close(void) {
    FastLocker lkr(lock);

    if (!--count) {
	init = false;
	UnmapViewOfFile(map);
	map = nullptr;
	delete [] data;
    }
    return 0;
}

DWORD ServiceData::collect(LPCWSTR value, LPVOID *datap, LPDWORD total, LPDWORD
    types) {
    *types = 0;
    if (!init)
	return ERROR_SUCCESS;
    if (value && !wcscmp(value, L"Foreign")) {
	return ERROR_SUCCESS;
    }
    if (*total < datasz + mapsz)
	return ERROR_MORE_DATA;
    memcpy(*datap, data, datasz);
    memcpy((char *)*datap + datasz, map, mapsz);
    *total = datasz + mapsz;
    *datap = (char *)*datap + *total;
    *types = 1;
    return 0;
}

void ServiceData::add(uint size, uint type, uint level) {
    PERF_COUNTER_DEFINITION *pcd = (PERF_COUNTER_DEFINITION *)
	(data + sizeof (PERF_OBJECT_TYPE)) + last;

    pcd->ByteLength = sizeof (PERF_COUNTER_DEFINITION);
    pcd->CounterNameTitleIndex = (last + 1) * 2 + counter;
    pcd->CounterHelpTitleIndex = (last + 1) * 2 + help;
    pcd->CounterType = type;
    pcd->CounterSize = size;
    pcd->DetailLevel = level;
    pcd->CounterOffset = offset;
    last++;
    offset += size;
}

#else	// Unix

#include <grp.h>
#include <poll.h>
#include <pwd.h>
#include <sys/file.h>
#ifdef __linux__
#include <sys/prctl.h>
#include <sys/sysinfo.h>
#endif
#ifdef __APPLE__
#include <dispatch/dispatch.h>
#include <sys/sysctl.h>
#endif
#ifdef BSD_BASE
#include <sys/event.h>
#endif
#ifdef __FreeBSD__
#include <sys/procctl.h>
#include <sys/sysctl.h>
#include <vm/vm_param.h>
#elif defined(__OpenBSD__)
#include <sys/swap.h>
#endif
#include <sys/resource.h>
#include <sys/wait.h>

// timer_create(), sigqueue() and sigwaitinfo()
#if defined(__linux__) || defined(__FreeBSD__)
#define POSIX_RT
#endif

Service::Timer::Timer(ulong msec): timer((timer_t)-1) {
#ifdef POSIX_RT
    itimerspec its{};
    sigevent se{};

    se.sigev_notify = SIGEV_SIGNAL;
    se.sigev_signo = SIGALRM;
    se.sigev_value.sival_ptr = &timer;	// NOLINT
    if (msec == (ulong)-1 || timer_create(CLOCK_MONOTONIC, &se, &timer))
	return;
    if (!msec)
	msec = dmsec;
    its.it_value.tv_sec = (time_t)msec / 1000;
    its.it_value.tv_nsec = (long)((msec % 1000) * 1000000);
    if (timer_settime(timer, 0, &its, nullptr)) {
	timer_delete(timer);
	timer = (timer_t)-1;
    }
#else
    (void)msec;
#endif
}

void Service::Timer::cancel() {
#ifdef POSIX_RT
    if (timer != (timer_t)-1)
	timer_delete(timer);
#endif
    timer = (timer_t)-1;
}

Service::Service(const char *servicename, const char *h): name(servicename) {
    (void)h;
}

Service::Service(const char *servicename, bool pauseable): bPause(pauseable),
    name(servicename) {
    service = this;
}

Service::~Service() {
    service = nullptr;
}

bool Service::open(const tchar *file) {
    int fd;
    struct flock fl{};			// l_whence = SEEK_SET = 0
    auto locked = [&](off_t start, off_t len) {
	fl.l_type = F_WRLCK;
	fl.l_start = start;
	fl.l_len = len;
	if (fcntl(fd, F_GETLK, &fl) == -1)
	    fl.l_type = F_UNLCK;
	return fl.l_type != F_UNLCK;
    };

    errnum = ESRCH;
    pid = 0;
    stStatus = Stopped;
    if (file)
	lckfile = file;
    if ((fd = ::open(lckfile.c_str(), O_RDONLY | O_CLOEXEC)) == -1)
	return false;
    if (!locked(0, Watching)) {
	// a live watcher with no child is restarting or reaping the old group
	if (locked(Watching, 1))
	    fl.l_start = Stopping;
    } else {
	// workers share [0, status): the furthest end is the least ready
	while (fl.l_len && (fl.l_start += fl.l_len) < Watching &&
	    locked(fl.l_start, Watching - fl.l_start))
	    continue;
	fl.l_type = F_RDLCK;
    }
    if (fl.l_type != F_UNLCK) {
	char buf[24];
	ssize_t len = read(fd, buf, sizeof (buf));

	// file holds the watcher pid, which must get signals, not a worker
	if (from_chars(buf, buf + (len > 0 ? len : 0), pid).ec != errc() ||
	    pid <= 0)
	    pid = (pid_t)fl.l_pid;
	stStatus = (Status)fl.l_start;
    }
    ::close(fd);
    return pid != 0;
}

bool Service::close(void) {
    pid = 0;
    return true;
}

void Service::abort_handler(void) {
    // a 2nd entry means logging or _exit() hung, so force the issue
    if (aborting.exchange(true))
	kill(getpid(), SIGKILL);
    sigalrm(abort_handler);
    alarm(5);
    if (service)
	dlog.crit(Log::mod(service->name), Log::cmd(T("abort")),
	    Log::error(T("timeout")));
    _exit(-2);
}

void Service::null_handler(int) {}

// cppcheck-suppress constParameterCallback
void Service::signal_handler(int sig, siginfo_t *si, void *) {
    bool paused = (service->stStatus == Paused);

    if (aborted)
	_exit(sig);
#ifdef POSIX_RT
    itimerspec its{};
    sigevent se{};
    timer_t timer;

    se.sigev_notify = SIGEV_THREAD;
    se.sigev_notify_function = abort_handler;
    if (timer_create(CLOCK_MONOTONIC, &se, &timer)) {
	timer = (timer_t)-1;
    } else {
	its.it_value.tv_sec = (time_t)(Timer::dmsec / 1000U);
	its.it_value.tv_nsec = (long)((Timer::dmsec % 1000U) * 1000000U);
	timer_settime(timer, 0, &its, nullptr);
    }
#elif defined(__APPLE__)
    dispatch_source_t timer = dispatch_source_create(
	DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
	dispatch_get_global_queue(QOS_CLASS_DEFAULT, 0));

    if (timer) {
	dispatch_source_set_event_handler_f(timer, [](void *) {
	    abort_handler();
	});
	dispatch_source_set_timer(timer, dispatch_time(DISPATCH_TIME_NOW,
	    (int64_t)Timer::dmsec * (int64_t)NSEC_PER_MSEC),
	    DISPATCH_TIME_FOREVER, 0);
	dispatch_resume(timer);
    }
#endif
    switch (sig) {			// NOLINT
    case SIGALRM:
	service->onTimer((ulong)si->si_value.sival_ptr);
	break;
    case SIGABRT:
    case SIGBUS:
    case SIGFPE:
    case SIGILL:
    case SIGSEGV:
#ifdef SIGSTKFLT
    case SIGSTKFLT:
#endif
    case SIGTRAP:
	service->onAbort();
	break;
    case SIGCONT:
	if (paused) {
	    service->update(Resuming);
	    service->onResume();
	    service->update(Running);
	}
	break;
    case SIGHUP:
	if (!paused)
	    service->update(Refreshing);
	if (!service->onRefresh()) {
	    service->update(Stopping);
	    service->onStop(false);
	} else if (!paused) {
	    service->update(Running);
	}
	break;
    case SIGINT:
	service->update(Stopping);
	service->onStop(false);
	break;
    case SIGPIPE:
	break;
    case SIGTERM:
	service->update(Stopping);
	service->onStop(true);
	break;
    case SIGTSTP:
	if (service->bPause && !paused) {
	    service->update(Pausing);
	    service->onPause();
	    service->update(Paused);
	}
	break;
    case SIGUSR1:
	service->onSigusr1();
	break;
    case SIGUSR2:
	service->onSigusr2();
	break;
    }
#ifdef POSIX_RT
    if (timer != (timer_t)-1)
	timer_delete(timer);
#elif defined(__APPLE__)
    if (timer) {
	dispatch_source_cancel(timer);
	dispatch_release(timer);
    }
#endif
    dlog.flush();
    if (aborted)
	_exit(sig);
}

void Service::init_sigset(sigset_t &sigs) {
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGALRM);
    sigaddset(&sigs, SIGABRT);
    sigaddset(&sigs, SIGCONT);
    sigaddset(&sigs, SIGHUP);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    sigaddset(&sigs, SIGTSTP);
    sigaddset(&sigs, SIGUSR1);
    sigaddset(&sigs, SIGUSR2);
}

// catch SIGALRM with fn in this thread
void Service::sigalrm(void (*fn)(int)) {
    struct sigaction sa{};
    sigset_t sigs;

    sa.sa_handler = fn;
    sigaction(SIGALRM, &sa, nullptr);
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGALRM);
    pthread_sigmask(SIG_UNBLOCK, &sigs, nullptr);
}

void Service::setsignal(bool abrt) {
    struct sigaction sa{};
    sigset_t sigs;

    sa.sa_handler = null_handler;
    sigaction(SIGHUP, &sa, nullptr);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, nullptr);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGQUIT, &sa, nullptr);
    init_sigset(sigs);
    // signals pending since fork stay queued for ctrl_handler
    pthread_sigmask(SIG_BLOCK, &sigs, nullptr);
    if (abrt) {
	sa.sa_flags = SA_SIGINFO;
	sa.sa_mask = sigs;
	sa.sa_sigaction = signal_handler;

	sigaction(SIGABRT, &sa, nullptr);
	sigaction(SIGBUS, &sa, nullptr);
	sigaction(SIGFPE, &sa, nullptr);
	sigaction(SIGILL, &sa, nullptr);
	sigaction(SIGSEGV, &sa, nullptr);
#ifdef SIGSTKFLT
	sigaction(SIGSTKFLT, &sa, nullptr);
#endif
	sigaction(SIGTRAP, &sa, nullptr);
    }
}

void Service::unsetsignal() {
    struct sigaction sa{};
    sigset_t sigs;

    sa.sa_handler = SIG_DFL;
    sigaction(SIGHUP, &sa, nullptr);
    sigaction(SIGPIPE, &sa, nullptr);
    sigaction(SIGQUIT, &sa, nullptr);
    init_sigset(sigs);
    pthread_sigmask(SIG_UNBLOCK, &sigs, nullptr);
}

int Service::ctrl_handler(void *) {
    bool quit = false;
    sigset_t sigs;

    sigpid = getpid();
    sigpid.notify_all();
    init_sigset(sigs);
    sigaddset(&sigs, SIGPIPE);
    while (!quit) {
	siginfo_t si{};
	int sig;
	const tchar *str;
#ifdef POSIX_RT
	sig = sigwaitinfo(&sigs, &si);
#else
	if (sigwait(&sigs, &sig))
	    sig = -1;
#endif
	switch (sig) {
	case SIGABRT:
	    quit = true;
	    str = T("abort");
	    break;
	case SIGALRM:
	    // exit watchdog fired but this thread consumed it
	    if (exiting || aborting)
		abort_handler();
	    str = T("timer");
	    break;
	case SIGHUP:
	    str = T("refresh");
	    break;
	case SIGINT:
	    quit = true;
	    str = T("stop");
	    break;
	case SIGPIPE:
	    str = T("pipe");
	    break;
	case SIGTERM:
	    quit = true;
	    str = T("term");
	    break;
	case SIGTSTP:
	    str = T("pause");
	    break;
	case SIGCONT:
	    str = T("resume");
	    break;
	case SIGUSR1:
	    str = T("rollover");
	    break;
	case SIGUSR2:
	    str = T("user");
	    break;
	default:			// -1 for EINTR
	    continue;
	}

	uid_t uid = si.si_uid;
	pid_t pid = si.si_pid;

	if (pid == watchpid && si.si_code == SI_QUEUE) {
	    auto val = (uint64_t)(uintptr_t)si.si_value.sival_ptr;

	    uid = (uid_t)(val >> 32);
	    pid = (pid_t)(uint32_t)val;
	}
	// ignore signals we sent our own pg
	if (pid != getpid() || si.si_code == SI_QUEUE) {
	    dlog.info(Log::mod(service->name), Log::kv(T("sig"), str),
		Log::kv(T("uid"), uid), Log::kv(T("pid"), pid));
	    signal_handler(sig, &si, nullptr);
	}
    }
    sigpid = 0;
    return 0;
}

int Service::run(int argc, const tchar * const *argv) {
    int ret;
    rlimit rl;

    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur != rl.rlim_max) {
	rl.rlim_cur = rl.rlim_max == RLIM_INFINITY ? 100UL * 1024 : rl.rlim_max;
	while (setrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur >= 1024)
	    rl.rlim_cur -= 512;
    }
    if (!console) {
	int fd;
	pid_t fpid = fork();

	if (fpid > 0) {
	    _exit(0);			// skip exit handlers and copied stdio
	} else if (fpid == -1) {
	    dlog.err(Log::mod(argv[0]), Log::cmd(T("fork")),
		Log::error(tstrerror(errno)));
	    return 4;
	}
	dlog.file(Log::Info, service->logfile.c_str());
	if ((fd = ::open(T("/dev/null"), O_RDONLY)) != -1) {
	    dup2(fd, 0);
	    ::close(fd);
	}
	if ((fd = ::open(service->outfile.c_str(), O_APPEND | O_BINARY |
	    O_CREAT | O_WRONLY | O_SEQUENTIAL, 0640)) == -1)
	    fd = ::open(T("/dev/null"), O_WRONLY);
	if (fd != -1) {
	    dup2(fd, 1);
	    dup2(fd, 2);
	    ::close(fd);
	}
	setsid();
    }
    ret = service->onStart(argc, argv);	// 1st svc only
    exiting = true;
    if (!console)
	setsignal(true);
    if (pid_t p = sigpid)
	kill(p, SIGINT);
    sigalrm(abort_handler);
    alarm(5);
    service->sigthread.wait();
    dlog.stop();
    return ret;
}

bool Service::update(Status status) {
    stStatus = status;
    return true;
}

bool Service::install(const char *file, const char *desc,
    const char * const *depend, bool manual) {
    int fd;
    bool ret;

    (void)desc; (void)depend; (void)manual;
    if (!file)
	file = path.c_str();
    if ((fd = ::open(file, O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) == -1)
	return false;
    ret = !fchown(fd, getuid(), getgid()) && !fchmod(fd,
	S_ISUID | S_IRWXU | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
    ::close(fd);
    return ret;
}

bool Service::uninstall() {
    int fd;
    bool ret;

    stop();
    if ((fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)) == -1)
	return false;
    ret = !fchmod(fd, S_IRWXU | S_IRGRP | S_IXGRP);
    ::close(fd);
    return ret;
}

int Service::start(int argc, const tchar * const *argv) {
    pid_t fpid;
    uint loop = 5;
    int ret;
    bool started = false;
    uint stopped = 0;
    Status sts;

    while (loop-- && (sts = status()) == Stopping)
	sleep(1);
    if (sts != Error && sts != Stopped)
	return 2;
    if (console || (fpid = fork()) == 0) {
	return run(argc, argv);
    } else if (fpid == -1) {
	errnum = errno;
	dlog.err(Log::mod(argv[0]), Log::cmd(T("fork")), Log::error(errstr()));
	return 3;
    }
    // run() forks again, so reap fpid and then poll the daemon lock status
    for (uint u = 0; u < 600; u++) {
	if ((sts = status()) == Running || sts == Pausing ||
	    sts == Paused || sts == Refreshing || sts == Resuming)
	    return 0;
	if (fpid && waitpid(fpid, &ret, WNOHANG) == fpid) {
	    ret = WIFEXITED(ret) ? WEXITSTATUS(ret) : WIFSIGNALED(ret) ?
		WTERMSIG(ret) : 3;
	    if (ret)
		return ret;
	    fpid = 0;
	}
	if (sts != Stopped) {
	    started = true;
	    stopped = 0;
	} else if (!fpid && ++stopped == 10) {
	    // never locked means status is unknown rather than failed
	    return started;
	}
	msleep(100);
    }
    return 5;
}

bool Service::send(int sig) {
    uint cnt = 0;
    Status newstatus = Running;
    Status oldstatus;
    uint loops = STATUS_LOOPS;
    bool ret;
    bool stop = false;

    if (!open())
	return false;
    oldstatus = stStatus;
    if (sig == SERVICE_CONTROL_STOP) {
	sig = SIGINT;
	stop = true;
    } else if (sig == SERVICE_CONTROL_ABORT) {
	sig = SIGABRT;
	stop = true;
    } else if (sig == SERVICE_CONTROL_EXIT) {
	sig = SIGTERM;
	stop = true;
    } else if (sig == SERVICE_CONTROL_PAUSE) {
	newstatus = Paused;
	sig = SIGTSTP;
    } else if (sig == SERVICE_CONTROL_CONTINUE) {
	sig = SIGCONT;
    } else if (sig == SERVICE_CONTROL_REFRESH) {
	sig = SIGHUP;
    } else if (sig == SERVICE_CONTROL_SIGUSR1) {
	sig = SIGUSR1;
    } else if (sig == SERVICE_CONTROL_SIGUSR2) {
	sig = SIGUSR2;
    } else {
	return false;
    }
    if (stop) {
	newstatus = Stopped;
	loops = STOP_LOOPS;
    }
    if (kill(pid, sig)) {
	close();
	return stop;
    }
    if (sig == SIGHUP || sig == SIGUSR1 || sig == SIGUSR2) {
	close();
	return true;
    }
    do {
	close();
	msleep(100);
	if (!open())
	    return stop;
	// no state change means it is ignored, such as pause when unpauseable
    } while (stStatus != newstatus && ++cnt < loops && (stop ||
	stStatus != oldstatus || cnt < 20));
    // a hung watcher: its workers kill their own groups when it dies
    if (stStatus != newstatus && stop && (!kill(-pid, SIGKILL) ||
	!kill(pid, SIGKILL))) {
	for (cnt = 0; open() && cnt < STATUS_LOOPS; cnt++) {
	    close();
	    msleep(100);
	}
    }
    ret = stStatus == newstatus;
    if (!ret)
	errnum = stStatus == oldstatus ? ENOTSUP : ETIMEDOUT;
    close();
    return ret;
}

Service::Status Service::status() {
    if (!open())
	return Stopped;
    return stStatus;
}

[[noreturn]] void Service::exit(int code) {
    update(Stopped);
    ::exit(code);
}

string Service::errstr() const {
    return strerror((int)errnum);
}
#endif

int Service::execute(int argc, const tchar * const *argv) {
    int ac;
    vector<const tchar *> av;
    const tchar *cmd = T("?");
    tstring prog, root;
    int ret = 0;
    Service::Status sts;
    auto reqarg = [&](int &i, tstring &dst, const tchar *msg) {
	if (i == argc - 1) {
	    dlog.err(msg);
	    return false;
	}
	dst = argv[++i];
	return true;
    };

#ifndef _WIN32
    console = isatty(0) != 0;
    if (getuid() != geteuid() && getuid() != 0) {
	tcout << name << T(": uid permission denied") << endl;
	return 1;
    }
#endif
    path = argv[0];
    if (path[0] != '/' && (path.size() < 2 || path[1] != ':')) {
	tchar buf[PATH_MAX + 2];

	if (tgetcwd(buf, size(buf))) {
	    path = buf;
	    path += '/';
	    path += argv[0];
	}
    }
    av.push_back(path.c_str());
    for (int i = 1; i < argc; i++) {
	cmd = argv[i];
	while (*cmd == '-')
	    cmd++;
	if (tstreq(cmd, T("console"))) {
	    console = true;
	} else if (tstreq(cmd, T("daemon"))) {
	    console = false;
	} else if (tstreq(cmd, T("installdir"))) {
	    if (!reqarg(i, installdir, T("install directory required")))
		return 1;
	} else if (tstreq(cmd, T("lockfile"))) {
	    if (!reqarg(i, lckfile, T("lock filename required")))
		return 1;
	} else if (tstreq(cmd, T("logfile"))) {
	    if (!reqarg(i, logfile, T("log filename required")))
		return 1;
	} else if (tstreq(cmd, T("outfile"))) {
	    if (!reqarg(i, outfile, T("output filename required")))
		return 1;
#ifdef _WIN32
	} else if (tstreq(cmd, T("worker"))) {
	    // spawned by a watcher: its args follow
	    if (!reqarg(i, wkrarg, T("worker handles required")))
		return 1;
	    console = true;
	    while (++i < argc)
		av.push_back(argv[i]);
	    break;
#endif
	} else {
	    while (++i < argc)
		av.push_back(argv[i]);
	    break;
	}
    }
    ac = (int)av.size();
    av.push_back(nullptr);
    splitpath(argv[0], name.c_str(), root, prog);
    if (installdir.empty())
	installdir = root;
    if (name.empty())
	name = prog;	//  -V820
    dlog.source(name.c_str());
    set_files();
    if ((ret = command(cmd, ac, av.data())) != -1) {
	// handled by virtual method
    } else if (tstreq(cmd, T("install"))) {
	ret = !install(nullptr, av[1], ac > 1 ? &av[2] : nullptr);
    } else if (tstreq(cmd, T("uninstall"))) {
	ret = !uninstall();
    } else if (tstreq(cmd, T("abort")) || tstreq(cmd, T("kill"))) {
	ret = !abort();
    } else if (tstreq(cmd, T("help")) || tstreq(cmd, T("?"))) {
	tcout << T("usage:\t") << name << endl <<
	    T("\t[--console|--daemon] [--installdir dir] [--logfile file]") <<
	    endl << T("\t[--outfile file] [--lockfile file]") << endl <<
	    T("\tcondrestart|restart|start [args]") << endl <<
	    T("\thelp") << endl <<
	    T("\tinstall [description [dependencies]]") << endl <<
	    T("\tkill") << endl << T("\tpause") << endl <<
	    T("\trefresh") << endl << T("\tresume") << endl <<
	    T("\troll") << endl << T("\tstate") << endl <<
	    T("\tstatus") << endl << T("\tstop") << endl <<
	    T("\tuninstall") << endl << T("\tversion") << endl << endl;
    } else if (tstreq(cmd, T("pause")) || tstreq(cmd, T("suspend"))) {
	ret = !pause();
    } else if (tstreq(cmd, T("refresh")) || tstreq(cmd, T("reload"))) {
	ret = !refresh();
    } else if (tstreq(cmd, T("condrestart"))) {
	ret = !stop(false);
	if (ret)
	    errnum = ESRCH;
	else
	    ret = start(ac, av.data());
    } else if (tstreq(cmd, T("restart"))) {
	stop();
	ret = start(ac, av.data());
    } else if (tstreq(cmd, T("continue")) || tstreq(cmd, T("resume"))) {
	ret = !resume();
    } else if (tstreq(cmd, T("roll")) || tstreq(cmd, T("sigusr1")) ||
	tstreq(cmd, T("rollover"))) {
	ret = !sigusr1();
    } else if (tstreq(cmd, T("sigusr2"))) {
	ret = !sigusr2();
    } else if (tstreq(cmd, T("start"))) {
	ret = start(ac, av.data());
	// exiting: this is the daemon itself returning its exit code
	if (ret && !exiting && (sts = status()) != Error) {
	    ret = sts == Stopped;
	    if (ret)
		errnum = 0;
	    tcout << name << T(": ") << status(sts) << endl;
	}
    } else if (tstreq(cmd, T("state"))) {
	sts = status();
	errnum = 0;
	ret = (int)sts;
    } else if (tstreq(cmd, T("status"))) {
	sts = status();
	errnum = 0;
	ret = (sts == Error || sts == Stopped);
	tcout << name << T(": ") << status(sts) << endl;
    } else if (tstreq(cmd, T("stop")) || tstreq(cmd, T("exit"))) {
	ret = status() == Stopped ? 0 : !stop(tstreq(cmd, T("exit")));
    } else if (tstreq(cmd, T("version"))) {
	tcout << ver << endl;
    } else {
	ret = run(ac, av.data());
    }
    if (ret && errnum && !exiting)
	tcerr << name << T(": ") << errstr() << endl;
    dlog.destruct();
    return ret;
}

void Service::set_files(void) {
    auto set = [this](tstring &file, const tchar *dir, const tchar *ext) {
	if (!file.empty())
	    return;
	file = dir;
	if (taccess(file.c_str(), R_OK | W_OK)) {
	    file = installdir + T("/log");
	    if (taccess(file.c_str(), R_OK | W_OK))
		file = installdir;
	}
	file += '/';
	file += name;
	file += ext;
    };

    set(lckfile, T("/var/run"), T(".pid"));
    set(logfile, T("/var/log"), T(".log"));
    set(outfile, T("/var/log"), T(".out"));
}

int Service::onStart(int argc, const tchar * const *argv) {
    (void)argc;
    (void)argv;
    setsignal();
#ifndef _WIN32
    sigthread.start(ctrl_handler);
    sigpid.wait(0);
#endif
    return 0;
}

void Service::onTimer(ulong timer) {
    dlog.debug(Log::mod(name), Log::cmd(T("timer")), Log::kv(T("id"), timer));
}

const tchar *Service::status(Status s) {
    static constexpr const tchar *StatusStr[] = {
	T("Error"), T("Pausing"), T("Paused"), T("Refreshing"), T("Resuming"),
	T("Running"), T("Starting"), T("Stopping"), T("Stopped")
    };

    return StatusStr[(int)s];
}

Daemon::Daemon(const tchar *svc_name, const tchar *display, bool pauseable):
    Service(svc_name, pauseable) {
    (void)display;
}

Daemon::~Daemon() {
    if (qflag != None && !worker())
	dlog.note(Log::mod(name), Log::kv(T("sts"), T("stopped")),
	    Log::kv(T("duration"), (mticks() - msec) / 1000U));
    if (lckfd != -1) {
	if (!worker())
	    (void)tunlink(lckfile.c_str());
	(void)lockfile(lckfd, F_UNLCK, SEEK_SET, 0, 0, 0);
	::close(lckfd);
    }
}

// shared [0, status) lets workers report together; a worker's own slot holds
// [0, status + 1) so Error still locks a byte
bool Daemon::update(Status status) {
    uint base = Slots + (uint)slot * SlotSize;

    if (lckfd == -1) {
	stStatus = status;
#ifdef _WIN32
	if (!worker())
	    return Service::update(status);
	stmap[slot] = (uchar)(status + 1);
#endif
	return true;
    }
    if (status < stStatus) {
	(void)lockfile(lckfd, F_UNLCK, SEEK_SET, status, Watching -
	    (uint)status, 0);
	if (worker())
	    (void)lockfile(lckfd, F_UNLCK, SEEK_SET, base + (uint)status + 1,
		SlotSize - (uint)status - 1, 0);
    } else {
	(void)lockfile(lckfd, F_RDLCK, SEEK_SET, 0, status, 0);
	if (worker())
	    (void)lockfile(lckfd, F_WRLCK, SEEK_SET, base, (ulong)status + 1,
		0);
    }
    return Service::update(status);
}

void Daemon::unavailable(bool state) const {
    (void)lockfile(lckfd, state ? F_RDLCK : F_UNLCK, SEEK_SET, Unavailable, 1,
	1);
}

// root would otherwise keep its supplementary groups after dropping privileges
static int dropgroups(void) {
#ifdef _WIN32
    return 0;
#else
    return geteuid() == 0 ? setgroups(0, nullptr) : 0;
#endif
}

bool Daemon::setids() {
    if (uid != (uid_t)-1) {
	dlog.setids(uid, gid);
	// cppcheck-suppress knownConditionTrueFalse
	if (fchown(lckfd, uid, gid) || dropgroups() || setgid(gid) ||
	    setuid(uid)) {
	    dlog.err(Log::mod(name), Log::error(T("unable to set uid")));
	    return false;
	}
	gid = (gid_t)-1;
	uid = (uid_t)-1;
#ifdef __linux__
	// credential changes clear the parent death signal
	if (worker()) {
	    prctl(PR_SET_PDEATHSIG, SIGRTMIN);
	    if (getppid() != watchpid)
		kill(0, SIGKILL);
	}
#endif
    }
    return true;
}

void Daemon::configfile(int argc, const tchar * const *argv) {
    for (int i = 1; i < argc; i++) {
	const tchar *p = argv[i];

	if (*p != '-')
	    continue;
	while (*p == '-')
	    p++;
	if (tstreq(p, T("config")) && i + 1 < argc) {
	    cfgfile = argv[i + 1];
	    break;
	}
    }
    if (cfgfile.empty()) {
	cfgfile = installdir + T("/etc/") + name + T(".cfg");
	if (taccess(cfgfile.c_str(), R_OK)) {
	    cfgfile = installdir + T("/") + name + T(".cfg");
	    if (taccess(cfgfile.c_str(), R_OK)) {
		cfgfile = name + T(".cfg");
		if (taccess(cfgfile.c_str(), R_OK))
		    cfgfile.erase();
	    }
	}
    }
}

int Daemon::onStart(int argc, const tchar * const *argv) {
    char buf[24];
    bool buffer, mp;
    int ret = 0;
    size_t len;
    struct stat sbuf, sfile;
    auto started = [this] {
	dlog.note(Log::mod(name), Log::cmd(T("start")), Log::kv(T("host"),
	    Sockaddr::hostname()), Log::kv(T("dir"), installdir.c_str()),
	    Log::kv(T("instance"), instance), Log::kv(T("release"), ver));
    };

    srvcpath = path;
    cfg.prefix(name.c_str());
    stStatus = Starting;
#ifdef _WIN32
    if (!wkrarg.empty())
	return spawned(argc, argv);
#endif
    do {
	lckfd = ::open(tstringtoachar(lckfile), O_CREAT | O_CLOEXEC | O_RDWR,
	    S_IREAD | S_IWRITE);
	// an old watcher reaping its last child holds only the Watching byte
	if (lckfd == -1 || lockfile(lckfd, F_WRLCK, SEEK_SET, 0, Starting, 1) ||
	    lockfile(lckfd, F_WRLCK, SEEK_SET, Watching, 1, 1)) {
	    dlog.err(Log::mod(name), Log::cmd(T("start")), Log::kv(T("sts"),
		T("running")));
	    if (lckfd != -1)
		::close(lckfd);
	    lckfd = -1;
	    return 1;
	}
	// coverity[fs_check_call : FALSE ]
	if (fstat(lckfd, &sbuf) || stat(tstringtoachar(lckfile), &sfile) ||
	    sbuf.st_ino != sfile.st_ino) {
	    ::close(lckfd);
	    lckfd = -1;
	}
    } while (lckfd == -1);
    len = (size_t)(to_chars(buf, buf + sizeof (buf), getpid()).ptr - buf);
    if (ftruncate(lckfd, 0) || write(lckfd, buf, (uint)len) < 1)
	return 2;
    configfile(argc, argv);
    if (!onRefresh())
	return 3;
#ifdef _WIN32
    // the SCM already restarts a single process
    watch = cfg.get(T("watch.enable"), cfg.get(T("worker.count"), nworkers) >
	1);
#else
    watch = cfg.get(T("watch.enable"), !console);
#endif
    // workers share the log file
    mp = watch && cfg.get(T("worker.count"), nworkers) > 1;
    buffer = !mp && cfg.get(T("log.file.buffer.enable"), false);
    dlog.setmp(mp);
    if (!cfg.get(T("enable"), true)) {
	dlog.note(Log::mod(name), Log::cmd(T("start")), Log::kv(T("sts"),
	    T("disabled")));
	return 4;
    }
    if (sbuf.st_size)
	dlog.warn(Log::mod(name), T("restarting after abort"));
    started();
#ifndef _WIN32
    rlimit rl;
    const passwd *pwd;
    uid_t id;
    string uidname = cfg.get(T("uid"));

    if (uidname.empty()) {
	uid = (uid_t)-1;
    } else {
	if (from_chars(uidname.data(), uidname.data() + uidname.size(),
	    id).ec == errc())
	    pwd = getpwuid(id);			// NOLINT
	else
	    pwd = getpwnam(uidname.c_str());	// NOLINT
	if (pwd) {
	    gid = pwd->pw_gid;
	    uid = pwd->pw_uid;
	    uidname = pwd->pw_name;
	    dlog.setids(uid, gid);
	    if (fchown(lckfd, uid, gid))
		dlog.err(Log::mod(name), T(" unable to chown to uid "), uidname);
	} else {
	    dloge(Log::mod(name), T(" unknown uid "), uidname);
	    return 5;
	}
    }
    dlogd(Log::mod(name), Log::kv(T("uid"), uid == (uid_t)-1 ? getuid() :
	uid), Log::kv(T("gid"), uid == (uid_t)-1 ? getgid() : gid),
	Log::kv(T("maxfd"), getrlimit(RLIMIT_NOFILE, &rl) ? 0 : rl.rlim_cur));
#endif
    if ((ret = onInit(argc, argv)) != 0)
	return ret;
    if (!watch) {
	(void)lockfile(lckfd, F_UNLCK, SEEK_SET, Watching, 1, 0);
	ret = Service::onStart(argc, argv);
	dlog.buffer(buffer);
	return ret;
    }
#ifdef _WIN32
    wargs.assign(argv + 1, argv + argc);
#endif
    ret = watchloop();
    if (!worker()) {
	tunlink(lckfile.c_str());
	(void)lockfile(lckfd, F_UNLCK, SEEK_SET, 0, 0, 0);
	::close(lckfd);
	lckfd = -1;
#ifdef _WIN32
	dlog.stop();
#endif
	exit(ret);
    }
#ifndef _WIN32
#ifdef BSD_BASE
    sigset_t all, old;
    pthread_t tid;
#endif

    // own group first so an orphaned worker's kill(0) can't hit the watcher;
    // a watcher that died uncleanly takes the whole group with it
    setpgid(0, getpid());
#ifdef __linux__
    signal(SIGRTMIN, [](int) { kill(0, SIGKILL); });
    prctl(PR_SET_PDEATHSIG, SIGRTMIN);
    if (getppid() != watchpid)		// watcher died before prctl()
	kill(0, SIGKILL);
#elif defined(BSD_BASE)
    // no PDEATHSIG: a thread, blocking all signals so it never steals the
    // process's, waits for the watcher to exit
    sigfillset(&all);
    pthread_sigmask(SIG_SETMASK, &all, &old);
    if (!pthread_create(&tid, nullptr, [](void *) -> void * {
	struct kevent ev;
	int kq = kqueue();

	EV_SET(&ev, (uintptr_t)watchpid.load(), EVFILT_PROC, EV_ADD |
	    EV_ONESHOT, NOTE_EXIT, 0, nullptr);
	if (kq != -1) {
	    (void)kevent(kq, &ev, 1, &ev, 1, nullptr);
	    ::close(kq);
	}
	// also catches ESRCH when the watcher exited before registering
	if (getppid() != watchpid)
	    kill(0, SIGKILL);
	return nullptr;
    }, nullptr))
	pthread_detach(tid);
    pthread_sigmask(SIG_SETMASK, &old, nullptr);
#endif
    update(Starting);
    ret = Service::onStart(argc, argv);
    dlog.buffer(buffer);
#endif
    return ret;
}

void Daemon::onAbort() {
    if (aborted)
	return;
    aborted = true;
    update(Stopped);
    if (restart && !exiting) {
#ifdef _WIN32
	int rc = (int)tspawnlp(P_NOWAIT, srvcpath.c_str(), srvcpath.c_str(),
	    T("restart"), NULL);
#else
	string s(srvcpath + " restart");
	int rc = execl("/bin/sh", "/bin/sh", "-c", s.c_str(), (char *)0);
#endif

	if (rc < 0) {
	    dlog.err(Log::mod(name), Log::error(T("restart failed ")));
	    _exit(1);
	}
    }
    if (console)
	dlog.alert(Log::mod(name), T("aborting"));
}

void Daemon::onPause(void) {
    dlog.note(Log::mod(name), Log::cmd(T("pause")));
}

void Daemon::onResume(void) {
    dlog.note(Log::mod(name), Log::cmd(T("resume")));
}

bool Daemon::onRefresh(void) {
    if (!cfgfile.empty() && !cfg.read(cfgfile.c_str())) {
	dlog.alert(Log::mod(name), Log::cmd(T("config")), Log::kv(T("file"),
	    cfgfile), Log::error(tstrerror(errno)));
	return false;
    }
    if (cfg.get(T("installdir")).empty())
	cfg.set(T("installdir"), installdir.c_str());
    cfg.set(T("name"), name.c_str(), Log::section());
    cfg.set(T("version"), ver.c_str());
    instance = cfg.get(T("instance"), T("default"));
    if (!cfgfile.empty())
	dlog.set(cfg);
    Service::Timer::dmsec = cfg.get(T("watch.timeout"), Timer::dmsec / 1000) *
	1000;
    if (!worker() && refreshed)
	dlog.note(Log::mod(name), Log::cmd(T("reload")));
    else
	refreshed = true;
    return true;
}

void Daemon::onStop(bool fast) {
    dlog.info(Log::mod(name), Log::cmd(fast ? T("exit") : T("stop")));
    qflag = fast ? Fast : Slow;
}

void Daemon::onSigusr1(void) {
    dlog.note(Log::mod(name), Log::cmd(T("rollover")));
    dlog.roll();
}

#ifdef _WIN32
// controls forwarded by the watcher; EOF means it exited
ulong __stdcall Daemon::ctlread(void *) {
    auto *daemon = (Daemon *)service;
    uchar ctl;
    DWORD in;

    while (ReadFile(daemon->ctlpipe, &ctl, 1, &in, nullptr) && in)
	daemon->handle(ctl);
    _exit(1);
}

bool Daemon::onWatch(ulong ctl) {
    HANDLE ev = wakeev;

    if (!ev)
	return false;
    if (ctl == SERVICE_CONTROL_STOP || ctl == SERVICE_CONTROL_SHUTDOWN)
	qflag = Slow;
    else if (ctl == SERVICE_CONTROL_EXIT)
	qflag = Fast;
    ctllck.lock();
    ctls.push_back(ctl);
    ctllck.unlock();
    SetEvent(ev);
    return true;
}

// workers inherit only their pipe, the status map, stdio and onSpawn() handles
bool Daemon::spawn(Worker &w) {
    vector<const tchar *> args;
    unique_ptr<char[]> attrs;
    tstring cmd, hdlarg;
    vector<HANDLE> hdls;
    HANDLE jobs[] = { job };
    PROCESS_INFORMATION pi{};
    HANDLE rd = nullptr, wr = nullptr;
    STARTUPINFOEX si{};
    SIZE_T sz = 0;
    bool ok;

    if (!CreatePipe(&rd, &wr, nullptr, 0)) {
	errnum = (long)GetLastError();
	return false;
    }
    onSpawn(hdls);
    hdlarg = format(T("{},{},{}"), w.slot, (uintptr_t)rd, (uintptr_t)stmaphdl);
    for (HANDLE h : hdls)
	hdlarg += format(T(",{}"), (uintptr_t)h);
    hdls.push_back(rd);
    hdls.push_back(stmaphdl);
    for (HANDLE h : hdls)
	(void)SetHandleInformation(h, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT);
    si.StartupInfo.cb = sizeof (si);
    si.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
    for (DWORD id : { STD_OUTPUT_HANDLE, STD_ERROR_HANDLE }) {
	HANDLE h = GetStdHandle(id);

	if (!h || h == INVALID_HANDLE_VALUE || !SetHandleInformation(h,
	    HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT))
	    continue;
	if (!ranges::contains(hdls, h))
	    hdls.push_back(h);
	if (id == STD_OUTPUT_HANDLE)
	    si.StartupInfo.hStdOutput = h;
	else
	    si.StartupInfo.hStdError = h;
    }
    args = { path.c_str(), T("--installdir"), installdir.c_str(),
	T("--lockfile"), lckfile.c_str(), T("--logfile"), logfile.c_str(),
	T("--outfile"), outfile.c_str(), T("--worker"), hdlarg.c_str() };
    args.insert(args.end(), wargs.begin(), wargs.end());
    args.push_back(nullptr);
    cmd = Process::cmdline(args.data());
    (void)InitializeProcThreadAttributeList(nullptr, 2, 0, &sz);
    attrs.reset(new char[sz]);
    si.lpAttributeList = (LPPROC_THREAD_ATTRIBUTE_LIST)attrs.get();
    if (!InitializeProcThreadAttributeList(si.lpAttributeList, 2, 0, &sz))
	si.lpAttributeList = nullptr;
    // the job list assigns the job before the worker runs
    ok = si.lpAttributeList && UpdateProcThreadAttribute(si.lpAttributeList, 0,
	PROC_THREAD_ATTRIBUTE_HANDLE_LIST, hdls.data(), hdls.size() *
	sizeof (HANDLE), nullptr, nullptr) &&
	UpdateProcThreadAttribute(si.lpAttributeList, 0,
	PROC_THREAD_ATTRIBUTE_JOB_LIST, jobs, sizeof (jobs), nullptr,
	nullptr) && CreateProcess(nullptr, cmd.data(), nullptr, nullptr, TRUE,
	CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT, nullptr, nullptr,
	&si.StartupInfo, &pi);
    if (!ok)
	errnum = (long)GetLastError();
    if (si.lpAttributeList)
	DeleteProcThreadAttributeList(si.lpAttributeList);
    CloseHandle(rd);
    if (!ok) {
	CloseHandle(wr);
	return false;
    }
    CloseHandle(pi.hThread);
    w.ctl = wr;
    w.pid = (pid_t)pi.dwProcessId;
    w.proc = pi.hProcess;
    w.wait = CreateThreadpoolWait([](PTP_CALLBACK_INSTANCE, void *ev, PTP_WAIT,
	TP_WAIT_RESULT) { SetEvent(ev); }, wakeev.load(), nullptr);
    if (w.wait)
	SetThreadpoolWait(w.wait, w.proc, nullptr);
    return true;
}

// a worker process: --worker slot,pipe,map[,onSpawn() handles]
int Daemon::spawned(int argc, const tchar * const *argv) {
    vector<HANDLE> hdls;
    int ret;

    for (size_t pos = 0; pos < wkrarg.size(); ) {
	size_t end = wkrarg.find(T(','), pos);

	if (end == tstring::npos)
	    end = wkrarg.size();
	hdls.push_back((HANDLE)(uintptr_t)atoun<ullong>(wkrarg.c_str() + pos,
	    end - pos));
	pos = end + 1;
    }
    if (hdls.size() < 3)
	return 2;
    slot = (int)(uintptr_t)hdls[0];
    ctlpipe = hdls[1];
    stmaphdl = hdls[2];
    if ((stmap = (atomic<uchar> *)MapViewOfFile(stmaphdl, FILE_MAP_WRITE, 0, 0,
	MaxSlots)) == nullptr)
	return 2;
    hdls.erase(hdls.begin(), hdls.begin() + 3);
    configfile(argc, argv);
    if (!onRefresh())
	return 3;
    dlog.setmp(true);
    onSpawn(hdls);
    if ((ret = onInit(argc, argv)) != 0)
	return ret;
    if (HANDLE h = CreateThread(nullptr, 0, ctlread, nullptr, 0, nullptr))
	CloseHandle(h);
    update(Starting);
    return Service::onStart(argc, argv);
}
#endif

// a worker's status, or -1 before it locks its slot
int Daemon::slotstatus(uint s) const {
#ifdef _WIN32
    return (int)stmap[s] - 1;
#else
    struct flock fl{};			// l_whence = SEEK_SET = 0

    fl.l_type = F_WRLCK;
    fl.l_start = Slots + (off_t)s * SlotSize;
    fl.l_len = SlotSize;
    return fcntl(lckfd, F_GETLK, &fl) == -1 || fl.l_type == F_UNLCK ? -1 :
	(int)fl.l_len - 1;
#endif
}

uint Daemon::swap_pct(void) {
#ifdef __linux__
    struct sysinfo si;

    return sysinfo(&si) || !si.totalswap ? 0 : (uint)((si.totalswap -
	si.freeswap) * 100 / si.totalswap);
#elif defined(__APPLE__)
    xsw_usage xsu;
    size_t len = sizeof (xsu);

    if (sysctlbyname("vm.swapusage", &xsu, &len, nullptr, 0) ||
	!xsu.xsu_total)
	return 0;
    return (uint)(xsu.xsu_used * 100 / xsu.xsu_total);
#elif defined(__FreeBSD__)
    int mib[16];
    size_t miblen = std::size(mib);
    uint64_t total = 0, used = 0;

    if (sysctlnametomib("vm.swap_info", mib, &miblen) ||
	miblen >= std::size(mib))
	return 0;
    for (mib[miblen] = 0; ; ++mib[miblen]) {
	struct xswdev xsw;
	size_t len = sizeof (xsw);

	if (sysctl(mib, (uint)miblen + 1, &xsw, &len, nullptr, 0))
	    break;
	total += (uint64_t)xsw.xsw_nblks;
	used += (uint64_t)xsw.xsw_used;
    }
    return total ? (uint)(used * 100 / total) : 0;
#elif defined(__OpenBSD__)
    int cnt = swapctl(SWAP_NSWAP, nullptr, 0);
    uint64_t total = 0, used = 0;

    if (cnt <= 0)
	return 0;

    vector<swapent> ents((size_t)cnt);

    ents.resize((size_t)(max)(swapctl(SWAP_STATS, ents.data(), cnt), 0));
    for (const swapent &e : ents) {
	if (e.se_flags & SWF_ENABLE) {
	    total += (uint64_t)e.se_nblks;
	    used += (uint64_t)e.se_inuse;
	}
    }
    return total ? (uint)(used * 100 / total) : 0;
#else
    return 0;
#endif
}

#ifndef _WIN32
// async-signal-safe: watchloop() acts on the flags after poll() wakes
// cppcheck-suppress constParameterCallback
void Daemon::watch_handler(int sig, siginfo_t *si, void *) {
    auto *daemon = (Daemon *)service;
    int err = errno;

    if (sig == SIGINT)
	daemon->qflag = Slow;
    else if (sig == SIGTERM)
	daemon->qflag = Fast;
    if (sig != SIGCHLD) {
	daemon->sigsrc[sig] = (uint64_t)si->si_uid << 32 |
	    (uint32_t)si->si_pid;
	daemon->sigpend |= 1ULL << sig;
    }
    // a full pipe already wakes the loop
    if (write(daemon->wakefd[1], "", 1) == -1)
	errno = err;
}
#endif

// forks and watches workers until stopped; returns 0 in each new worker
int Daemon::watchloop(void) {
#ifndef _WIN32
    static constexpr int fwdsigs[] = {
	SIGABRT, SIGCONT, SIGHUP, SIGINT, SIGTERM, SIGTSTP, SIGUSR1, SIGUSR2
    };
    sigset_t blk, old;
#endif
    bool first = true, keep = true, paused = false;
    Status held = Starting;
    msec_t now = mticks();
    msec_t due = now + (msec_t)cfg.get(T("watch.interval"), 60U) * 1000;
    msec_t retry = 0, spawnat = 0, swapped = 0;
    int ret = 0;
    uint retries = 0;
#ifdef _WIN32
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION jl{};

    jl.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if ((job = CreateJobObject(nullptr, nullptr)) == nullptr ||
	!SetInformationJobObject(job, JobObjectExtendedLimitInformation, &jl,
	sizeof (jl)) || (stmaphdl = CreateFileMapping(INVALID_HANDLE_VALUE,
	nullptr, PAGE_READWRITE, 0, MaxSlots, nullptr)) == nullptr ||
	(stmap = (atomic<uchar> *)MapViewOfFile(stmaphdl, FILE_MAP_WRITE, 0, 0,
	MaxSlots)) == nullptr || (wakeev = CreateEvent(nullptr, FALSE, FALSE,
	nullptr)) == nullptr) {
	errnum = (long)GetLastError();
	dlog.err(Log::mod(name), Log::cmd(T("watch")), Log::error(errstr()));
	return 6;
    }
    setsignal();
#else
    struct sigaction sa{};

    if (pipe(wakefd)) {
	dlog.err(Log::mod(name), Log::cmd(T("watch")), Log::error(errstr()));
	return 6;
    }
    for (int fd : wakefd) {
	fcntl(fd, F_SETFD, FD_CLOEXEC);
	fcntl(fd, F_SETFL, O_NONBLOCK);
    }
    sa.sa_flags = SA_NOCLDSTOP | SA_SIGINFO;
    sa.sa_sigaction = watch_handler;
    sigemptyset(&blk);
    for (int sig : fwdsigs) {
	sigaction(sig, &sa, nullptr);
	sigaddset(&blk, sig);
    }
    sigaction(SIGCHLD, &sa, nullptr);
    sigaddset(&blk, SIGCHLD);
    // orphaned descendants reparent here so a dead worker's group is reaped
#ifdef __linux__
    prctl(PR_SET_CHILD_SUBREAPER, 1);
#elif defined(__FreeBSD__)
    procctl(P_PID, getpid(), PROC_REAP_ACQUIRE, nullptr);
#endif
    // workers share the status range
    (void)lockfile(lckfd, F_RDLCK, SEEK_SET, 0, Starting, 0);
#endif
    watchpid = getpid();
    dlog.stop();
    for (;;) {
#ifndef _WIN32
	char buf[64];
#endif
	uint count, intvl, startms, stopms, szpct;
	ulong maxpss, maxsz;
#ifdef _WIN32
	vector<ulong> pend;
#else
	uint64_t pend = sigpend.exchange(0);
#endif
	bool pending = false, quit;
#ifndef _WIN32
	pid_t p;
	int sts;
#endif
	Status want;
	msec_t wake;
#ifndef _WIN32
	pollfd pfd{.fd = wakefd[0], .events = POLLIN, .revents = 0};
#endif
	auto forward = [&](const Worker &w, int sig) {
#ifdef _WIN32
	    auto ctl = (uchar)sig;
	    DWORD out;

	    (void)WriteFile(w.ctl, &ctl, 1, &out, nullptr);
#elif defined(POSIX_RT)
	    // pass the original sender for ctrl_handler() to log; uid is lost
	    // on 32 bit platforms but the pid always fits
	    sigval val{.sival_ptr = (void *)(uintptr_t)sigsrc[sig].load()};

	    (void)sigqueue(w.pid, sig, val);
#else
	    (void)kill(w.pid, sig);
#endif
	};
	auto recycle = [&](Worker &w, const tchar *err,
	    const struct pidstat &ps) {
#ifdef _WIN32
	    forward(w, SERVICE_CONTROL_STOP);
#else
	    kill(w.pid, cfg.get(T("watch.core"), false) ? SIGQUIT : SIGINT);
#endif
	    w.kill = now + stopms;
	    dlog.warn(Log::mod(name), Log::cmd(T("watch")), Log::kv(T("pid"),
		w.pid), Log::kv(T("pss"), ps.pss), Log::kv(T("maxpss"), maxpss),
		Log::kv(T("sz"), ps.sz), Log::kv(T("maxsz"), maxsz),
		Log::error(err), T("restarting"));
	};
	auto reaped = [&](const Worker &w, int code, bool sig) {
	    msec_t life = now - w.start;

	    if (qflag || w.kill || !keep)	// expected or giving up
		return;
	    // a clean exit after serving, as after maxrequests, is routine
	    if (!code && !sig && w.ran) {
		dlog.info(Log::mod(name), Log::cmd(T("watch")),
		    Log::kv(T("pid"), w.pid), Log::kv(T("duration"), life / 1000),
		    T("exited"));
	    } else if (w.first && !w.ran) {
		// a worker dying during startup won't fix itself
		ret = code ? code : -1;
		keep = false;
		dlog.crit(Log::mod(name), Log::cmd(T("watch")),
		    Log::kv(T("pid"), w.pid), Log::kv(T("sts"), ret),
		    Log::error(T("immediate exit")));
	    } else {
		dlog.warn(Log::mod(name), Log::cmd(T("watch")),
		    Log::kv(T("pid"), w.pid), Log::kv(sig ? T("signal") :
		    T("exit"), code), Log::error(T("unexpected exit")),
		    Log::kv(T("duration"), life / 1000));
		if (now - retry > 60000) {
		    retries = 1;
		    retry = now;
		} else if (++retries >= cfg.get(T("watch.maxstarts"), 10U)) {
		    ret = code ? code : -1;
		    keep = false;
		    dlog.crit(Log::mod(name), Log::cmd(T("watch")),
			Log::error(T("too many restarts")));
		}
	    }
	};

#ifdef _WIN32
	ctllck.lock();
	pend.swap(ctls);
	ctllck.unlock();
	// refresh before workers so they can rely on the watcher's new state
	if (ranges::contains(pend, (ulong)SERVICE_CONTROL_REFRESH)) {
	    forklock.lock();
	    (void)onRefresh();
	    forklock.unlock();
	}
	for (ulong ctl : pend) {
	    bool pausing = ctl == SERVICE_CONTROL_CONTINUE || ctl ==
		SERVICE_CONTROL_PAUSE;

	    if (pausing)
		paused = ctl == SERVICE_CONTROL_PAUSE;
	    for (const Worker &w : wkrs) {
		// workers pause once serving, else running() would undo it
		if (!pausing || (w.ran && !w.kill))
		    forward(w, (int)ctl);
	    }
	}
#else
	// refresh before workers so they can rely on the watcher's new state
	if (pend & (1ULL << SIGHUP)) {
	    forklock.lock();
	    (void)onRefresh();
	    forklock.unlock();
	}
	for (int sig : fwdsigs) {
	    if (!(pend & (1ULL << sig)))
		continue;
	    if (sig == SIGCONT || sig == SIGTSTP)
		paused = sig == SIGTSTP;
	    for (const Worker &w : wkrs) {
		// workers pause once serving, else running() would undo it
		if ((sig != SIGCONT && sig != SIGTSTP) || (w.ran && !w.kill))
		    forward(w, sig);
	    }
	}
#endif
	now = mticks();
	count = (max)(cfg.get(T("worker.count"), nworkers), 1U);
#ifdef _WIN32
	count = (min)(count, MaxSlots);
#endif
	intvl = cfg.get(T("watch.interval"), 60U) * 1000;
	maxpss = cfg.get(T("watch.maxpss"), 0U);
	szpct = cfg.get(T("watch.maxsz"), 33U);
	maxsz = szpct ? maxpss * (100 + szpct) / 100 : 0;
	startms = cfg.get(T("watch.start"), 90U) * 1000;
	stopms = cfg.get(T("watch.stop"), 60U) * 1000;
#ifdef _WIN32
	for (auto it = wkrs.begin(); it != wkrs.end(); ) {
	    DWORD code = 0;
	    Worker w = *it;

	    if (WaitForSingleObject(w.proc, 0) != WAIT_OBJECT_0) {
		++it;
		continue;
	    }
	    it = wkrs.erase(it);
	    (void)GetExitCodeProcess(w.proc, &code);
	    SetThreadpoolWait(w.wait, nullptr, nullptr);
	    WaitForThreadpoolWaitCallbacks(w.wait, TRUE);
	    CloseThreadpoolWait(w.wait);
	    CloseHandle(w.ctl);
	    CloseHandle(w.proc);
	    reaped(w, (int)code, false);
	}
#else
	while ((p = waitpid(-1, &sts, WNOHANG)) > 0) {
	    auto it = ranges::find(wkrs, p, &Worker::pid);
	    Worker w;

	    if (it == wkrs.end())		// adopted orphan
		continue;
	    w = *it;
	    wkrs.erase(it);
	    // a replacement must wait for the whole old group to free its
	    // sockets and file locks; orphans adopted as subreaper end here
	    (void)kill(-p, SIGKILL);
	    for (;;) {
		while (waitpid(-p, nullptr, WNOHANG) > 0)
		    continue;
		if (kill(-p, 0))
		    break;
		msleep(10);
	    }
	    reaped(w, WIFEXITED(sts) ? WEXITSTATUS(sts) : WIFSIGNALED(sts) ?
		WTERMSIG(sts) : 0, WIFSIGNALED(sts));
	}
#endif
	quit = qflag || !keep;
	for (Worker &w : wkrs) {
	    if (quit && !w.kill) {
		if (!qflag)		// qflag signals were forwarded
#ifdef _WIN32
		    forward(w, SERVICE_CONTROL_STOP);
#else
		    kill(w.pid, SIGINT);
#endif
		w.kill = now + stopms;
	    } else if (w.kill && now >= w.kill) {
#ifndef _WIN32
		int ksig = cfg.get(T("watch.corekill"), false) ? SIGQUIT :
		    SIGKILL;

#endif
		dlog.note(Log::mod(name), Log::cmd(T("watch")),
		    Log::kv(T("pid"), w.pid), T("killing hung child"));
#ifdef _WIN32
		(void)TerminateProcess(w.proc, 1);
#else
		if (kill(-w.pid, ksig))
		    kill(w.pid, ksig);
#endif
		w.kill = now + stopms;
	    }
	}
	if (!quit && now >= due) {
	    Status agg = Error;
	    Worker *big = nullptr;
	    uint64_t bigpss = 0;
	    tstring err;

	    due = now + intvl;
	    for (Worker &w : wkrs) {
		Status cur;
		const tchar *why = nullptr;
		struct pidstat ps;
		int ws;

		if (w.kill)
		    continue;
		ws = slotstatus(w.slot);
		cur = ws < 0 ? Starting : (Status)ws;
		(void)pidstat(w.pid, &ps);
		if (maxpss && ps.pss > maxpss) {
		    why = T("proportional size exceeds maximum");
		} else if (maxsz && ps.sz > maxsz) {
		    why = T("total size exceeds maximum");
		} else if (cur != w.status) {
		    w.status = cur;
		    w.since = now;
		} else if (cur == Starting && now - w.since > startms) {
		    why = T("start timeout");
		} else if (cur == Refreshing && now - w.since >
		    (msec_t)cfg.get(T("watch.refresh"), 60U) * 1000) {
		    why = T("refresh timeout");
		} else if (cur == Stopping && now - w.since > stopms) {
		    why = T("stop timeout");
		}
		if (why) {
		    recycle(w, why, ps);
		    continue;
		}
		agg = (max)(agg, cur);
		if (!big || ps.pss > bigpss) {
		    big = &w;
		    bigpss = ps.pss;
		}
	    }
	    if (uint maxswap = cfg.get(T("watch.maxswap"), 0U); big &&
		maxswap && now - swapped >= cfg.get(T("watch.swapwait"), 4U *
		// cppcheck-suppress unsignedLessThanZero
		60 * 60) * 1000ULL && swap_pct() > maxswap) {
		struct pidstat ps;

		(void)pidstat(big->pid, &ps);
		recycle(*big, T("system swap use exceeds maximum"), ps);
		swapped = now;
	    } else if (big && (agg == Running || agg == Stopped) &&
		!check(agg, err)) {
		for (Worker &w : wkrs) {
		    struct pidstat ps;

		    if (w.kill)
			continue;
		    (void)pidstat(w.pid, &ps);
		    recycle(w, err.c_str(), ps);
		}
	    }
	}
	if (!quit) {
	    auto live = (uint)ranges::count(wkrs, (msec_t)0, &Worker::kill);

	    // a smaller worker.count retires the newest extras
	    for (Worker &w : wkrs | views::reverse) {
		if (live <= count)
		    break;
		if (!w.kill) {
#ifdef _WIN32
		    forward(w, SERVICE_CONTROL_STOP);
#else
		    kill(w.pid, SIGINT);
#endif
		    w.kill = now + stopms;
		    --live;
		}
	    }
	    // replacements wait for the old worker's whole group to exit
	    while (wkrs.size() < count && now >= spawnat) {
		uint s = 0;
#ifdef _WIN32
		bool ok;
		Worker w;
#endif

		while (ranges::contains(wkrs, s, &Worker::slot))
		    ++s;
#ifdef _WIN32
		w = {0, now, now, 0, s, Starting, first, false, nullptr,
		    nullptr, nullptr};
		stmap[s] = 0;
		forklock.lock();
		ok = spawn(w);
		forklock.unlock();
		if (!ok) {
		    dlog.err(Log::mod(name), Log::cmd(T("spawn")),
			Log::error(errstr()));
		    spawnat = now + intvl / 4;
		    break;
		}
		wkrs.push_back(w);
		dlog.debug(Log::mod(name), Log::cmd(T("watch")),
		    Log::kv(T("pid"), w.pid), Log::kv(T("slot"), s));
#else
		// a worker must not inherit a half refreshed watcher
		forklock.lock();
		onPreFork();
		sigprocmask(SIG_BLOCK, &blk, &old);
		if ((p = fork()) == 0) {
		    sigset_t chld;

		    slot = (int)s;
		    wkrs.clear();
		    ::close(wakefd[0]);
		    ::close(wakefd[1]);
		    wakefd[0] = wakefd[1] = -1;
		    sa.sa_handler = SIG_DFL;
		    sa.sa_flags = 0;
		    sigaction(SIGCHLD, &sa, nullptr);
		    sigemptyset(&chld);
		    sigaddset(&chld, SIGCHLD);
		    // forwarded signals stay blocked for ctrl_handler
		    sigprocmask(SIG_UNBLOCK, &chld, nullptr);
		    onPostFork(true);
		    forklock.unlock();
		    return 0;
		}
		sigprocmask(SIG_SETMASK, &old, nullptr);
		onPostFork(false);
		forklock.unlock();
		if (p == -1) {
		    dlog.err(Log::mod(name), Log::cmd(T("fork")),
			Log::error(errstr()));
		    spawnat = now + intvl / 4;
		    break;
		}
		wkrs.push_back({0, now, now, p, s, Starting, first, false});
		dlog.debug(Log::mod(name), Log::cmd(T("watch")),
		    Log::kv(T("pid"), p), Log::kv(T("slot"), s));
#endif
	    }
	    first = false;
	}
	if (quit && wkrs.empty())
	    break;
	for (Worker &w : wkrs) {
	    int ws = w.ran || w.kill ? Running : slotstatus(w.slot);

	    if (ws >= Pausing && ws <= Running) {
		if (paused && !w.ran && !w.kill)
#ifdef _WIN32
		    forward(w, SERVICE_CONTROL_PAUSE);
#else
		    forward(w, SIGTSTP);
#endif
		w.ran = true;
	    } else {
		pending = true;
	    }
	}
	// hold Starting until every worker serves so status never looks idle
#ifdef _WIN32
	want = quit ? Stopping : pending ? Starting : paused ? Paused : Running;
	// repeats while starting so the SCM sees checkpoint progress
	if (want != held || want == Starting) {
	    held = want;
	    (void)Service::update(want);
	}
#else
	want = quit ? Stopping : pending ? Starting : Stopped;
	if (want != held) {
	    held = want;
	    (void)lockfile(lckfd, want == Stopped ? F_UNLCK : F_RDLCK, SEEK_SET,
		0, want == Stopped ? Watching : (uint)want, 0);
	}
#endif
	wake = quit ? (msec_t)-1 : (min)(due, spawnat > now ? spawnat : due);
	for (const Worker &w : wkrs) {
	    if (w.kill)
		wake = (min)(wake, w.kill);
	}
	if (pending)
	    wake = (min)(wake, now + 100);
	(void)dlog.close();
#ifdef _WIN32
	(void)WaitForSingleObject(wakeev, wake <= now ? 0 : (DWORD)(min)(wake -
	    now, (msec_t)INFINITE - 1));
#else
	(void)poll(&pfd, 1, wake <= now ? 0 : (int)(min)(wake - now,
	    (msec_t)INT_MAX));
	while (read(wakefd[0], buf, sizeof (buf)) > 0)
	    continue;
#endif
    }
    if (qflag)
	dlog.note(Log::mod(name), Log::cmd(qflag == Fast ? T("exit") :
	    T("stop")), Log::kv(T("duration"), (mticks() - msec) / 1000));
#ifdef _WIN32
    UnmapViewOfFile(stmap);
    stmap = nullptr;
    CloseHandle(stmaphdl);
    CloseHandle(job);
#else
    ::close(wakefd[0]);
    ::close(wakefd[1]);
#endif
    return ret;
}
