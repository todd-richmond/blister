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

#include "stdapi.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <sys/stat.h>
#include "Log.h"
#include "Service.h"

#ifdef _WIN32
#include <process.h>

#pragma comment(lib, "advapi32.lib")
#pragma warning(disable: 4390)

#define DWORD_MULTIPLE(x) ((((x) + sizeof (DWORD) - 1 ) / sizeof (DWORD)) * \
    sizeof (DWORD))
#define SERVICE_PREFIX T("service_")
#else
#pragma GCC diagnostic ignored "-Wunused-result"
#endif

#ifndef OPEN_MAX
#define OPEN_MAX 2048
#endif

static const uint STATUS_LOOPS = 400;

ulong Service::Timer::dmsec = 120;
bool Service::aborted;
bool Service::console;
bool Service::exiting;
bool Service::restart;
tstring Service::srvcpath;
Service *Service::service;
volatile pid_t Service::sigpid;
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
	if (full[0] == '/' || full[1] == ':') {
	    root = full;
	} else {
	    (void)tgetcwd(buf, sizeof (buf) / sizeof (tchar));
	    root = buf;
	    root += '/';
	    root += full;
	}
	if ((pos = root.find_last_of('/')) == root.npos)
	    pos = root.find_last_of('\\');
	if (pos >= 4 && !tstrnicmp(root.c_str() + pos - 3, T("bin"), 3))
	    pos -= 4;
	else if (pos >= 6 && !tstrnicmp(root.c_str() + pos - 5, T(".libs"), 5))
	    pos -= 6;
	root.erase(pos);
    }
#ifdef _WIN32
    if (service) {
	HKEY key;
	DWORD size;
	DWORD type;

	tsprintf(buf, T("SYSTEM\\CurrentControlSet\\Services\\%s\\Parameters"),
	    id);
	if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
	    buf, 0L, KEY_ALL_ACCESS, &key) == ERROR_SUCCESS) {
	    size = sizeof (buf);
	    if (RegQueryValueEx(key, T("Install Directory"), 0L, &type,
		(LPBYTE)&buf, &size)) {
		dlogw(Log::mod(id), Log::error(T("install key missing")));
	    } else {
		full = buf;
	    }
	    RegCloseKey(key);
	}
    }
#endif
    if ((p = tstrrchr(full, '/')) == NULL && (p = tstrrchr(full, '\\')) == NULL)
	p = full;
    else
	p++;
    if ((sep = tstrrchr(full, '.')) != NULL && !tstrnicmp(sep, T(".exe"), 4))
	prog.assign(p, (tstring::size_type)(sep - p));
    else
	prog = p;
}

#ifdef _WIN32
Service::Service(const tchar *servicename, const tchar *h): name(servicename),
    bPause(false), errnum(0), ctrlfunc(NULL), gid(0), hStatus(0), hSCManager(0),
    hService(0), checkpoint(0), map(NULL), mapsz(0), maphdl(0), pid(0),
    stStatus(Stopped), uid(0) {
    ZERO(ssStatus);
    if (h)
	host = h;
}

Service::Service(const tchar *servicename, bool pauseable): name(servicename),
    bPause(pauseable), errnum(0), ctrlfunc(service_handler), gid(0), hStatus(0),
    hSCManager(0), hService(0), checkpoint(0), map(NULL), mapsz(0), maphdl(0),
    pid(0), stStatus(Stopped), uid(0) {
    service = this;
    ZERO(ssStatus);
}

Service::~Service() {
    if (ctrlfunc)
	service = NULL;
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
	map = NULL;
    }
    if (maphdl) {
	CloseHandle(maphdl);
	maphdl = 0;
    }
    if (hService) {
	CloseServiceHandle(hService);
	hService = NULL;
    }
    if (hSCManager) {
	CloseServiceHandle(hSCManager);
	hSCManager = NULL;
	return true;
    }
    return false;
}

int __stdcall Service::ctrl_handler(ulong sig) {
    if (sig == CTRL_BREAK_EVENT) {
	if (!service->onRefresh()) {
	    service->onStop(false);
	}
    } else if (sig == CTRL_C_EVENT)
	service->onStop(false);
    else if (sig == CTRL_SHUTDOWN_EVENT || sig == CTRL_CLOSE_EVENT)
	service->onStop(true);
#ifndef NDEBUG
    else
	DebugBreak();
#endif
    dlog.flush();
    return 1;
}

void Service::signal_handler(int sig) {
    if (!aborted) {
	if (sig == SIGABRT || sig == SIGFPE || sig == SIGILL || sig == SIGSEGV) {
	    service->onAbort();
	}
    }
    _exit(sig);
}

#pragma warning(push)
#pragma warning(disable: 4702)

long Service::exception_handler(_EXCEPTION_POINTERS *info) {
    if (!aborted)
	service->onAbort();
    _exit(1);
    return EXCEPTION_CONTINUE_EXECUTION;
}

#pragma warning(pop)

void Service::setsignal(bool abrt) {
    if (console)
	SetErrorMode(SEM_FAILCRITICALERRORS|SEM_NOOPENFILEERRORBOX|SEM_NOGPFAULTERRORBOX);
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
	    { (tchar *)service->name.c_str(), srv_main },
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
    tchar modulename[128];
    int ret = 0;

    if (service->name == argv[0])
	service->hStatus = RegisterServiceCtrlHandler(service->name.c_str(),
	    service->ctrlfunc);
    else if (!service->hStatus)
	return;
    GetModuleFileName(NULL, modulename, sizeof (modulename) / sizeof (tchar));
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
    switch (sig) {
    case SERVICE_CONTROL_SHUTDOWN:
    case SERVICE_CONTROL_STOP:
	update(Stopping);
	GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0); //-V549
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
	update((Status)ssStatus.dwCurrentState);
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
    if (state == SERVICE_START_PENDING)
	ssStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN | SERVICE_ACCEPT_STOP;
    else if (state == SERVICE_STOPPED)
	ssStatus.dwControlsAccepted = 0;
    else if (bPause)
	ssStatus.dwControlsAccepted = SERVICE_ACCEPT_SHUTDOWN |
	    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_PAUSE_CONTINUE;
    else
	ssStatus.dwControlsAccepted =
	    SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    if (state == SERVICE_RUNNING || state == SERVICE_STOPPED)
	ssStatus.dwCheckPoint = checkpoint = 0;
    else
	ssStatus.dwCheckPoint = ++checkpoint;
    return SetServiceStatus(hStatus, &ssStatus) != FALSE;
}

bool Service::install(const tchar *file, const tchar *desc,
    const tchar * const * depend, bool manual) {
    tchar buf[PATH_MAX];
    size_t i;
    tchar *p = NULL;
    tstring root, prog;

    if (uninstall())
	open();
    if (!file) {
	GetModuleFileName(NULL, buf, sizeof (buf) / sizeof (tchar));
	file = buf;
    }
    if (!desc) {
	splitpath(file, NULL, root, prog);
	prog[0] = (tchar)totupper(prog[0]);
	for (i = 1; i < prog.size(); i++)
	    prog[0] = (tchar)totlower(prog[0]);
	desc = prog.c_str();
    }
    if (depend) {
	size_t sz = 0;

	for (i = 0; depend[i]; i++)
	    sz += tstrlen(depend[i]) + 1;
	if ((p = new tchar[sz + 1]) != NULL) {
	    tchar *pp;

	    for (i = 0, pp = p; depend[i]; i++) {
		tstrcpy(pp, depend[i]);
		pp += tstrlen(pp);
		*pp++ = '\0';
	    }
	    *pp = '\0';
	}
    }
    hService = CreateService(hSCManager, name.c_str(),
	desc, SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS,
	manual ? SERVICE_DEMAND_START : SERVICE_AUTO_START,
	SERVICE_ERROR_NORMAL, file, NULL, NULL, p, NULL, NULL);
    errnum = GetLastError();
    delete [] p;
    return hService != NULL;
}

bool Service::uninstall() {
    stop();
    if (DeleteService(hService)) {
	close();
	return true;
    }
    return false;
}

bool Service::start(int argc, const tchar *const *argv) {
    if (!open())
	return false;
    errnum = StartService(hService, argc - 1, (LPCTSTR *)&argv[1]) ? 0 :
	GetLastError();
    return errnum == 0;
}

bool Service::send(int sig) {
    DWORD newstate = 0;
    SERVICE_STATUS status;

    if (!open())
	return false;
    if (sig == SERVICE_CONTROL_STOP || sig == SERVICE_CONTROL_ABORT ||
	sig == SERVICE_CONTROL_EXIT)
	newstate = SERVICE_STOPPED;
    else if (sig == SERVICE_CONTROL_PAUSE)
	newstate = SERVICE_PAUSED;
    else
	newstate = SERVICE_RUNNING;
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

void Service::exit(int code) {
    ssStatus.dwWin32ExitCode = code;
    update(Stopped);
    _exit(code);
}

tstring Service::errstr() const {
    tchar *msg;
    tstring s(T("Service Error"));

    if (FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER |
	FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_ARGUMENT_ARRAY, NULL,
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
	s.c_str())) == NULL)
	return NULL;
    if ((map = MapViewOfFile(maphdl, FILE_MAP_WRITE, 0, 0, mapsz)) == NULL) {
	CloseHandle(maphdl);
	maphdl = 0;
	return NULL;
    }
    return map;
}

ServiceData::ServiceData(const tchar *service, uint num, uint size):
    count(0), counter(0), ctrs(num), data(NULL), datasz(0), help(0),
    init(false), last(0), map(NULL), mapsz(size), name(service), offset(0) {
}

DWORD ServiceData::open(LPWSTR lpDeviceNames) {
    static Lock lock;

    (void)lpDeviceNames;
    lock.lock();
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

	if ((status = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
	    s.c_str(), 0L, KEY_ALL_ACCESS, &key)) != ERROR_SUCCESS) {
	    dloge(Log::mod(name), Log::error(
		T("unable to open performance registry")));
	    return 1;
	}
	size = sizeof (counter);
	status = RegQueryValueEx(key, T("First Counter"), 0L,
	  &type, (LPBYTE)&counter, &size);
	size = sizeof (help);
	if (!status)
	    status = RegQueryValueEx(key, T("First Help"), 0L,
		&type, (LPBYTE)&help, &size);
	if (status) {
	    dloge(Log::mod(name), Log::error(
		T("unable to read performance counters")));
	    RegCloseKey(key);
	    return 1;
	}
	RegCloseKey(key);
	s = SERVICE_PREFIX + name;
	if ((hdl = OpenFileMapping(FILE_MAP_READ, FALSE, s.c_str())) == NULL)
	    return 1;
	if ((map = MapViewOfFile(hdl, FILE_MAP_READ, 0, 0, mapsz)) == NULL) {
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
	if ((data = new char[datasz]) == NULL) {
	    UnmapViewOfFile(map);
	    return 1;
	}
	memset(data, 0, datasz);
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
	pcb = (PERF_COUNTER_BLOCK  *)((char *)pid + pid->ByteLength);
	pcb->ByteLength = (DWORD)(sizeof (PERF_COUNTER_BLOCK) + mapsz);
	init = true;
    }
    count++;
    lock.unlock();
    return 0;
}

DWORD ServiceData::close(void) {
    static Lock lock;

    lock.lock();
    if (!--count) {
	init = false;
	UnmapViewOfFile(map);
	map = NULL;
	delete [] data;
    }
    lock.unlock();
    return 0;
}

DWORD ServiceData::collect(LPCWSTR value, LPVOID *datap, LPDWORD total, LPDWORD
    types) {
    *types = 0;
    if (!init)
	return ERROR_SUCCESS;
    if (value && !wcscmp(value, L"Foreign")) {
	return ERROR_SUCCESS;
    } else if (value && wcscmp(value, L"Global") != 0 && wcscmp(value,
	L"Costly") != 0) {
    /*
	if (!(IsNumberInUnicodeList(
	    MSDataDefinition.MS_ObjectType.ObjectNameTitleIndex, value)))
	    // request received for data object not provided by this routine
	    return ERROR_SUCCESS;
    */
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

#include <pwd.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/wait.h>

Service::Timer::Timer(ulong msec): timer(NULL) {
#if defined(__APPLE__)
    (void)msec;
#elif defined(__linux__)
    itimerspec its;
    sigevent se;

    ZERO(se);
    se.sigev_notify = SIGEV_SIGNAL;
    se.sigev_signo = SIGALRM;
    se.sigev_value.sival_ptr = &timer;
    if (msec == (ulong)-1 || timer_create(CLOCK_MONOTONIC, &se, &timer))
	return;
    if (!msec)
	msec = dmsec;
    ZERO(its);
    its.it_value.tv_sec = (time_t)msec / 1000;
    *(ulong *)&its.it_value.tv_nsec = (msec % 1000) * 1000000;
    if (timer_settime(timer, 0, &its, NULL)) {
	timer_delete(timer);
	timer = NULL;
    }
#endif
}

void Service::Timer::cancel() {
    if (timer) {
#if defined(__APPLE__)
#elif defined(__linux__)
	timer_delete(timer);
#endif
	timer = NULL;
    }
}

Service::Service(const char *servicename, const char *h): bPause(false),
    errnum(0), gid(0), name(servicename), pid(0), stStatus(Stopped), uid(0) {
    (void)h;
}

Service::Service(const char *servicename, bool pauseable): bPause(pauseable),
    errnum(0), gid(0), name(servicename), pid(0), stStatus(Stopped), uid(0) {
    service = this;
}

Service::~Service() {
    service = NULL;
}

bool Service::open(const tchar *file) {
    int fd;
    struct flock fl;

    errnum = ESRCH;
    pid = 0;
    stStatus = Stopped;
    if (file)
	lckfile = file;
    if ((fd = ::open(lckfile.c_str(), O_RDONLY | O_NOATIME)) == -1)
	return false;
    ZERO(fl);
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    if (fcntl(fd, F_GETLK, &fl) != -1 && fl.l_pid && fl.l_type != F_UNLCK) {
	pid = (pid_t)fl.l_pid;
	stStatus = (Status)fl.l_len;
    }
    ::close(fd);
    return pid != 0;
}

bool Service::close(void) {
    pid = 0;
    return true;
}

void Service::abort_handler(void) {
    static bool aborting;

    if (!aborting) {
	struct sigaction sa;

	aborting = true;
	ZERO(sa);
	sa.sa_handler = abort_handler;
	sigaction(SIGALRM, &sa, NULL);
	alarm(5);
	dlog << Log::Crit << Log::mod(service->name) << Log::cmd(T("abort")) <<
	    Log::kv(T("err"), T("timeout")) << endlog;
	alarm(0);
    }
    _exit(-2);
}

void Service::null_handler(int) {}

void Service::signal_handler(int sig, siginfo_t *si, void *) {
    bool paused = (service->stStatus == Paused);

    if (aborted)
	_exit(sig);
#ifdef __linux__
    itimerspec its;
    sigevent se;
    timer_t timer;

    ZERO(se);
    se.sigev_notify = SIGEV_THREAD;
    se.sigev_notify_function = abort_handler;
    se.sigev_value.sival_ptr = &timer;
    if (timer_create(CLOCK_MONOTONIC, &se, &timer)) {
	timer = NULL;
    } else {
	ZERO(its);
	its.it_value.tv_sec = (time_t)(Timer::dmsec / 1000U);
	its.it_value.tv_nsec = (long)((Timer::dmsec % 1000U) * 1000000U);
	timer_settime(timer, 0, &its, NULL);
    }
#endif
    switch (sig) {
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
#ifdef __linux__
    if (timer)
	timer_delete(timer);
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

void Service::setsignal(bool abrt) {
    struct sigaction sa;
    sigset_t sigs;

    ZERO(sa);
    sa.sa_handler = null_handler;
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGQUIT, &sa, NULL);
    init_sigset(sigs);
    sigprocmask(SIG_UNBLOCK, &sigs, NULL);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);
    if (abrt) {
	sa.sa_flags = SA_SIGINFO;
	sa.sa_mask = sigs;
	sa.sa_sigaction = signal_handler;

	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
#ifdef SIGSTKFLT
	sigaction(SIGSTKFLT, &sa, NULL);
#endif
	sigaction(SIGTRAP, &sa, NULL);
    }
}

void Service::unsetsignal() {
    struct sigaction sa;
    sigset_t sigs;

    ZERO(sa);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGPIPE, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
    init_sigset(sigs);
    pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);
}


int Service::ctrl_handler(void *) {
    bool quit = false;
    int sig;
    sigset_t sigs;

    sigpid = getpid();
    init_sigset(sigs);
    sigaddset(&sigs, SIGPIPE);
    while (!quit) {
	tchar buf[16];
	siginfo_t si;
	const tchar *str;
#ifdef __linux__
	sig = sigwaitinfo(&sigs, &si);
#else
	ZERO(si);
	if (sigwait(&sigs, &sig))
	    sig = 0;
#endif
	switch (sig) {
	case SIGABRT:
	    quit = true;
	    str = T("abort");
	    break;
	case SIGALRM:
	    str = "timer";
	    break;
	case SIGBUS:
	case SIGFPE:
	case SIGILL:
	case SIGTRAP:
	case SIGSEGV:
#ifdef SIGSTKFLT
	case SIGSTKFLT:
#endif
	    quit = true;
	    str = T("cpu");
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
	case -1:
	    if (errno == EINTR)
		continue;
	default:
	    tsprintf(buf, T("%i"), sig);
	    str = buf;
	    break;
	};
	// ignore signals we sent our own pg
	if (si.si_pid != getpid() || si.si_code == SI_QUEUE) {
	    dlogi(Log::mod(service->name), Log::kv(T("sig"), str));
	    signal_handler(sig, &si, NULL);
	}
    };
    sigpid = 0;
    return 0;
}

int Service::run(int argc, const tchar * const *argv) {
    int ret;
    rlimit rl;
    struct sigaction sa;

    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur != rl.rlim_max) {
	rl.rlim_cur = rl.rlim_max == RLIM_INFINITY ? 100 * 1024 : rl.rlim_max;
	while (setrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur >= 1024)
	    rl.rlim_cur -= 512;
    }
    if (!console) {
	int fd;
	pid_t fpid = fork();

	dlog.file(Log::Info, service->logfile.c_str());
	if (fpid > 0) {
	    ::exit(0);
	} else if (fpid == -1) {
	    dloge(Log::mod(argv[0]), Log::error(T("unable to fork")));
	    ::exit(1);
	}
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
    if (sigpid)
	kill(sigpid, SIGINT);
    ZERO(sa);
    sa.sa_handler = abort_handler;
    sigaction(SIGALRM, &sa, NULL);
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
    (void)desc; (void)depend; (void)manual;
    if (!file)
	file = path.c_str();
    return chown(file, getuid(), getgid()) == -1 &&
	chmod(file, S_ISUID|S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) != -1;
}

bool Service::uninstall() {
    stop();
    return chmod(path.c_str(), S_IRWXU|S_IRGRP|S_IXGRP) != -1;
}

bool Service::start(int argc, const tchar * const *argv) {
    pid_t fpid;
    uint loop = 15;
    Status sts;

    while (loop-- && (sts = status()) == Stopping)
	sleep(1);
    if (sts != Error && sts != Stopped)
	return false;
    if (console || (fpid = fork()) == 0) {
	exit(run(argc, argv));
    } else if (fpid == -1) {
	errnum = errno;
	dloge(Log::mod(argv[0]), Log::error(T("unable to fork")));
	return false;
    } else {
	bool started = false;
	int ret;

	waitpid(fpid, &ret, 0);
	ret = WIFEXITED(ret) ? WEXITSTATUS(ret) : WIFSIGNALED(ret) ?
	    WTERMSIG(ret) : 0;
	for (int i = 0; i < 10 * 30; i++) {
	    if ((sts = status()) == Running || sts == Pausing ||
		sts == Paused || sts == Refreshing || sts == Resuming) {
		break;
	    } else if (sts == Starting) {
		started = true;
	    } else if (ret) {
		return false;
	    } else if ((sts == Error || sts == Stopped) &&
		(started || i > 50)) {
		return false;
	    }
	    msleep(100);
	}
    }
    return true;
}

bool Service::send(int sig) {
    uint cnt = 0;
    Status newstatus = Running;
    bool ret;
    bool stop = false;

    if (!open())
	return false;
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
    if (stop)
	newstatus = Stopped;
    if (kill(pid, sig)) {
	close();
	return stop;
    }
    do {
	close();
	if (sig == SIGHUP)
	    return true;
	msleep(100);
	if (!open())
	    return stop;
    } while (stStatus != newstatus && ++cnt < STATUS_LOOPS);
    ret = (stStatus == newstatus || (stop && kill(pid, SIGKILL) == 0));
    close();
    return ret;
}

Service::Status Service::status() {
    if (!open())
	return Stopped;
    return stStatus;
}

void Service::exit(int code) {
    update(Stopped);
    ::exit(code);
}

string Service::errstr() const {
    return strerror((int)errnum);
}
#endif

int Service::execute(int argc, const tchar * const *argv) {
    int ac = 1;
    const tchar **av;
    const tchar *cmd = T("?");
    tstring prog;
    int ret = 0;
    Service::Status sts;

#ifndef _WIN32
    console = isatty(0) != 0;
    if (getuid() != geteuid() && getuid() != 0) {
	tcout << name << T(": uid permission denied") << endl;
	return 1;
    }
#endif
    av = new const tchar *[argc + 1];
    path = argv[0];
    if (path[0] != '/' && path[1] != ':') {
	tchar buf[PATH_MAX + 2];

	(void)tgetcwd(buf, sizeof (buf) / sizeof (tchar));
	path = buf;
	path += '/';
	path += argv[0];
    }
    av[0] = path.c_str();
    for (int i = 1; i < argc; i++) {
	cmd = argv[i];
	while (*cmd == '-')
	    cmd++;
	if (tstreq(cmd, T("console"))) {
	    console = true;
	} else if (tstreq(cmd, T("daemon"))) {
	    console = false;
	} else if (tstreq(cmd, T("installdir"))) {
	    if (i == argc - 1) {
		dlog.err(T("install directory required"));
		delete [] av;
		return -1;
	    }
	    installdir = argv[++i];
	} else if (tstreq(cmd, T("lockfile"))) {
	    if (i == argc - 1) {
		dlog.err(T("lock filename required"));
		delete [] av;
		return -1;
	    }
	    lckfile = argv[++i];
	} else if (tstreq(cmd, T("logfile"))) {
	    if (i == argc - 1) {
		dlog.err(T("log filename required"));
		delete [] av;
		return -1;
	    }
	    logfile = argv[++i];
	} else if (tstreq(cmd, T("outfile"))) {
	    if (i == argc - 1) {
		dlog.err(T("output filename required"));
		delete [] av;
		return -1;
	    }
	    outfile = argv[++i];
	} else {
	    while (++i < argc)
		av[ac++] = argv[i];
	    break;
	}
    }
    av[ac] = NULL;
    splitpath(argv[0], name.c_str(), installdir, prog);
    if (name.empty())
	name = prog;	// -V::820
    dlog.source(name.c_str());
    set_files();
    if ((ret = command(cmd, ac, av)) != -1) {
    } else if (tstreq(cmd, T("install"))) {
	ret = !install(NULL, av[0], &av[1]);
    } else if (tstreq(cmd, T("uninstall"))) {
	ret = !uninstall();
    } else if (tstreq(cmd, T("abort")) || tstreq(cmd, T("kill"))) {
	ret = !abort();
    } else if (tstreq(cmd, T("help")) || tstreq(cmd, T("?"))) {
	tcout << T("usage:\t") << name << endl <<
	    T("\t[--console|--daemon] [--installdir dir] [--logfile file]") <<
	    endl << T("\t[--outfile file] --pidfile file]") << endl <<
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
	    ret = !start(ac, av);
    } else if (tstreq(cmd, T("restart"))) {
	stop();
	ret = !start(ac, av);
    } else if (tstreq(cmd, T("continue")) || tstreq(cmd, T("resume"))) {
	ret = !resume();
    } else if (tstreq(cmd, T("roll")) || tstreq(cmd, T("sigusr1")) ||
	tstreq(cmd, T("rollover"))) {
	ret = !sigusr1();
    } else if (tstreq(cmd, T("sigusr2"))) {
	ret = !sigusr2();
    } else if (tstreq(cmd, T("start"))) {
	ret = !start(ac, av);
	if (ret && status() != Error) {
	    ret = 0;
	    tcout << name << T(": ") << status(status()) << endl;
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
	ret = run(ac, av);
    }
    if (ret && errnum)
	tcerr << name << T(": ") << errstr() << endl;
    delete [] av;
    return ret;
}

void Service::set_files(void) {
    if (lckfile.empty()) {
	lckfile = T("/var/run");
	if (taccess(lckfile.c_str(), R_OK | W_OK)) {
	    lckfile = installdir + T("log");
	    if (taccess(lckfile.c_str(), R_OK | W_OK))
		lckfile = installdir;
	}
	lckfile += '/';
	lckfile += name;
	lckfile += T(".pid");
    }
    if (logfile.empty()) {
	logfile = T("/var/log");
	if (taccess(logfile.c_str(), R_OK | W_OK)) {
	    logfile = installdir + T("log");
	    if (taccess(logfile.c_str(), R_OK | W_OK))
		logfile = installdir;
	}
	logfile += '/';
	logfile += name;
	logfile += T(".log");
    }
    if (outfile.empty()) {
	outfile = T("/var/log");
	if (taccess(outfile.c_str(), R_OK | W_OK)) {
	    outfile = installdir + T("log");
	    if (taccess(outfile.c_str(), R_OK | W_OK))
		outfile = installdir;
	}
	outfile += '/';
	outfile += name;
	outfile += T(".out");
    }
}

int Service::onStart(int argc, const tchar * const *argv) {
    (void)argc;
    (void)argv;
    setsignal();
#ifndef _WIN32
    sigthread.start(ctrl_handler);
    while (!sigpid)
	msleep(20);
#endif
    return 0;
}

void Service::onTimer(ulong timer) {
    dlog << Log::Debug << Log::mod(name) << Log::cmd("timer") << Log::kv(T("id"),
	timer) << endlog;
}

const tchar *Service::status(Status s) {
    static const tchar *StatusStr[] = {
	T("Error"), T("Pausing"), T("Paused"), T("Refreshing"), T("Resuming"),
	T("Running"), T("Starting"), T("Stopping"), T("Stopped")
    };

    return StatusStr[(int)s];
}


Daemon::Daemon(const tchar *svc_name, const tchar *display, bool pauseable):
    Service(svc_name, pauseable), qflag(None), child(0), lckfd(-1),
    msec(mticks()), refreshed(false), watch(false) {
    (void)display;
}

Daemon::~Daemon() {
    if (qflag != None)
	dlog.note(Log::mod(name), Log::kv(T("sts"), T("stopped")));
    if (lckfd != -1) {
	if (!watch || child)
	    (void)tunlink(lckfile.c_str());
	(void)lockfile(lckfd, F_UNLCK, SEEK_SET, 0, 0, 0);
	::close(lckfd);
    }
}

bool Daemon::update(Status status) {
    if (!child) {
	stStatus = status;
	return true;
    }
    if (status < stStatus)
	(void)lockfile(lckfd, F_UNLCK, SEEK_SET, status, 0, 0);
    else
	(void)lockfile(lckfd, F_WRLCK, SEEK_SET, 0, status, 0);
    return Service::update(status);
}

bool Daemon::setids() {
    if (uid != (uid_t)-1) {
	dlog.setids(uid, gid);
	if (fchown(lckfd, uid, gid) || setgid(gid) || setuid(uid)) {
	    dloge(Log::mod(name), Log::error(T("unable to set uid")));
	    return false;
	} else {
	    gid = (gid_t)-1;
	    uid = (uid_t)-1;
	}
    }
    return true;
}

int Daemon::onStart(int argc, const tchar * const *argv) {
    char buf[64];
    bool buffer;
    int ret = 0;
    struct stat sbuf, sfile;
    time_t start;

    time(&start);
    srvcpath = path;
    cfg.prefix(name.c_str());
    stStatus = Starting;
    do {
	lckfd = ::open(tstringtoachar(lckfile), O_CREAT | O_WRONLY, S_IREAD |
	    S_IWRITE);
	if (lckfd == -1 || lockfile(lckfd, F_WRLCK, SEEK_SET, 0, Starting, 1)) {
	    dloge(Log::mod(name), Log::cmd(T("start")), T("sts=running"));
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
    sprintf(buf, "%ld", (long)getpid());
    if (ftruncate(lckfd, 0) || write(lckfd, buf, (uint)strlen(buf)) < 1)
	return 2;
    for (int i = 1; i < argc; i++) {
	const tchar *p = argv[i];

	if (*p == '-')
	    while (*p == '-')
		p++;
	else
	    continue;
	if (tstreq(p, T("config"))) {
	    cfgfile = argv[i + 1];
	    break;
	}
    }
    if (cfgfile.empty()) {
	cfgfile = installdir + T("etc/") + name + T(".cfg");
	if (access(tstringtoachar(cfgfile), R_OK)) {
	    cfgfile = installdir + name + T(".cfg");
	    if (access(tstringtoachar(cfgfile), R_OK)) {
		cfgfile = name + T(".cfg");
		if (access(tstringtoachar(cfgfile), R_OK))
		    cfgfile.erase();
	    }
	}
    }
    if (!onRefresh())
	return 3;
    buffer = cfg.get(T("log.file.buffer.enable"), false);
    watch = !console && cfg.get(T("watch.enable"), true);
    dlog.setmp(false);
    if (!cfg.get(T("enable"), true)) {
	dlogn(Log::mod(name), Log::cmd(T("start")), Log::kv(T("sts"),
	    T("disabled")));
	return 4;
    }
    if (sbuf.st_size)
	dlogw(Log::mod(name), Log::error(T("restarting after abort")));
    dlogn(Log::mod(name), Log::cmd(T("start")), Log::kv(T("host"),
	Sockaddr::hostname()), Log::kv(T("dir"), installdir.c_str()),
	Log::kv(T("instance"), instance), Log::kv(T("release"), ver));
#ifndef _WIN32
    rlimit rl;
    passwd *pwd;
    string uidname = cfg.get(T("uid"));

    if (uidname.empty()) {
	uid = (uid_t)-1;
    } else {
	if (istdigit(uidname[0]))
	    pwd = getpwuid((uid_t)atoi(uidname.c_str()));   // NOLINT
	else
	    pwd = getpwnam(uidname.c_str());	// NOLINT
	if (pwd) {
	    gid = pwd->pw_gid;
	    uid = pwd->pw_uid;
	    uidname = pwd->pw_name;
	    dlog.setids(uid, gid);
	    (void)fchown(lckfd, uid, gid);
	} else {
	    dloge(Log::mod(name), T(" unknown uid "), uidname);
	}
    }
    dlogd(Log::mod(name), Log::kv(T("uid"), uid == (uid_t)-1 ? getuid() :
	(uid_t)uid), Log::kv(T("gid"), gid <= 0 ? getgid() : (uid_t)gid),
	Log::kv(T("maxfd"), getrlimit(RLIMIT_NOFILE, &rl) ? OPEN_MAX :
	rl.rlim_cur));
#endif
    if (watch) {
#ifndef _WIN32
	bool first = true;
	struct sigaction sa;

	ZERO(sa);
	sa.sa_flags = SA_SIGINFO;
	sa.sa_sigaction = watch_handler;
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGCONT, &sa, NULL);
	sigaction(SIGHUP, &sa, NULL);
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	sigaction(SIGTSTP, &sa, NULL);
	sigaction(SIGUSR1, &sa, NULL);
	sigaction(SIGUSR2, &sa, NULL);
	dlog.stop();
	do {
	    time(&start);
	    child = fork();
	    if (child == -1) {
		dloge(Log::mod(name), Log::cmd(T("fork")), Log::error(errno));
		sleep(cfg.get(T("watch.interval"), 60U) / 4);
	    } else if (child) {
		struct flock fl;
		sigset_t sigs;

		ZERO(sa);
		sa.sa_flags = 0;
		sa.sa_handler = null_handler;
		sigaction(SIGALRM, &sa, NULL);
		sigemptyset(&sigs);
		sigaddset(&sigs, SIGALRM);
		pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);
		first = false;
		sprintf(buf, "%lu %lu", (ulong)getpid(), (ulong)child);
		if (lseek(lckfd, 0, SEEK_SET) || write(lckfd, buf, strlen(
		    buf)) < 1) {
		    dlogw(Log::mod(name), Log::cmd(T("watch")),
			Log::kv(T("pid"), child), Log::error(errno));
		} else {
		    dlogd(Log::mod(name), Log::cmd(T("watch")),
			Log::kv(T("pid"), child));
		}
		lockfile(lckfd, F_UNLCK, SEEK_SET, 0, 0, 0);
		ZERO(fl);
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		while (fcntl(lckfd, F_GETLK, &fl) != -1 && !fl.l_pid)
		    msleep(100);
		while (true) {
		    int flg = 0;
		    string info;
		    uint intvl = cfg.get(T("watch.interval"), 60U);
		    ulong kb = 0;
		    ulong maxmem = cfg.get(T("watch.maxmem"), 0U);
		    struct pidstat psbuf;
		    int sts;

		    dlog.close();
		    alarm(intvl);
		    if (lockfile(lckfd, F_WRLCK, SEEK_SET, 0, Running, 0) ==
			-1) {
			alarm(0);
			flg = WNOHANG;
		    }
		    if (waitpid(child, &sts, flg) > 0) {
			alarm(0);
			ret = WIFEXITED(sts) ? WEXITSTATUS(sts) :
			    WIFSIGNALED(sts) ? WTERMSIG(sts) : 0;
			if (!qflag)
			    dloga(Log::mod(name), Log::cmd(T("watch")),
				Log::kv(T("pid"), child), Log::kv(T("sts"), ret),
				Log::error(T("unexpected exit")),
				Log::kv(T("duration"), time(NULL) - start));
			break;
		    }
		    alarm(0);
		    if (!pidstat(child, &psbuf))
			kb = psbuf.sz;
		    if (qflag || (maxmem && kb > maxmem) ||
			(status() != Starting && !check(info))) {
			uint waitlmt = cfg.get(T("watch.wait"), 30U);

			if (!qflag)
			    kill(child, cfg.get(T("watch.core"), false) ?
				SIGQUIT : SIGINT);
			alarm(waitlmt);
			if (waitpid(child, &sts, 0) == -1) {
			    dlogn(Log::mod(name), Log::cmd(T("watch")),
				T("killing hung child"));
			    if (kill(child * -1, SIGKILL))
				kill(child, SIGKILL);
			    alarm(waitlmt);
			    waitpid(child, &sts, 0);
			}
			alarm(0);
			if (!qflag) {
			    dlogw(Log::mod(name), Log::cmd(T("watch")),
				Log::kv(T("pid"), child), Log::kv(T("mem"), kb),
				Log::kv(T("max"), maxmem), T("restarted"));
			} else if (!flg) {
			    dlogn(Log::mod(name), Log::cmd(qflag == Fast ?
				T("exit") : T("stop")), Log::kv(T("duration"),
				time(NULL) - start), Log::kv(T("mem"), kb),
				Log::kv(T("rss"), psbuf.rss));
			}
			ret = 0;
			break;
		    }
		}
		lockfile(lckfd, F_WRLCK, SEEK_SET, 0, qflag ? Stopping :
		    Starting, 0);
	    } else {
		lockfile(lckfd, F_WRLCK, SEEK_SET, 0, Starting, 0);
		if (!first) {
		    dlogn(Log::mod(name), Log::cmd(T("start")),
			Log::kv(T("host"), Sockaddr::hostname()),
			Log::kv(T("dir"), installdir.c_str()),
			Log::kv(T("instance"), instance),
			Log::kv(T("release"), ver));
		}
		setpgid(0, getpid());
		ret = Service::onStart(argc, argv);
		dlog.buffer(buffer);
	    }
	} while (!qflag && child && !ret);
	if (child) {
	    tunlink(lckfile.c_str());
	    lockfile(lckfd, F_UNLCK, SEEK_SET, 0, 0, 0);
	    ::close(lckfd);
	    exit(ret);
	}
#endif
    } else {
	ret = Service::onStart(argc, argv);
	sprintf(buf, "%lu", (ulong)sigpid);
	if (ftruncate(lckfd, 0) || lseek(lckfd, 0, SEEK_SET) < 0 || write(lckfd,
	    buf, (uint)strlen(buf)) < 1)
	    ret = 0;
	dlog.buffer(buffer);
    }
    return ret;
}

void Daemon::onAbort() {
    if (aborted)
	return;
    aborted = true;
    update(Stopped);
    if (restart && !exiting) {
#ifdef _WIN32
	if (tspawnlp(P_NOWAIT, srvcpath.c_str(), srvcpath.c_str(), T("restart"),
	    NULL) < 0)
#else
	string s(srvcpath + " restart");

	if (execl("/bin/sh", "/bin/sh", "-c", s.c_str(), (char *)0) < 0)
#endif
	{   // NOLINT
	    dloge(Log::mod(name), Log::error(T("restart failed ")));
	    _exit(1);
	}
    }
    if (console)
	dloga(Log::mod(name), T("aborting"));
}

void Daemon::onPause(void) {
    dlogn(Log::mod(name), Log::cmd(T("pause")));
}

void Daemon::onResume(void) {
    dlogn(Log::mod(name), Log::cmd(T("resume")));
}

bool Daemon::onRefresh(void) {
    if (!cfgfile.empty() && !cfg.read(cfgfile.c_str())) {
	dloga(Log::mod(name), Log::cmd(T("config")), Log::kv(T("file"),
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
    if (!child && refreshed)
	dlog.note(Log::mod(name), Log::cmd(T("reload")));
    else
	refreshed = true;
    return true;
}

void Daemon::onStop(bool fast) {
    dlogn(Log::mod(name), Log::cmd(fast ? T("exit") : T("stop")),
	Log::kv(T("duration"), (mticks() - msec) / 1000U));
    qflag = fast ? Fast : Slow;
}

void Daemon::onSigusr1(void) {
    dlogn(Log::mod(name), Log::cmd(T("rollover")));
    dlog.roll();
}

#ifndef _WIN32
void Daemon::watch_handler(int sig, siginfo_t *, void *) {
    Daemon *daemon = (Daemon *)service;

    if (!daemon->child)
	return;
    else if (sig == SIGHUP)
	daemon->onRefresh();
    else if (sig == SIGINT)
	daemon->qflag = Slow;
    else if (sig == SIGTERM)
	daemon->qflag = Fast;
    kill(daemon->child, sig);
}
#endif
