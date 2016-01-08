/*
 * Copyright 2001-2014 Todd Richmond
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

static const uint STATUS_LOOPS = 400;

bool Service::aborted;
bool Service::console;
bool Service::exiting;
bool Service::restart;
tstring Service::srvcpath;
Service *Service::service;
volatile pid_t Service::sigpid;
tstring Service::ver(T(__DATE__) T(" ") T(__TIME__));

#ifdef __linux__
typedef void (*KillFunc)(void);
DLLibrary pthread(T("libpthread"));
KillFunc killfunc = (KillFunc)pthread.get(T("pthread_kill_other_threads_np"));
#endif

#ifndef OPEN_MAX
#define OPEN_MAX 256
#endif

void Service::splitpath(const tchar *full, const tchar *id, tstring &root,
    tstring &prog) {
    tchar buf[PATH_MAX + 2];
    const tchar *p = NULL;
    tstring::size_type pos;
    const tchar *sep;

    (void)id;
    p = tgetenv(T("installdir"));
    if (p) {
	root = p;
    } else {
	if (full[0] == '/' || full[1] == ':') {
	    root = full;
	} else {
	    (void)tgetcwd(buf, sizeof(buf) / sizeof(tchar));
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
		dlog << Log::Warn << Log::mod(id) <<
		    Log::kv(T("err"), T("install key missing")) << endlog;
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
	prog.assign(p, sep - p);
    else
	prog = p;
}

#ifdef _WIN32
#include <process.h>

#pragma comment(lib, "advapi32.lib")

#define DWORD_MULTIPLE(x) (((x + sizeof (DWORD) - 1 ) / sizeof (DWORD)) * sizeof (DWORD))
#define PREFIX T("service_")

Service::Service(const tchar *servicename, const tchar *h): name(servicename),
    bPause(false), errnum(0), ctrlfunc(NULL), gid(0), hStatus(0), hSCManager(0),
    hService(0), checkpoint(0), map(NULL), mapsz(0), maphdl(0),
    pid(0), stStatus(Stopped), uid(0) {
    if (h)
	host = h;
}

Service::Service(const tchar *servicename, bool pauseable): name(servicename),
    bPause(pauseable), errnum(0), ctrlfunc(service_handler), gid(0), hStatus(0),
    hSCManager(0), hService(0), checkpoint(0), map(NULL), mapsz(0), maphdl(0),
    pid(0), stStatus(Stopped), uid(0) {
    service = this;
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
    _exit(1);
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
    tchar *p = NULL, *pp;
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
    tstring s(PREFIX + name);

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
	    dlog << Log::Err << Log::mod(name) << Log::kv(T("err"),
		T("unable to open performance registry key")) << endlog;
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
	    dlog << Log::Err << Log::mod(name) <<  Log::kv(T("err"),
		T("unable to determine counter info")) << endlog;
	    RegCloseKey(key);
	    return 1;
	}
	RegCloseKey(key);
	s = PREFIX + name;
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
	size = sizeof (PERF_OBJECT_TYPE) +
	    ctrs * sizeof (PERF_COUNTER_DEFINITION);
	datasz = (size_t)size + sizeof (PERF_INSTANCE_DEFINITION) + DWORD_MULTIPLE(namesz) +
	    sizeof (PERF_COUNTER_BLOCK);
	if ((data = new char [datasz]) == NULL) {
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
	pid = (PERF_INSTANCE_DEFINITION *)((char *)data + size);
	pid->ByteLength = sizeof (PERF_INSTANCE_DEFINITION) +
	    DWORD_MULTIPLE(namesz) + 4;
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
	pcb->ByteLength = sizeof (PERF_COUNTER_BLOCK) + mapsz;
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
	((char *)data + sizeof (PERF_OBJECT_TYPE)) + last;

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
    if ((fd = ::open(lckfile.c_str(), O_RDONLY)) == -1)
	return false;
    ZERO(fl);
    fl.l_type = F_WRLCK;
    fl.l_whence = SEEK_SET;
    if (fcntl(fd, F_GETLK, &fl) != -1 && fl.l_pid) {
	char buf[16];
	int in;

	pid = (pid_t)fl.l_pid;
	stStatus = (Status)fl.l_len;
	if ((in = (int)read(fd, buf, sizeof (buf) - 1)) > 0) {
	    buf[in] = '\0';
	    pid = atoi(buf);
	    lseek(fd, 0, SEEK_SET);
	}
    }
    ::close(fd);
    return pid != 0;
}

bool Service::close(void) {
    pid = 0;
    return true;
}

void Service::signal_handler(int sig) {
    if (!aborted) {
	bool ispaused = (service->stStatus == Paused);

	if (sig == SIGINT) {
	    service->update(Stopping);
	    service->onStop(false);
	} else if (sig == SIGTERM) {
	    service->update(Stopping);
	    service->onStop(true);
	} else if (sig == SIGHUP) {
	    if (!ispaused)
		service->update(Refreshing);
	    if (!service->onRefresh()) {
		service->update(Stopping);
		service->onStop(false);
	    }
	    if (!ispaused)
		service->update(Running);
	} else if (sig == SIGTSTP && service->bPause && !ispaused) {
	    service->update(Pausing);
	    service->onPause();
	    service->update(Paused);
	} else if (ispaused && sig == SIGCONT) {
	    service->update(Resuming);
	    service->onResume();
	    service->update(Running);
	} else if (sig == SIGUSR1) {
	    service->onSigusr1();
	} else if (sig == SIGUSR2) {
	    service->onSigusr2();
	} else if (sig == SIGPIPE || sig == SIGALRM) {
	} else if (sig == SIGABRT || sig == SIGBUS || sig == SIGFPE ||
#ifdef SIGSTKFLT
	    sig == SIGSTKFLT ||
#endif
	    sig == SIGILL || sig == SIGTRAP || sig == SIGSEGV) {
	    service->onAbort();
	}
    }
    dlog.flush();
    if (aborted)
	_exit(1);
}

void Service::null_handler(int) {}

void Service::setsignal(bool abrt) {
    sigset_t sigs;
    struct sigaction sa;

    ZERO(sa);
    sa.sa_handler = null_handler;
    sigaction(SIGHUP, &sa, NULL);
    sa.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sa, NULL);
    sa.sa_handler = SIG_DFL;
    sigaction(SIGQUIT, &sa, NULL);
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGABRT);
    sigaddset(&sigs, SIGCONT);
    sigaddset(&sigs, SIGHUP);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGTERM);
    sigaddset(&sigs, SIGTSTP);
    sigaddset(&sigs, SIGUSR1);
    sigaddset(&sigs, SIGUSR2);
    sigprocmask(SIG_UNBLOCK, &sigs, NULL);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);
    if (abrt) {
	sa.sa_mask = sigs;
	sa.sa_handler = signal_handler;
	sigaction(SIGABRT, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
	sigaction(SIGFPE, &sa, NULL);
	sigaction(SIGILL, &sa, NULL);
	sigaction(SIGTRAP, &sa, NULL);
	sigaction(SIGSEGV, &sa, NULL);
#ifdef SIGSTKFLT
	sigaction(SIGSTKFLT, &sa, NULL);
#endif
    }
}

int Service::ctrl_handler(void *) {
    sigset_t sigs;
    int sig;

    sigpid = getpid();
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGABRT);
    sigaddset(&sigs, SIGCONT);
    sigaddset(&sigs, SIGHUP);
    sigaddset(&sigs, SIGINT);
    sigaddset(&sigs, SIGPIPE);
    sigaddset(&sigs, SIGTERM);
    sigaddset(&sigs, SIGTSTP);
    sigaddset(&sigs, SIGUSR1);
    sigaddset(&sigs, SIGUSR2);
    do {
	char buf[8];
	const tchar *str;

	sig = 0;
    	sigwait(&sigs, &sig);
	switch (sig) {
	case SIGABRT:
	    str = T("abort");
	    break;
	case SIGHUP:
	    str = T("refresh");
	    break;
	case SIGINT:
	    str = T("shutdown");
	    break;
	case SIGPIPE:
	    str = T("pipe");
	    break;
	case SIGTERM:
	    str = T("termination");
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
	    str = T("SIGUSR2");
	    break;
	default:
	    sprintf(buf, T("%i"), sig);
	    str = buf;
	    break;
	};
	dlog << Log::Info << Log::mod(service->name) << Log::kv(T("sig"),
	    str) << endlog;
	signal_handler(sig);
    } while (sig && sig != SIGABRT && sig != SIGINT && sig != SIGTERM &&
	sig != SIGBUS && sig != SIGFPE && sig != SIGILL && sig != SIGSEGV);
    sigpid = 0;
    return 0;
}

int Service::run(int argc, const tchar * const *argv) {
    int ret;
    struct rlimit rl;

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
	    dlog << Log::Err << Log::mod(argv[0]) << Log::kv(T("err"),
		T("unable to fork")) << endlog;
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
    chown(file, getuid(), getgid());
    return chmod(file, S_ISUID|S_IRWXU|S_IRGRP|S_IXGRP|S_IROTH|S_IXOTH) != -1;
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
    if (console) {
	run(argc, argv);
    } else if ((fpid = fork()) == -1) {
	errnum = errno;
	return false;
    } else if (fpid == 0) {
	exit(run(argc, argv));
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
    console = isatty(0);
    if (getuid() != geteuid() && getuid() != 0) {
	tcout << name << T(": uid permission denied") << endl;
	return 1;
    }
#endif
    av = new const tchar *[argc + 1];
    path = argv[0];
    if (path[0] != '/' && path[1] != ':') {
	tchar buf[PATH_MAX + 2];

	(void)tgetcwd(buf, sizeof(buf) / sizeof(tchar));
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
	} else if (tstreq(cmd, T("pidfile"))) {
	    if (i == argc - 1) {
		dlog.err(T("pid filename required"));
		delete [] av;
		return -1;
	    }
	    lckfile = argv[++i];
	} else {
	    while (++i < argc)
		av[ac++] = argv[i];
	    break;
	}
    }
    splitpath(argv[0], name.c_str(), installdir, prog);
    if (name.empty())
	name = prog;
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
	tcout << name << T("\t[--installdir dir] [--pidfile file]:") << endl <<
	    T("\t[--console|--daemon] [--logfile file] [--outfile file]") <<
	    T(" condrestart|") << endl <<
	    T("\t\trestart|start [args]") << endl <<
	    T("\thelp") << endl <<
	    T("\tinstall [description [dependencies]]") << endl <<
	    T("\tkill") << endl << T("\tpause") << endl <<
	    T("\trefresh") << endl << T("\tresume") << endl <<
	    T("\troll") << endl << T("\tstate") << endl <<
	    T("\tstatus") << endl << T("\tstop") << endl <<
	    T("\tuninstall") << endl << T("\tversion") << endl << endl;
    } else if (tstreq(cmd, T("pause")) || tstreq(cmd, T("suspend"))) {
	ret = !pause();
    } else if (tstreq(cmd, T("refresh")) ||
	tstreq(T("reload"), cmd)) {
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
    } else if (tstreq(cmd, T("sigusr1")) || tstreq(cmd, T("roll")) ||
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

const tchar *Service::status(Status s) {
    static const tchar *StatusStr[] = {
	T("Error"), T("Starting"), T("Refreshing"), T("Pausing"), T("Paused"),
	T("Resuming"), T("Stopping"), T("Running"), T("Stopped")
    };

    return StatusStr[(int)s];
}


Daemon::Daemon(const tchar *name, const tchar *display, bool pauseable):
    Service(name, pauseable), qflag(None), child(0), lckfd(-1),
    refreshed(false), start(0), watch(false) {
    (void)display;
}

Daemon::~Daemon() {
    if (qflag != None)
	dlog << Log::Note << Log::mod(name) << Log::kv(T("sts"),
	    T("stopped")) << endlog;
    if (lckfd != -1) {
	if (!watch || child)
	    (void)tunlink(lckfile.c_str());
	(void)lockfile(lckfd, F_UNLCK, SEEK_SET, 0, 0, 0);
	::close(lckfd);
    }
}

bool Daemon::update(Status status) {
    if (status < stStatus)
	(void)lockfile(lckfd, F_UNLCK, SEEK_SET, status, 0, 0);
    else
	(void)lockfile(lckfd, F_WRLCK, SEEK_SET, 0, status, 0);
    return Service::update(status);
}

bool Daemon::setids() {
    if (uid != (uid_t)-1) {
	(void)fchown(lckfd, uid, gid);
	dlog.setids(uid, gid);
	if (setgid(gid) || setuid(uid)) {
	    dlog << Log::Err << Log::mod(name) << Log::kv(T("err"),
		T("unable to set uid")) << endlog;
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
    tstring s;
    struct stat sbuf, sfile;

    time(&start);
    srvcpath = path;
    cfg.prefix(name.c_str());
    stStatus = Starting;
    do {
	lckfd = ::open(tstringtoachar(lckfile), O_CREAT | O_WRONLY, S_IREAD |
	    S_IWRITE);
	if (lckfd == -1 || lockfile(lckfd, F_WRLCK, SEEK_SET, 0, Starting, 1)) {
	    dlog << Log::Warn << Log::mod(name) << T("sts=running") << endlog;
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
    ftruncate(lckfd, 0);
    sprintf(buf, "%ld", (long)getpid());
    write(lckfd, buf, (uint)strlen(buf));
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
	s = installdir + T("etc/") + name + T(".cfg");
	if (access(tstringtoachar(s), R_OK)) {
	    s = installdir + name + T(".cfg");
	    if (access(tstringtoachar(s), R_OK)) {
		s = name + T(".cfg");
		if (access(tstringtoachar(s), R_OK))
		    s.erase();
	    }
	}
	cfgfile = s;
    }
    if (!onRefresh())
	return 2;
    buffer = cfg.get(T("log.file.buffer.enable"), false);
    watch = !console && cfg.get(T("watch.enable"), true);
    dlog.setmp(false);
    if (!cfg.get(T("enable"), true)) {
	dlog << Log::Note << Log::mod(name) << Log::cmd(T("start")) <<
	    Log::kv(T("sts"), T("disabled")) << endlog;
	return 3;
    }
    if (sbuf.st_size)
	dlog << Log::Warn << Log::mod(name) <<
	    Log::kv(T("err"), T("restarting after abort")) << endlog;
    dlog << Log::Note << Log::mod(name) << Log::cmd(T("start")) <<
	Log::kv(T("host"), Sockaddr::hostname()) <<
	Log::kv(T("dir"), installdir.c_str()) <<
	Log::kv(T("instance"), instance) <<
	Log::kv(T("release"), ver) << endlog;
#ifndef _WIN32
    struct rlimit rl;
    struct passwd *pwd;
    string uidname = cfg.get(T("uid"));

    if (uidname.empty()) {
	uid = (uid_t)-1;
    } else {
	if (istdigit(uidname[0]))
	    pwd = getpwuid((uid_t)atoi(uidname.c_str()));
	else
	    pwd = getpwnam(uidname.c_str());
	if (pwd) {
	    gid = pwd->pw_gid;
	    uid = pwd->pw_uid;
	    uidname = pwd->pw_name;
	    dlog.setids(uid, gid);
	    fchown(lckfd, uid, gid);
	} else {
	    dlog << Log::Err << Log::mod(name) << T(" unknown uid ") <<
		uidname << endlog;
	}
    }
    dlog << Log::Debug << Log::mod(name) <<
	Log::kv(T("uid"), uid == (uid_t)-1 ? getuid() : (uid_t)uid) <<
	Log::kv(T("gid"), gid <= 0 ? getgid() : (uid_t)gid) <<
	Log::kv(T("maxfd"), getrlimit(RLIMIT_NOFILE, &rl) ? OPEN_MAX :
	rl.rlim_cur) << endlog;
#endif
    if (watch) {
#ifndef _WIN32
	bool first = true;
	struct sigaction sa;

	ZERO(sa);
	sa.sa_handler = watch_handler;
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
		dlog << Log::Err << Log::mod(name) << Log::kv(T("err"),
		    strerror(errno)) << endlog;
		sleep(cfg.get(T("watch.interval"), 60U) / 4);
	    } else if (child) {
		struct flock fl;
		Log::Level lvl = dlog.level();

		ZERO(sa);
		sa.sa_handler = null_handler;
		sigaction(SIGALRM, &sa, NULL);
		dlog << Log::Debug << Log::mod(name) << Log::cmd(T("watch")) <<
		    Log::kv(T("pid"), child) << endlog;
		dlog.close();
		dlog.level(Log::None);
		first = false;
		lseek(lckfd, 0, SEEK_SET);
		sprintf(buf, "%ld %ld", (long)getpid(), (long)child);
		write(lckfd, buf, strlen(buf));
		lockfile(lckfd, F_UNLCK, SEEK_SET, 0, 0, 0);
		ZERO(fl);
		fl.l_type = F_WRLCK;
		fl.l_whence = SEEK_SET;
		while (fcntl(lckfd, F_GETLK, &fl) != -1 && !fl.l_pid)
		    msleep(0);
		while (true) {
		    int flg = 0;
		    string info;
		    uint intvl = cfg.get(T("watch.interval"), 60U);
		    ulong kb = 0;
		    ulong maxmem = cfg.get(T("watch.maxmem"), 0U);
		    int sts;

		    alarm(intvl);
		    if (lockfile(lckfd, F_WRLCK, SEEK_SET, 0, Running, 0) == -1) {
			alarm(0);
			flg = WNOHANG;
		    } else {
			dlog.level(lvl);
		    }
		    if (waitpid(child, &sts, flg) > 0) {
			alarm(0);
			dlog.level(lvl);
			ret = WIFEXITED(sts) ? WEXITSTATUS(sts) :
			    WIFSIGNALED(sts) ? WTERMSIG(sts) : 0;
			if (!qflag)
			    dlog << Log::Warn << Log::mod(name) <<
				Log::cmd(T("watch")) <<
				Log::kv(T("pid"), child) <<
				Log::kv(T("sts"), ret) <<
				Log::kv(T("err"), T("unexpected exit")) <<
				Log::kv(T("duration"), time(NULL) - start) <<
				endlog;
			break;
		    }
		    alarm(0);
		    if (maxmem) {
#ifdef linux
			int fd;
			char path[64];

			sprintf(path, "/proc/%u/statm", child);
			if ((fd = ::open(path, O_RDONLY)) != -1) {
			    if (read(fd, buf, sizeof (buf)) > 0)
				kb = strtoul(buf, NULL, 10);
			    ::close(fd);
			}
#elif defined(sun)
			char path[64];

			sprintf(path, "/proc/%ld/as", (long)child);
			if (stat(path, &sbuf) != -1)
			    kb = sbuf.st_size / 1024;
#endif
		    }
		    if (qflag || kb > maxmem ||
			(status() != Starting && !check(info))) {
			uint waitlmt = cfg.get(T("watch.wait"), 30U);

			if (!qflag)
			    kill(child, SIGINT);
			alarm(waitlmt);
			if (waitpid(child, &sts, 0) == -1) {
			    kill(child, SIGKILL);
			    alarm(waitlmt);
			    waitpid(child, &sts, 0);
			}
			alarm(0);
			dlog.level(lvl);
			if (!qflag)
			    dlog << Log::Warn << Log::mod(name) <<
				Log::cmd(T("watch")) <<
				Log::kv(T("pid"), child) <<
				Log::kv(T("mem"), kb) <<
				Log::kv(T("max"), maxmem) << info <<
				T(" restarted") << endlog;
			else if (!flg)
			    dlog << Log::Note << Log::mod(name) <<
				Log::cmd(qflag == Fast ? T("exit") :
				T("stop")) << Log::kv(T("duration"),
				time(NULL) - start) << endlog;
			ret = 0;
			break;
		    }
		}
		dlog.level(lvl);
		lockfile(lckfd, F_WRLCK, SEEK_SET, 0, qflag ? Stopping :
		    Starting, 0);
	    } else {
		lockfile(lckfd, F_WRLCK, SEEK_SET, 0, Starting, 0);
		if (!first) {
		    dlog << Log::Note << Log::mod(name) <<
			Log::cmd(T("start")) <<
			Log::kv(T("host"), Sockaddr::hostname()) <<
			Log::kv(T("dir"), installdir.c_str()) <<
			Log::kv(T("instance"), instance) <<
			Log::kv(T("release"), ver) << endlog;
		}
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
	ftruncate(lckfd, 0);
	sprintf(buf, "%lu", (ulong)sigpid);
	lseek(lckfd, 0, SEEK_SET);
	write(lckfd, buf, (uint)strlen(buf));
	dlog.buffer(buffer);
    }
    return ret;
}

void Daemon::onAbort() {
    if (aborted)
	return;
    aborted = true;
#ifdef __linux__
    if (killfunc)
	killfunc();
#endif
    update(Stopped);
    if (restart && !exiting) {
#ifdef _WIN32
	if (spawnlp(P_NOWAIT, tstringtoachar(srvcpath),
	    tstringtoachar(srvcpath), "restart", NULL) < 0)
#else
	string s(srvcpath + " restart");

	if (execl("/bin/bash", "/bin/bash", "-c", s.c_str(), (char *)0) < 0)
#endif
	{
	    dlog << Log::Emerg << Log::mod(name) << Log::kv(T("err"),
	    T("restart failed ")) << endlog;
	    _exit(1);
	}
    }
    if (console)
	dlog << Log::Alert << Log::mod(name) << T("aborting") << endlog;
}

void Daemon::onPause(void) {
    dlog << Log::Note << Log::mod(name) << Log::cmd(T("pause")) << endlog;
}

void Daemon::onResume(void) {
    dlog << Log::Note << Log::mod(name) << Log::cmd(T("resume")) << endlog;
}

bool Daemon::onRefresh() {
    cfg.lock();
    if (!cfgfile.empty() && !cfg.read(cfgfile.c_str())) {
	dlog << Log::Alert << Log::mod(name) <<
	    T("mod=config file=") << cfgfile <<
	    Log::kv(T("err"), T("unable to read")) << endlog;
	cfg.unlock();
	return false;
    }
    if (cfg.get(T("installdir")).empty())
	cfg.set(T("installdir"), installdir.c_str());
    cfg.set(T("name"), name.c_str(), Log::section());
    cfg.set(T("version"), ver.c_str());
    instance = cfg.get(T("instance"), T("default"));
    if (!cfgfile.empty())
	dlog.set(cfg);
    cfg.unlock();
    if (!child && refreshed)
	dlog << Log::Note << Log::mod(name) << Log::cmd(T("reload")) << endlog;
    else
	refreshed = true;
    return true;
}

void Daemon::onStop(bool fast) {
    dlog << Log::Note << Log::mod(name) << Log::cmd(fast ?  T("exit") :
	T("stop")) << Log::kv(T("duration"), time(NULL) - start) << endlog;
    qflag = fast ? Fast : Slow;
}

void Daemon::onSigusr1() {
    dlog << Log::Note << Log::mod(name) << Log::cmd(T("rollover")) << endlog;
    dlog.roll();
}

void Daemon::watch_handler(int sig) {
    Daemon *thisp = static_cast<Daemon *>(service);

    if (!thisp->child)
	return;
    if (sig == SIGHUP) {
	thisp->onRefresh();
    } else if (sig == SIGINT) {
	thisp->qflag = Slow;
    } else if (sig == SIGTERM) {
	thisp->qflag = Fast;
    }
    kill(thisp->child, sig);
}


WatchDaemon::WatchDaemon(int argc, const tchar * const *argv,
    const tchar *dname): Daemon(dname ? dname : T("")), interval(60),
    maxmem(0) {
    int ac;

    for (ac = 2; ac < argc; ac++) {
	const tchar *p = argv[ac];

	if (*p != '-')
	    break;
	while (*p == '-')
	    p++;
	if (!tstrcmp(p, T("check")))
	    interval = tstrtoul(argv[++ac], NULL, 10);
	else if (!tstrcmp(p, T("maxmem")))
	    maxmem = tstrtoul(argv[++ac], NULL, 10);
	else if (!tstrcmp(p, T("name")))
	    name = argv[++ac];
	else
	    ac++;
    }
    if (ac >= argc) {
	const tchar *prog = tstrrchr(argv[0], '/');

	if (!prog && (prog = tstrrchr(argv[0], '\\')) == NULL)
	    prog = argv[0];
	else
	    prog++;
	cout << "usage:" << endl << T("\t") << prog <<
	    T(" start [--check seconds] [--maxmem kb] [--name str] cmd ...") <<
	    endl << T("\t") << prog <<
	    T(" continue|exit|pause|refresh|status|stop [--name str] cmd") <<
	    endl;
	exit(1);
    }
    if (name.empty()) {
	tstring::size_type i;

	name = argv[ac];
	if ((i = name.find_last_of(T("."))) != name.npos)
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
    for (ac = 1; ac < argc; ac++) {
	if (*argv[ac] == '-')
	    ac++;
	else
	    break;
    }
    for (int i = ac + 1; i < argc; i++) {
	if (!args.empty())
	    args += ' ';
	args += argv[i];
    }
#ifndef _WIN32
    sigset_t sigs;

    sigfillset(&sigs);
    sigprocmask(SIG_UNBLOCK, &sigs, NULL);
    pthread_sigmask(SIG_UNBLOCK, &sigs, NULL);
#endif
    running();
    dlog << Log::Info << Log::mod(name) << Log::cmd(T("exec")) <<
	Log::kv(T("file"), argv[ac]) <<
	Log::kv(T("args"), args) << endlog;
    dlog.close();
    texecvp(argv[ac], (tchar **)&argv[ac]);
    dlog << Log::Err << Log::mod(name) << Log::cmd(T("exec")) <<
	Log::kv(T("file"), argv[ac]) <<
	Log::kv(T("err"), strerror(errno)) << endlog;
    return (uint)-1;
}

