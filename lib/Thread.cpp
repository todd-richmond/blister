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
#include "Thread.h"

static const thread_id_t NOID = (thread_id_t)-1;

Lock ThreadGroup::grouplck;
set<ThreadGroup *> ThreadGroup::groups;
ulong ThreadGroup::nextId;
ThreadGroup ThreadGroup::MainThreadGroup(false);
Thread Thread::MainThread(THREAD_HDL(), &ThreadGroup::MainThreadGroup);

#ifdef _WIN32
#include <errno.h>

Process Process::self(GetCurrentProcess());
int Process::argc = __argc;
#ifdef _UNICODE
tchar **Process::argv = __wargv;
tchar **Process::envv = _wenviron;
#else
tchar **Process::argv = __argv;
tchar **Process::envv = _environ;
#endif

Mutex::Mutex(const tchar *name) {
    if (name) {
	tstring s(name);

	s.replace(s.begin(), s.end(), '\\', '_');
	hdl = CreateMutex(NULL, 0, s.c_str());
    } else {
	hdl = CreateMutex(NULL, 0, NULL);
    }
}

Process Process::start(tchar *const *args, const int *fds) {
    tstring cmd;
    PROCESS_INFORMATION proc;
    STARTUPINFO si;

    ZERO(proc);
    ZERO(si);
    si.cb = sizeof (si);
    if (fds) {				// only support 3 fds
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = (HANDLE)(ullong)fds[0];
	if (fds[1] != -1) {
	    si.hStdOutput = (HANDLE)(ullong)fds[1];
	    if (fds[2] != -1)
		si.hStdError = (HANDLE)(ullong)fds[2];
	}
    }
    while (*args)
	cmd += *(args++) + ' ';
    if (CreateProcess(NULL, (tchar *)cmd.c_str(), NULL, NULL, TRUE, 0, NULL,
	NULL, &si, &proc))
	CloseHandle(proc.hThread);
    else
	errno = EINVAL;
    return Process(proc.hProcess);
}

#else
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/stat.h>

bool SharedSemaphore::open(const tchar *name, uint init, bool exclusive) {
    int key = (int)(name ? stringhash(name) : IPC_PRIVATE);

    close();
    if ((hdl = semget(key, 1, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR)) ==
	-1) {
	if (exclusive)
	    return false;
    } else {
	semctl(hdl, 0, SETVAL, init);
	return true;
    }
    hdl = semget(key, 1, IPC_CREAT | S_IRUSR | S_IWUSR);
    return hdl != -1;
}
#endif

bool DLLibrary::open(const tchar *dll) {
    close();
    file = dll ? dll : T("self");
#ifdef _WIN32
    hdl = dll ? LoadLibrary(dll) : GetModuleHandle(NULL);
    if (!hdl && dll && file.find(T(".dll")) == file.npos) {
	file += T(".dll");
	hdl = LoadLibrary(file.c_str());
    }
#else
    hdl = dlopen(dll, RTLD_LAZY | RTLD_GLOBAL);
#ifdef __APPLE__
    if (!hdl && dll && file.find(".dylib") == file.npos) {
	file += ".dylib";
	hdl = dlopen(file.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
#else
    if (!hdl && dll && file.find(".so") == file.npos) {
	file += ".so";
	hdl = dlopen(file.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
#endif
    if (!hdl)
	err = dlerror();
#endif
    return hdl != 0;
}

bool DLLibrary::close() {
#ifdef _WIN32
    if (hdl && (HMODULE)hdl != GetModuleHandle(NULL))
	FreeLibrary((HMODULE)hdl);
#else
    if (hdl)
	dlclose(hdl);
#endif
    hdl = 0;
    return true;
}

void *DLLibrary::get(const tchar *symbol) const {
#ifdef _WIN32
    return GetProcAddress((HMODULE)hdl, tchartoachar(symbol));
#else
    return dlsym(hdl, symbol);
#endif
}

uint Processor::count(void) {
    static uint cpus;

    if (!cpus) {
#ifdef _WIN32
	SYSTEM_INFO si;

	GetSystemInfo(&si);
	cpus = (uint)si.dwNumberOfProcessors;
#else
	cpus = (uint)sysconf(_SC_NPROCESSORS_ONLN);
#endif
    }
    return cpus;
}

ullong Processor::affinity(void) {
    ullong mask = (ullong)-1;
#ifdef _WIN32
    DWORD_PTR pmask, smask;

    if (GetProcessAffinityMask(GetCurrentProcess(), &pmask, &smask))
	mask = pmask;
#elif defined(__linux__)
    cpu_set_t cset;

    if (!sched_getaffinity(0, sizeof (cset), &cset)) {
	mask = 0;
	for (uint u = 0; u < sizeof (mask) * 8; u++) {
	    if (CPU_ISSET(u, &cset))
		mask |= (ullong)1 << u;
	}
    }
#endif
    return mask;
}

bool Processor::affinity(ullong mask) {
#ifdef _WIN32
    return SetProcessAffinityMask(GetCurrentProcess(), (uint32_t)mask) != 0;
#elif defined(__linux__)
    cpu_set_t cset;

    CPU_ZERO(&cset);
    for (uint u = 0; u < sizeof (mask) * 8; u++) {
	if (mask && ((ullong)1 << u))
	    CPU_SET(u, &cset);
    }
    return sched_setaffinity(0, sizeof (cset), &cset) == 0;
#else
    (void)mask;
    return false;
#endif
}

Thread::Thread(thread_hdl_t handle, ThreadGroup *tg, bool aterm): cv(lck),
    argument(NULL), autoterm(aterm), hdl(handle), id(NOID), main(NULL),
    retval(0), state(Running) {
    group = ThreadGroup::add(*this, tg);
}

Thread::Thread(void): cv(lck), argument(NULL), autoterm(false), group(NULL),
    hdl(0), id(NOID), main(NULL), retval(0), state(Init) {
}

Thread::~Thread() {
    if (hdl && id != NOID) {
	if (autoterm)
	    terminate();
	else
	    wait();
    }
    if (group)
	group->remove(*this);
}

// set state and notify threadgroup
void Thread::clear(void) {
    lck.lock();
    if (id != NOID) {
#ifdef _WIN32
	CloseHandle(hdl);
#else
	pthread_detach(hdl);
#endif
	id = NOID;
    }
    state = Terminated;
    lck.unlock();
    group->notify(*this);
    lck.lock();
    hdl = 0;
    cv.broadcast();
    lck.unlock();
}

// exit thread cleanly - called by itself
void Thread::end(int status) {
    retval = status;
    clear();
#ifdef _WIN32
    _endthreadex(status);
#else
    pthread_exit(&status);
#endif
}

// call into ThreadMain with correct class scope
int Thread::init(void *thisp) {
    return (static_cast<Thread *> (thisp))->onStart();
}

bool Thread::priority(int pri) {
    if (!hdl)
	return false;
#ifdef _WIN32
    if (pri < -10)
	return SetThreadPriority(hdl, THREAD_PRIORITY_IDLE) != 0;
    else if (pri < -5)
	return SetThreadPriority(hdl, THREAD_PRIORITY_LOWEST) != 0;
    else if (pri < 0)
	return SetThreadPriority(hdl, THREAD_PRIORITY_BELOW_NORMAL) != 0;
    else if (pri < 1)
	return SetThreadPriority(hdl, THREAD_PRIORITY_NORMAL) != 0;
    else if (pri < 6)
	return SetThreadPriority(hdl, THREAD_PRIORITY_ABOVE_NORMAL) != 0;
    else if (pri < 11)
	return SetThreadPriority(hdl, THREAD_PRIORITY_HIGHEST) != 0;
    else
	return SetThreadPriority(hdl, THREAD_PRIORITY_TIME_CRITICAL) != 0;
#else
    int mn, mx;
    int policy;
    struct sched_param sched;

    if (pthread_getschedparam(hdl, &policy, &sched))
	return false;
    mn = sched_get_priority_min(policy);
    mx = sched_get_priority_max(policy);
    if (pri < -20)
	pri = -20;
    else if (pri > 20)
	pri = 20;
    sched.sched_priority = (int)(mn + (mx * 1.0 - mn) / 41 * (pri + 20));
    return pthread_setschedparam(hdl, policy, &sched) == 0;
#endif
}

bool Thread::resume(void) {
    bool ret = false;
    Locker lkr(lck);

    if (state == Suspended) {
	state = Running;
#ifdef _WIN32
	ret = ResumeThread(hdl) != -1;
	if (!ret)
	    state = Suspended;
#else
	ret = true;
#endif
    }
    return ret;
}

// setup thread and call it's main routine
THREAD_FUNC Thread::threadInit(void *arg) {
    Thread *thread = static_cast<Thread *> (arg);
    ThreadState istate = thread->state;

    thread->lck.lock();
    thread->id = THREAD_ID();
    srand((uint)((ulong)microtime() ^ (ulong)thread->id));
    thread->state = Running;
    thread->cv.set();
    thread->lck.unlock();
    if (istate == Suspended)
	thread->suspend();
    thread->retval = (thread->main)(thread->argument);
    thread->clear();
    return 0;
}

// create Thread and have it call ThreadMain()
bool Thread::start(uint stacksz, ThreadGroup *tg, bool suspend, bool aterm) {
    return start(init, this, stacksz, tg, suspend, aterm);
}

// create Thread and start it running at a given function
bool Thread::start(ThreadRoutine func, void *arg, uint stacksz, ThreadGroup *tg,
    bool suspend, bool aterm) {
    Locker lkr(lck);

    argument = arg;
    autoterm = aterm;
    main = func;
    if (state != Terminated && state != Init)
	return false;
    else if (suspend)
	state = Suspended;
    else
	state = Running;
#ifdef _WIN32
    hdl = (HANDLE)_beginthreadex(NULL, stacksz, threadInit, this, 0, (uint *)&id);
#else
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    if (stacksz) {
	stacksz += 32 * 1024;
	pthread_attr_setstacksize(&attr, stacksz);
    }
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    pthread_create(&hdl, &attr, threadInit, this);
    pthread_attr_destroy(&attr);
#endif
    if (hdl) {
	group = ThreadGroup::add(*this, tg);
	cv.wait();
	if (suspend)
	    msleep(100);		    // wait for thread to sleep
	return true;
    } else {
	state = Init;
	return false;
    }
}

bool Thread::stop(void) {
    Locker lkr(lck);

    if (state != Terminated) {
	onStop();
	if (state == Suspended)
	    resume();
	state = Terminated;
    }
    return true;
}

bool Thread::suspend() {
    Locker lkr(lck);

    if (state == Suspended) {
	return true;
    } else if (state == Running) {
	state = Suspended;
	lkr.unlock();
#ifdef _WIN32
	if (SuspendThread(hdl) != (DWORD)-1)	//-V720
	    return true;
#endif
	lkr.lock();
	if (state == Suspended)
	    state = Running;
    }
    return false;
}

// terminate thread ungracefully
bool Thread::terminate(void) {
    bool ret = false;
    Locker lkr(lck);

    if (state == Running || state == Suspended) {
#ifdef _WIN32
#pragma warning(disable: 6258)
	ret = TerminateThread(hdl, 1) != FALSE;
#else
	ret = pthread_cancel(hdl) == 0;
#endif
	if (ret) {
	    retval = -2;
	    lkr.unlock();
	    clear();
	}
    } else if (state == Terminated) {
	ret = true;
    }
    return ret;
}

// wait for thread to exit
bool Thread::wait(ulong timeout) {
    Locker lkr(lck);

    if (state == Init) {
	return true;
    } else if (state == Terminated) {
	return hdl ? cv.wait() : true;
    } else if (id == NOID) {
	lkr.unlock();
#ifdef _WIN32
	return WaitForSingleObject(hdl, timeout) == WAIT_OBJECT_0;
#else
	// pthreads do not support a timeout
	if (timeout == INFINITE)
	    return pthread_join(hdl, NULL) == 0;
#endif
    } else {
	return cv.wait(timeout);
    }
    return false;
}

ThreadGroup::ThreadGroup(bool aterm): cv(cvlck), autoterm(aterm), state(Init) {
    grouplck.lock();
    id = (thread_id_t)((ulong)nextId++);
    groups.insert(this);
    grouplck.unlock();
}

ThreadGroup::~ThreadGroup() {
    if (autoterm)
	terminate();
    wait(INFINITE, true);
    waitForMain(INFINITE);
    grouplck.lock();
    groups.erase(this);
    grouplck.unlock();
}

ThreadGroup *ThreadGroup::add(Thread &thread, ThreadGroup *tg) {
    if (!tg) {
	set<ThreadGroup *>::iterator i;
	set<Thread *>::iterator ii;

	grouplck.lock();
	for (i = groups.begin(); i != groups.end(); ++i) {
	    tg = *i;
	    if (!THREAD_ISSELF(tg->master.id)) {
		tg->cvlck.lock();
		for (ii = tg->threads.begin(); ii != tg->threads.end(); ++ii) {
		    if (THREAD_ISSELF((*ii)->id))
			break;
		}
		tg->cvlck.unlock();
		if (ii == tg->threads.end())
		    tg = NULL;
		else
		    break;
	    }
	}
	grouplck.unlock();
	if (tg == NULL)
	    tg = &MainThreadGroup;
    }
    if (&thread != &tg->master) {
	tg->cvlck.lock();
	tg->threads.insert(&thread);
	tg->cvlck.unlock();
    }
    return tg;
}

// control all threads in group - does not work yet if caller is in same group
void ThreadGroup::control(ThreadState ts, ThreadControlRoutine func) {
    set<Thread *>::iterator it;
    Locker lck(cvlck);

    state = ts;
    for (it = threads.begin(); it != threads.end(); ++it) {
	if (!THREAD_ISSELF((*it)->id))
	    ((*it)->*func)();
    }
}

int ThreadGroup::init(void *thisp) {
    return (static_cast<ThreadGroup *>(thisp))->onStart();
}

void ThreadGroup::notify(const Thread &thread) {
    if (&thread != &master) {
	Locker lkr(cvlck);

	cv.set();
    }
}

void ThreadGroup::priority(int pri) {
    set<Thread *>::iterator it;
    Locker lkr(cvlck);

    for (it = threads.begin(); it != threads.end(); ++it)
	(*it)->priority(pri);
}

void ThreadGroup::remove(Thread &thread) {
    Locker lkr(cvlck);

    threads.erase(&thread);
}

bool ThreadGroup::start(uint stacksz, bool suspend, bool aterm) {
    if (master.getState() != Init && master.getState() != Terminated)
	return false;
    autoterm = aterm;
    return master.start(init, this, stacksz, this, suspend, autoterm);
}

Thread *ThreadGroup::wait(ulong msec, bool all) {
    Locker lkr(cvlck);

    do {
	set<Thread *>::iterator it(threads.begin());
	bool running = false;

	while (it != threads.end()) {
	    Thread *thread = *it;

	    if (thread->terminated()) {
		threads.erase(it);
		lkr.unlock();
		thread->wait();
		thread->group = NULL;
		if (all) {
		    lkr.lock();
		    it = threads.begin();
		    continue;
		} else {
		    return thread;
		}
	    } else {
		thread_id_t tid = thread->getId();

		if (tid != NOID && !THREAD_ISSELF(tid))
		    running = true;
	    }
	    ++it;
	}
	if (!running || !msec) {
	    break;
	} else if (msec == INFINITE) {
	    cv.wait(msec);
	} else {
	    ulong diff;
	    msec_t start = mticks();

	    if (!cv.wait(msec))
		break;
	    diff = (ulong)(mticks() - start);
	    msec -= diff < msec ? diff : msec;
	}
    } while (true);
    return NULL;
}

