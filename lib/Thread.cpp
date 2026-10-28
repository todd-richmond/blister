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
#include <algorithm>
#include <vector>
#include "Thread.h"

using ThreadLocalMap = vector<pair<void *, ThreadLocalFree>>;

static constexpr thread_id_t NOID = (thread_id_t)-1;
static thread_local ThreadGroup *curgroup;

// cleans up threads not started by Thread; key deleted at library unload
static class ThreadLocalKey: nocopy {
public:
    ThreadLocalKey() {
#ifdef _WIN32
	key = FlsAlloc(destroy);
#else
	pthread_key_create(&key, destroy);
#endif
    }
    ~ThreadLocalKey() {
#ifdef _WIN32
	FlsFree(key);
#else
	pthread_key_delete(key);
#endif
    }

    ThreadLocalMap *get(void) const {
#ifdef _WIN32
	return (ThreadLocalMap *)FlsGetValue(key);
#else
	return (ThreadLocalMap *)pthread_getspecific(key);
#endif
    }
    void set(ThreadLocalMap *fmap) const {
#ifdef _WIN32
	FlsSetValue(key, fmap);
#else
	pthread_setspecific(key, fmap);
#endif
    }
    // callbacks may register new data so detach the map before running them
    void run(void) const {
	ThreadLocalMap *fmap = get();

	if (fmap) {
	    set(nullptr);
	    run(fmap);
	}
    }

private:
#ifdef _WIN32
    DWORD key;
#else
    pthread_key_t key;
#endif

    static void run(ThreadLocalMap *fmap) {
	for (const auto &[data, func] : *fmap)
	    func(data);
	delete fmap;
    }
#ifdef _WIN32
    static void WINAPI destroy(void *data);
#else
    static void destroy(void *data) { run((ThreadLocalMap *)data); }
#endif
} flocal;

#ifdef _WIN32
void WINAPI ThreadLocalKey::destroy(void *data) {
    flocal.set(nullptr);
    run((ThreadLocalMap *)data);
}
#endif

atomic_ulong ThreadGroup::next_id;
ThreadGroup ThreadGroup::MainThreadGroup;
#ifdef _WIN32
// GetCurrentThread() is a pseudo-handle that names whichever thread uses it
Thread Thread::MainThread(OpenThread(SYNCHRONIZE | THREAD_QUERY_INFORMATION |
    THREAD_SET_INFORMATION, FALSE, GetCurrentThreadId()),
    &ThreadGroup::MainThreadGroup);
#else
Thread Thread::MainThread(THREAD_HDL(), &ThreadGroup::MainThreadGroup);
#endif

#ifdef _WIN32
// -V::1020
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
    while (*args) {
	cmd += *(args++);
	if (*args)
	    cmd += ' ';
    }
    if (CreateProcess(NULL, cmd.data(), NULL, NULL, TRUE, // NOSONAR
	0, NULL, NULL, &si, &proc)) {
	CloseHandle(proc.hThread);
    } else {
	DWORD err = GetLastError();
	errno = (err == ERROR_FILE_NOT_FOUND) ? ENOENT :
	    (err == ERROR_ACCESS_DENIED) ? EACCES :
	    (err == ERROR_NOT_ENOUGH_MEMORY) ? ENOMEM : EINVAL;
    }
    return Process(proc.hProcess);
}

#else
#include <dlfcn.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <sys/stat.h>

bool SharedSemaphore::open(const tchar *name, uint init, bool exclusive) {
    int key = (int)(name ? stringhash(name) : IPC_PRIVATE);

    close();
    if ((hdl = semget(key, 1, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR)) ==
	-1) {
	if (exclusive)
	    return false;
    } else {
#ifdef __linux__
	// new semaphores start at 0 so adding cannot clobber a racing opener
	if (init <= SHRT_MAX) {
	    sembuf op{0, (short)init, 0};

	    if (init)
		::semop(hdl, &op, 1);
	    return true;
	}
#endif
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
    if (!hdl && dll && !file.contains(T(".dll"))) {
	file += T(".dll");
	hdl = LoadLibrary(file.c_str());
    }
#else
    hdl = dlopen(dll, RTLD_LAZY | RTLD_GLOBAL);
#ifdef __APPLE__
    if (!hdl && dll && !file.contains(".dylib")) {
	file += ".dylib";
	hdl = dlopen(file.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
#else
    if (!hdl && dll && !file.contains(".so")) {
	file += ".so";
	hdl = dlopen(file.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
#endif
    if (!hdl) {
	err = dlerror();
	file.erase();
    }
#endif
    return hdl != nullptr;
}

bool DLLibrary::close() {
#ifdef _WIN32
    if (hdl && (HMODULE)hdl != GetModuleHandle(NULL))
	FreeLibrary((HMODULE)hdl);
#else
    if (hdl)
	dlclose(hdl);
#endif
    file.erase();
    hdl = nullptr;
    return true;
}

void *DLLibrary::get(const tchar *symbol) const {
    if (!hdl)
	return nullptr;
#ifdef _WIN32
    return GetProcAddress((HMODULE)hdl, tchartoachar(symbol));
#else
    return dlsym(hdl, symbol);
#endif
}

uint Processor::init(void) {
#ifdef _WIN32
    SYSTEM_INFO si;

    GetSystemInfo(&si);
    return (uint)si.dwNumberOfProcessors;
#else
#ifdef __linux__
    cpu_set_t cset;

    if (!sched_getaffinity(0, sizeof (cset), &cset) && CPU_COUNT(&cset) > 0)
	return (uint)CPU_COUNT(&cset);
#endif
    return (uint)sysconf(_SC_NPROCESSORS_ONLN);
#endif
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
    return SetProcessAffinityMask(GetCurrentProcess(), (DWORD_PTR)mask) != 0;
#elif defined(__linux__)
    cpu_set_t cset;

    CPU_ZERO(&cset);
    for (uint u = 0; u < sizeof (mask) * 8; u++) {
	if (mask & ((ullong)1 << u))
	    CPU_SET(u, &cset);
    }
    return sched_setaffinity(0, sizeof (cset), &cset) == 0;
#else
    (void)mask;
    return false;
#endif
}

// register func to free data at thread exit or free data now if func is null
void Thread::thread_cleanup(void *data, ThreadLocalFree func) {
    WARN_PUSH_DISABLE(26430);
    ThreadLocalMap *fmap = flocal.get();

    if (func) {
	if (!fmap) {
	    fmap = new ThreadLocalMap();
	    flocal.set(fmap);
	}
	for (auto &[d, f] : *fmap) {
	    if (d == data) {
		f = func;
		return;
	    }
	}
	fmap->emplace_back(data, func);
    } else if (data && fmap) {
	auto it = ranges::find(*fmap, data, &ThreadLocalMap::value_type::first);

	if (it != fmap->end()) {
	    func = it->second;
	    fmap->erase(it);
	    func(data);
	}
    }
    WARN_POP();
}

Thread::Thread(thread_hdl_t handle, ThreadGroup *tg): cv(lck),
    argument(nullptr), hdl(handle), id(NOID), main(nullptr), retval(0),
    state(Running) {
    group = ThreadGroup::add(*this, tg);
}

Thread::Thread(void): cv(lck), argument(nullptr), group(nullptr), hdl(0),
    id(NOID), main(nullptr), retval(0), state(Init) {
}

Thread::~Thread() {
    if (hdl && getId() != NOID)
	wait();
    if (group)
	group->remove(*this);
    if (this == &MainThread)
	flocal.run();
}

// set state and notify threadgroup before hdl clears so wait() cannot release
// the Thread or its group while notify() is still running
void Thread::clear(void) {
    flocal.run();
    lck.lock();
#ifdef _WIN32
    CloseHandle(hdl);
#else
    pthread_detach(hdl);
#endif
    id.store(NOID, memory_order_release);
    setState(Terminated);
    group->notify(*this);
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
    pthread_exit(nullptr);
#endif
}

// call into ThreadMain with correct class scope
int Thread::init(void *thisp) {
    return ((Thread *)thisp)->onStart();
}

bool Thread::priority(int pri) {	// NOLINT
    Locker lkr(lck);

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
    pri = clamp(pri, -20, 20);
#ifdef __linux__
    if (mn == mx) {			// SCHED_OTHER only supports nice
	thread_id_t tid = getId();

	if (tid == NOID) {		// wrapped thread - only caller is valid
	    if (!pthread_equal(hdl, pthread_self()))
		return false;
	    tid = 0;
	}
	return setpriority(PRIO_PROCESS, (id_t)tid, -pri) == 0;
    }
#endif
    sched.sched_priority = mn + (mx - mn) * (pri + 20) / 41;
    return pthread_setschedparam(hdl, policy, &sched) == 0;
#endif
}

// setup thread and call it's main routine
THREAD_FUNC Thread::thread_init(void *arg) {
    Thread *thread = (Thread *)arg;
    thread_id_t self = THREAD_ID();

    curgroup = thread->group;
    thread->id.store(self, memory_order_release);
#ifdef _WIN32
    srand((uint)((ulong)uticks() ^ (ulong)(usec_t)self));	// NOSONAR
#endif
    thread->started.release();
    thread->retval = thread->main(thread->argument);
    thread->clear();
    return 0;
}

// create Thread and have it call ThreadMain()
bool Thread::start(uint stacksz, ThreadGroup *tg, bool suspend) {
    return start(init, this, stacksz, tg, suspend);
}

// create Thread and start it running at a given function
// a suspended Thread has no OS thread until resume()
bool Thread::start(ThreadRoutine func, void *arg, uint stacksz, ThreadGroup *tg,
    bool suspend) {
    ThreadGroup *g = ThreadGroup::add(*this, tg);
    Locker lkr(lck);

    // a stopped Thread keeps hdl until its OS thread exits
    if ((getState() != Terminated && getState() != Init) || hdl) {
	lkr.unlock();
	if (g != group)
	    g->remove(*this);
	return false;
    }
    group = g;
    argument = arg;
    main = func;
    stacksize = stacksz;
    if (suspend) {
	setState(Suspended);
	return true;
    }
    return launch(lkr);
}

// create the OS thread
bool Thread::launch(Locker &lkr) {
    setState(Running);
#ifdef _WIN32
    uint tid;

    hdl = (HANDLE)_beginthreadex(NULL, stacksize, thread_init, this, 0, &tid);
#else
    pthread_attr_t attr;
    uint stacksz = stacksize;

    pthread_attr_init(&attr);
    if (stacksz) {
#ifdef NDEBUG
	stacksz += 32 * 1024;
#else
	stacksz += 64 * 1024;
#endif
	pthread_attr_setstacksize(&attr, stacksz);
    }
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    if (pthread_create(&hdl, &attr, thread_init, this))
	hdl = 0;
    pthread_attr_destroy(&attr);
#endif
    if (hdl) {
	started.acquire();
	return true;
    }
    ThreadGroup *g = group;

    setState(Init);
    group = nullptr;
    lkr.unlock();
    g->remove(*this);
    return false;
}

// start a Thread created suspended
bool Thread::resume(void) {
    Locker lkr(lck);

    return getState() == Suspended && launch(lkr);
}

bool Thread::stop(void) {
    Locker lkr(lck);

    if (getState() != Terminated) {
	bool suspended = getState() == Suspended;

	onStop();
	setState(Terminated);
	if (suspended) {		// no thread exists to report exit
	    group->notify(*this);
	    cv.broadcast();
	}
    }
    return true;
}

// wait for thread to exit
bool Thread::wait(ulong timeout) {
    Locker lkr(lck);

    if (getState() == Init || getState() == Suspended)
	return true;
    if (hdl && getId() == NOID) {			// wrapped thread
	thread_hdl_t h = hdl;
	bool ret;

	lkr.unlock();
#ifdef _WIN32
	ret = WaitForSingleObject(h, timeout) == WAIT_OBJECT_0;
#elif defined(__linux__)
	if (timeout == INFINITE) {
	    ret = pthread_join(h, nullptr) == 0;
	} else {
	    timespec ts;

	    clock_gettime(CLOCK_REALTIME, &ts);
	    time_adjust_msec(&ts, timeout);
	    ret = pthread_timedjoin_np(h, nullptr, &ts) == 0;
	}
#else
	// other pthreads do not support a timeout
	ret = timeout == INFINITE && pthread_join(h, nullptr) == 0;
#endif
	if (ret) {			// a joined pthread cannot be joined again
	    lkr.lock();
	    setState(Terminated);
	    hdl = 0;
	    cv.broadcast();
	}
	return ret;
    }

    msec_t end = mticks() + timeout;

    while (hdl) {
	if (timeout == INFINITE) {
	    cv.wait();
	} else {
	    msec_t now = mticks();

	    if (now >= end)
		return false;
	    cv.wait((ulong)(end - now));
	}
    }
    return true;
}

ThreadGroup::ThreadGroup(void): cv(cvlck), id(++next_id), state(Init) {}

ThreadGroup::~ThreadGroup() {
    wait(INFINITE, true);
    waitForMain(INFINITE);
}

ThreadGroup *ThreadGroup::add(Thread &thread, ThreadGroup *tg) {
    if (!tg)
	tg = curgroup ? curgroup : &MainThreadGroup;
    if (&thread != &tg->master) {
	tg->cvlck.lock();
	tg->threads.insert(&thread);
	tg->cvlck.unlock();
    }
    return tg;
}

// run func unlocked; pinned keeps remove()/wait() from freeing the thread
template<class F>
void ThreadGroup::control(F func) {
    Locker lkr(cvlck);

    while (pinned)
	cv.wait();

    const vector<Thread *> snapshot(threads.begin(), threads.end());

    for (auto *thread : snapshot) {
	if (!threads.contains(thread))
	    continue;
	pinned = thread;
	lkr.unlock();
	func(*thread);
	lkr.lock();
	cv.broadcast();
    }
    pinned = nullptr;
    cv.broadcast();
}

int ThreadGroup::init(void *thisp) {
    return ((ThreadGroup *)thisp)->onStart();
}

// broadcast since waiters also watch for pinned to clear
void ThreadGroup::notify(const Thread &thread) {
    if (&thread != &master) {
	Locker lkr(cvlck);

	cv.broadcast();
    }
}

void ThreadGroup::priority(int pri) {
    control([pri](Thread &thread) { thread.priority(pri); });
}

void ThreadGroup::remove(Thread &thread) {
    Locker lkr(cvlck);

    while (pinned == &thread)
	cv.wait();
    threads.erase(&thread);
}

bool ThreadGroup::start(uint stacksz, bool suspend) {
    if (master.getState() != Init && master.getState() != Terminated)
	return false;
    return master.start(init, this, stacksz, this, suspend);
}

void ThreadGroup::stop(void) {
    const thread_id_t self = THREAD_ID();

    onStop();
    setState(Terminated);
    control([self](Thread &thread) {
	if (!THREAD_EQUAL(thread.getId(), self))
	    thread.stop();
    });
}

Thread *ThreadGroup::wait(ulong msec, bool all) {
    const thread_id_t self = THREAD_ID();
    Locker lkr(cvlck);

    do {
	Thread *batch[64];
	uint count = 0;
	bool running = false;

	for (auto it = threads.begin(); it != threads.end(); ) {
	    Thread *thread = *it;

	    if (thread->terminated() && thread != pinned) {
		it = threads.erase(it);
		batch[count++] = thread;
		if (!all || count == 64)
		    break;
	    } else {
		thread_id_t tid = thread->getId();

		if (thread == pinned || (tid != NOID &&
		    !THREAD_EQUAL(tid, self)))
		    running = true;
		++it;
	    }
	}
	if (count > 0) {
	    lkr.unlock();
	    for (uint i = 0; i < count; i++) {
		batch[i]->wait();
		batch[i]->group = nullptr;
	    }
	    if (all) {
		lkr.lock();
		continue;
	    } else {
		return batch[0];
	    }
	}
	if (!running || !msec) {
	    break;
	} else if (msec == INFINITE) {
	    cv.wait(msec);
	} else {
	    ulong diff;
	    msec_t ticks = mticks();

	    if (!cv.wait(msec))
		break;
	    diff = (ulong)(mticks() - ticks);
	    msec = diff < msec ? msec - diff : 0;
	}
    } while (true);
    return nullptr;
}
