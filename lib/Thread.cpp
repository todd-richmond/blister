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

static thread_local ThreadGroup *curgroup;
static thread_local Thread *curthread;

// cleans up threads not started by Thread; key deleted at library unload
static class ThreadLocalKey: nocopy {
public:
#ifdef _WIN32
    ThreadLocalKey() noexcept: key(FlsAlloc(destroy)) {}
#else
    ThreadLocalKey() noexcept { pthread_key_create(&key, destroy); }
#endif
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

// quote args using CommandLineToArgvW() backslash and quote rules
tstring Process::cmdline(const tchar * const *args) {
    tstring cmd;

    for (const tchar * const *a = args; *a; ++a) {
	const tchar *s = *a;

	if (a != args)
	    cmd += T(' ');
	if (*s && !tstrpbrk(s, T(" \t\n\v\""))) {
	    cmd += s;
	    continue;
	}
	cmd += T('"');
	for (;; ++s) {
	    size_t slashes = 0;

	    while (*s == T('\\')) {
		++s;
		++slashes;
	    }
	    if (!*s) {
		cmd.append(slashes * 2, T('\\'));
		break;
	    }
	    cmd.append(*s == T('"') ? slashes * 2 + 1 : slashes, T('\\'));
	    cmd += *s;
	}
	cmd += T('"');
    }
    return cmd;
}

Process Process::start(const tchar *const *args, const int *fds) {
    tstring cmd(cmdline(args));
    PROCESS_INFORMATION proc;
    STARTUPINFO si;

    ZERO(proc);
    ZERO(si);
    si.cb = sizeof (si);
    if (fds) {
	// STARTF_USESTDHANDLES leaves unset handles NULL, not inherited
	auto hdl = [fds](int i, DWORD std) {
	    return fds[i] == -1 ? GetStdHandle(std) : (HANDLE)(ullong)fds[i];
	};

	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = hdl(0, STD_INPUT_HANDLE);
	si.hStdOutput = hdl(1, STD_OUTPUT_HANDLE);
	si.hStdError = hdl(2, STD_ERROR_HANDLE);
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
    int key = name ? (int)stringhash(name) : IPC_PRIVATE;

    if (name && key == IPC_PRIVATE)	// 0 would create a set nobody can share
	key = 1;
    close();
    if ((hdl = semget(key, 1, IPC_CREAT | IPC_EXCL | S_IRUSR | S_IWUSR)) !=
	-1) {
	bool ok;
#ifdef __linux__
	// new semaphores start at 0 so adding cannot clobber a racing opener
	sembuf op{0, (short)init, 0};

	if (init <= SHRT_MAX)
	    ok = !init || semop(op);
	else
#endif
	    ok = semctl(hdl, 0, SETVAL, init) == 0;
	if (!ok) {
	    semctl(hdl, 0, IPC_RMID);
	    hdl = -1;
	}
	return ok;
    }
    if (exclusive || errno != EEXIST)
	return false;
    hdl = semget(key, 1, S_IRUSR | S_IWUSR);
    return hdl != -1;
}

// sem_op 0 waits for zero so post in SHRT_MAX chunks
bool SharedSemaphore::set(uint cnt) {
    sembuf op;

    op.sem_num = 0;
    op.sem_flg = 0;
    while (cnt) {
	op.sem_op = (short)min(cnt, (uint)SHRT_MAX);
	if (!semop(op))
	    return false;
	cnt -= (uint)op.sem_op;
    }
    return true;
}

bool SharedSemaphore::wait(ulong msec) {
    sembuf op;

    op.sem_num = 0;
    op.sem_op = -1;
    op.sem_flg = 0;
    if (msec == INFINITE)
	return semop(op);
#ifdef BSD_BASE
    // no semtimedop() so poll with a short backoff until the deadline
    msec_t end = mticks() + msec;
    ulong nap = 1;

    op.sem_flg = IPC_NOWAIT;
    for (;;) {
	if (::semop(hdl, &op, 1) == 0)
	    return true;
	if (errno != EAGAIN && errno != EINTR)
	    return false;
	msec_t now = mticks();

	if (now >= end)
	    return false;
	if (errno == EAGAIN) {
	    ulong left = (ulong)(end - now);

	    msleep(nap < left ? nap : left);
	    if (nap < 10)
		nap *= 2;
	}
    }
#else
    const msec_t end = mticks() + msec;

    for (;;) {
	timespec ts{};

	time_adjust_msec(&ts, msec);
	if (LIKELY(!semtimedop(hdl, &op, 1, &ts)))
	    return true;
	if (errno != EINTR)
	    return false;

	const msec_t now = mticks();

	if (now >= end)
	    return false;
	msec = (ulong)(end - now);
    }
#endif
}
#endif

// wait for woken and cancelled waiters to finish with their nodes
LifoSemaphore::~LifoSemaphore() {
    Node *n = allnodes.load(memory_order_acquire);
    uint total = 0;

    for (const Node *a = n; a; a = a->allnext)
	++total;
    for (;;) {
	uint idle = 0;

	broadcast();
	for (const Node *f = freelist.top(); f; f =
	    f->next.load(memory_order_acquire))
	    ++idle;
	if (idle >= total && !waiters.load(memory_order_acquire))
	    break;
	THREAD_YIELD();
    }
    while (n) {
	Node *a = n->allnext;

	delete n;
	n = a;
    }
}

bool DLLibrary::open(const tchar *dll) {
    close();
    file = dll ? dll : T("self");
#ifdef _WIN32
    // LoadLibrary appends .dll itself
    hdl = dll ? LoadLibrary(dll) : GetModuleHandle(NULL);
    if (!hdl) {
	err = T("LoadLibrary failed");
	file.erase();
    }
#else
#ifdef __APPLE__
    static constexpr char ext[] = ".dylib";
#else
    static constexpr char ext[] = ".so";
#endif

    hdl = dlopen(dll, RTLD_LAZY | RTLD_GLOBAL);
    if (!hdl && dll && !file.contains(ext)) {
	file += ext;
	hdl = dlopen(file.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
    if (!hdl) {
	err = dlerror();
	file.erase();
    }
#endif
    if (hdl)
	err.erase();
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
    WARN_PUSH_DISABLE(26430)
    ThreadLocalMap *fmap = flocal.get();

    if (func) {
	if (!fmap) {
	    fmap = new ThreadLocalMap();
	    flocal.set(fmap);
	}
	auto it = ranges::find(*fmap, data, &ThreadLocalMap::value_type::first);

	if (it != fmap->end())
	    it->second = func;
	else
	    fmap->emplace_back(data, func);
    } else if (data && fmap) {
	auto it = ranges::find(*fmap, data, &ThreadLocalMap::value_type::first);

	if (it != fmap->end()) {
	    func = it->second;
	    fmap->erase(it);
	    func(data);
	}
    }
    WARN_POP()
}

Thread::Thread(thread_hdl_t handle, ThreadGroup *tg) noexcept: hdl(handle),
    state(Running) {
    group = ThreadGroup::add(*this, tg);
}

Thread::~Thread() {
    Locker lkr(lck);

    // clear() runs on the OS thread and touches this until it unlocks
    while (hdl && getId() != NOID && this != current())
	cv.wait();

    ThreadGroup *g = group;

    lkr.unlock();
    if (g)
	g->remove(*this);
    if (this == &MainThread)
	flocal.run();
}

// set state and notify threadgroup before hdl clears so wait() cannot release
// the Thread or its group while notify() is still running
void Thread::clear(void) {
    flocal.run();
    curthread = nullptr;
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

Thread *Thread::current(void) { return curthread; }

// call into ThreadMain with correct class scope
int Thread::init(void *thisp) {
    return ((Thread *)thisp)->onStart();
}

bool Thread::priority(int pri) {	// NOLINT
    Locker lkr(lck);

    if (!hdl)
	return false;
#ifdef _WIN32
    return SetThreadPriority(hdl, pri < -10 ? THREAD_PRIORITY_IDLE :
	pri < -5 ? THREAD_PRIORITY_LOWEST : pri < 0 ?
	THREAD_PRIORITY_BELOW_NORMAL : pri < 1 ? THREAD_PRIORITY_NORMAL :
	pri < 6 ? THREAD_PRIORITY_ABOVE_NORMAL : pri < 11 ?
	THREAD_PRIORITY_HIGHEST : THREAD_PRIORITY_TIME_CRITICAL) != 0;
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
    sched.sched_priority = mn + (mx - mn) * (pri + 20) / 40;
    return pthread_setschedparam(hdl, policy, &sched) == 0;
#endif
}

// setup thread and call it's main routine
THREAD_FUNC Thread::thread_init(void *arg) {
    Thread *thread = (Thread *)arg;
    thread_id_t self = THREAD_ID();

    curgroup = thread->group;
    curthread = thread;
    thread->id.store(self, memory_order_release);
    thread->setState(Running);
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
// the group sees the Thread only once it is Suspended or running with an id
bool Thread::start(ThreadRoutine func, void *arg, uint stacksz, ThreadGroup *tg,
    bool suspend) {
    ThreadGroup *g = ThreadGroup::resolve(tg);
    Locker lkr(lck);
    // a stopped Thread keeps hdl until its OS thread exits
    auto busy = [this] {
	return (getState() != Terminated && getState() != Init) || hdl;
    };

    if (busy())
	return false;
    if (group) {			// restart: leave the old group first
	ThreadGroup *old = group;

	lkr.unlock();
	old->remove(*this);
	lkr.lock();
	if (busy())
	    return false;
    }
    group = g;
    argument = arg;
    main = func;
    stacksize = stacksz;
    if (suspend)
	setState(Suspended);
    else if (!launch(lkr))
	return false;
    ThreadGroup::add(*this, g);
    return true;
}

// create the OS thread
bool Thread::launch(Locker &lkr) {
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

// onStop() runs unlocked so overrides may call back into the Thread
bool Thread::stop(void) {
    if (getState() == Terminated)
	return true;
    onStop();

    Locker lkr(lck);
    ThreadState s = getState();

    if (s != Terminated) {
	setState(Terminated);
	if (s == Suspended) {		// no thread exists to report exit
	    group->notify(*this);
	    cv.broadcast();
	}
    }
    return true;
}

// wait for thread to exit. Wrapped threads have no id and are joined by one
// waiter at a time while others wait for it to finish
bool Thread::wait(ulong timeout) {
    Locker lkr(lck);
    msec_t end;
    ulong left = timeout;

    if (!hdl || getState() == Init || getState() == Suspended)
	return true;
    if (!timeout || this == current())
	return false;
    if (getId() == NOID &&
#ifdef _WIN32
	GetThreadId(hdl) == GetCurrentThreadId())
#else
	pthread_equal(hdl, pthread_self()))
#endif
	return false;
    end = timeout == INFINITE ? 0 : mticks() + timeout;
    do {
	if (getId() != NOID || joining) {
	    if (!cv.wait(left) && hdl)
		return false;
	    if (!hdl)
		return true;
	    if (timeout != INFINITE) {
		const msec_t now = mticks();

		if (now >= end)
		    return false;
		left = (ulong)(end - now);
	    }
	    continue;
	}

	thread_hdl_t h = hdl;
	bool ret;

	joining = true;
	lkr.unlock();
#ifdef _WIN32
	ret = WaitForSingleObject(h, left) == WAIT_OBJECT_0;
#elif defined(__linux__)
	if (left == INFINITE) {
	    ret = pthread_join(h, nullptr) == 0;
	} else {
	    timespec ts;

	    clock_gettime(CLOCK_REALTIME, &ts);
	    time_adjust_msec(&ts, left);
	    ret = pthread_timedjoin_np(h, nullptr, &ts) == 0;
	}
#else
	// other pthreads do not support a timeout
	ret = left == INFINITE && pthread_join(h, nullptr) == 0;
#endif
	lkr.lock();
	joining = false;
	cv.broadcast();
	if (!ret)
	    return false;
	setState(Terminated);		// a joined pthread cannot be joined again
	hdl = 0;
	return true;
    } while (true);
}

ThreadGroup::~ThreadGroup() {
    wait(INFINITE, true);
    waitForMain(INFINITE);
}

ThreadGroup *ThreadGroup::add(Thread &thread, ThreadGroup *tg) {
    tg = resolve(tg);
    if (&thread != &tg->master) {
	tg->cvlck.lock();
	tg->threads.insert(&thread);
	tg->cvlck.unlock();
    }
    return tg;
}

ThreadGroup *ThreadGroup::resolve(ThreadGroup *tg) {
    return tg ? tg : curgroup ? curgroup : &MainThreadGroup;
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
    master.priority(pri);
    control([pri](Thread &thread) { thread.priority(pri); });
}

void ThreadGroup::remove(Thread &thread) {
    Locker lkr(cvlck);

    while (pinned == &thread)
	cv.wait();
    threads.erase(&thread);
}

bool ThreadGroup::start(uint stacksz, bool suspend) {
    return master.start(init, this, stacksz, this, suspend);
}

void ThreadGroup::stop(void) {
    const Thread *self = Thread::current();

    onStop();
    control([self](Thread &thread) {
	if (&thread != self)
	    thread.stop();
    });
}

// a timed wait also bounds joining stopped wrapped threads
Thread *ThreadGroup::wait(ulong msec, bool all) {
    const Thread *self = Thread::current();
    Locker lkr(cvlck);
    msec_t end = 0;
    // remaining msec with the deadline set at the first need to block
    auto left = [&end, msec] {
	if (!msec || msec == INFINITE)
	    return msec;

	const msec_t now = mticks();

	if (!end)
	    end = now + msec;
	return now < end ? (ulong)(end - now) : 0UL;
    };

    do {
	Thread *batch[64];
	uint count = 0;
	bool running = false;

	for (auto it = threads.begin(); it != threads.end(); ) {
	    Thread *thread = *it;

	    const ThreadState state = thread->getState();
	    const bool hasid = thread->getId() != Thread::NOID;

	    // stop() marks a live thread terminated so also require it exited
	    if (state == Terminated && !hasid && thread != pinned) {
		it = threads.erase(it);
		batch[count++] = thread;
		if (!all || count == 64)
		    break;
	    } else {
		if (thread == pinned || (hasid && thread != self))
		    running = true;
		++it;
	    }
	}
	if (count > 0) {
	    lkr.unlock();
	    for (uint i = 0; i < count; i++) {
		if (!batch[i]->wait(left()) && msec != INFINITE) {
		    lkr.lock();
		    threads.insert(batch + i, batch + count);
		    cv.broadcast();
		    return nullptr;
		}
		batch[i]->group = nullptr;
	    }
	    if (!all)
		return batch[0];
	    lkr.lock();
	    continue;
	}
	if (!running || !msec || !cv.wait(left()))
	    break;
    } while (true);
    return nullptr;
}
