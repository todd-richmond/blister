#ifndef Thread_h
#define Thread_h

#include <set>

#ifdef _WIN32
#include <process.h>
#include <windows.h>

#define THREAD_EQUAL(x, y) (x == y)
#define THREAD_FUNC uint __stdcall
#define THREAD_HDL() GetCurrentThread()
#define THREAD_ID() (thread_t)GetCurrentThreadId()

typedef HANDLE thread_t;
#else
#if __GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 2)
#include <ext/atomicity.h>
#else
#include <bits/atomicity.h>
#endif
#include <dlfcn.h>
#include <pthread.h>

#define INFINITE (ulong)-1
#define THREAD_EQUAL(x, y) pthread_equal(x, y)
#define THREAD_FUNC void *
#define THREAD_HDL() pthread_self()
#define THREAD_ID() pthread_self()

typedef pthread_t thread_t;
#endif

#define THREAD_SELF() THREAD_ID()
#define THREAD_ISSELF(x) (x && THREAD_EQUAL(x, THREAD_SELF()))

class Thread;
class ThreadGroup;

template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() = &C::unlock>
class LockerTemplate: nocopy {
public:
    LockerTemplate(C &lock, bool lockit = true):
	lck(lock), locked(lockit) { if (lockit) (lck.*LOCK)(); }
    ~LockerTemplate() { if (locked) (lck.*UNLOCK)(); }

    void lock(void) { if (!locked) { (lck.*LOCK)(); locked = true; } }
    void unlock(void) { if (locked) { (lck.*UNLOCK)(); locked = false; } }

private:
    C &lck;
    bool locked;
};

template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() = &C::unlock>
class FastLockerTemplate: nocopy {
public:
    FastLockerTemplate(C &lock): lck(lock) { (lck.*LOCK)(); }
    ~FastLockerTemplate() { (lck.*UNLOCK)(); }

private:
    C &lck;
};

class DLLibrary: nocopy {
public:
    DLLibrary(const tchar *dll = NULL): hdl(0) { open(dll); }
    ~DLLibrary() { close(); }

    operator void *(void) const { return hdl; }
    bool operator !(void) const { return hdl == NULL; }

    const tstring &name(void) const { return file; }
    bool open(const tchar *dll);
    const tstring &error() const { return err; }
    bool close(void);
    void *get(const tchar *symbol) const;

private:
    void *hdl;
    tstring err;
    tstring file;
};

#ifdef _WIN32
#define msleep(msec)   Sleep(msec)

class Refcount {
 public:
    Refcount(int value = 1): count(value) {}
    void addref(void) { InterlockedIncrement(&count); }
    bool release(void) { return InterlockedDecrement(&count) == 0; }
    bool is_zero() { return count == 0; }

private:
    long count;
};

template<class C>
class TLS: nocopy {
public:
    TLS() { key = TlsAlloc(); }
    ~TLS() { TlsFree(key); }

    C *data(void) const { return (C *)TlsGetValue(key); }
    C *get(void) const {
	C *c = data();
	if (!c) {
	    c = new C;
	    set(c);
	}
	return c;
    }
    void set(const C *data) const { TlsSetValue(key, (void *)data); }

private:
    uint key;
};

class SpinLock: nocopy {
public:
    SpinLock(): lck(0), spins(50) {}

    uint spin(uint cnt) { return spins = cnt; }
    void lock(void) {
	if (!trylock()) {
	    uint spin = 1;

	    do {
		if (spin++ % spins == 0)
		    Sleep(0);
	    } while (!trylock());
	}
    }
    bool trylock(void) { return InterlockedExchange(&lck, 1) == 0; }
    void unlock(void) { InterlockedExchange(&lck, 0); }

private:
    long lck;
    uint spins;
};

class Lock: nocopy {
public:
    typedef DWORD (WINAPI *SpinFunc)(CRITICAL_SECTION *, DWORD);
    typedef DWORD (WINAPI *TryFunc)(CRITICAL_SECTION *);

    Lock() { InitializeCriticalSection(&csec); }
    ~Lock() { DeleteCriticalSection(&csec); }

    uint spin(uint cnt) { return spinfunc ? spinfunc(&csec, cnt): 1; }
    void lock(void) { EnterCriticalSection(&csec); }
    bool trylock(void) { return tryfunc ? tryfunc(&csec) != 0 : false; }
    void unlock(void) { LeaveCriticalSection(&csec); }

private:
    CRITICAL_SECTION csec;
    static DLLibrary kernel32;
    static SpinFunc spinfunc;
    static TryFunc tryfunc;
};

class Mutex: nocopy {
public:
    Mutex(const tchar *name = NULL);
    ~Mutex() { if (hdl) ReleaseMutex(hdl); }

    virtual void lock(void) { WaitForSingleObject(hdl, INFINITE); }
    virtual bool trylock(ulong msec = 0)
	{ return WaitForSingleObject(hdl, msec) == WAIT_OBJECT_0; }
    virtual void unlock(void) { ReleaseMutex(hdl); }

private:
    HANDLE hdl;
};

class Event: nocopy {
public:
    Event(bool manual = false, bool set = false, const tchar *name = NULL):
	hdl(NULL) { open(manual, set, name); }
    ~Event() { if (hdl) CloseHandle(hdl); }

    operator HANDLE(void) const { return hdl; }

    virtual bool open(bool manual = false, bool set = false,
	const tchar *name = NULL) {
	close();
	return (hdl = CreateEvent(NULL, manual, set, name)) != NULL;
    }
    virtual bool clear(void) { PulseEvent(hdl); return ResetEvent(hdl) != 0; }
    virtual bool close(void) {
	HANDLE h = hdl;

	hdl = NULL;
	return h ? CloseHandle(h) != 0 : true;
    }
    virtual bool set(void) { return SetEvent(hdl) != 0; }
    virtual bool wait(ulong msec = INFINITE)
	{ return WaitForSingleObject(hdl, msec) != WAIT_TIMEOUT; }

protected:
    HANDLE hdl;
};

class Condvar: nocopy {
public:
    Condvar(Lock &lck): lock(lck), head(NULL), tail(NULL) {}
    ~Condvar() {}
    
    void broadcast(void) { set(0x7FFFFFFF); }
    void set(uint count = 1);
    bool wait(ulong msec = INFINITE, bool hipri = false);

private:
    class waiting {
    public:
	waiting *next;
	Event *evt;

	waiting(Condvar &cv, Event *event, bool hipri): evt(event) {
	    if (hipri) {
		next = (waiting *)cv.head;
		cv.head = this;
		if (!cv.tail)
		    cv.tail = this;
	    } else {
		next = NULL;
		if (cv.tail)
		    cv.tail = cv.tail->next = this;
		else
		    cv.head = cv.tail = this;
	    }
	}
    };

    friend waiting;
    Lock &lock;
    waiting *head, *tail;
    static TLS<Event> tls;
    friend Thread;
};

// Event wrapper that keeps count of sets
class CountedEvent: public Event {
public:
    CountedEvent(bool manual = false, const tchar *name = NULL, uint count = 0)
	{ open(manual, name, count); }
    ~CountedEvent() {}

    uint count(void) const { return cnt; }

    virtual bool open(bool manual = false, const tchar *name = NULL,
	uint count = 0) { cnt = count; return Event::open(manual, false, name); }
    virtual bool clear(void) {
	LockerTemplate<SpinLock> lkr(lock);

	cnt = 0;
	return Event::clear();
    }
    virtual bool close(void) { cnt = 0; return Event::close(); }
    virtual bool set(void) {
	LockerTemplate<SpinLock> lkr(lock);

	return ++cnt == 1 ? PulseEvent(hdl) != 0 : true;
    }
    virtual bool wait(ulong msec = INFINITE) {
	LockerTemplate<SpinLock> lkr(lock);

	if (cnt) {
	    cnt--;
	    return true;
	} else {
	    lkr.unlock();
	    if (WaitForSingleObject(hdl, msec) == WAIT_OBJECT_0) {
		lkr.lock();
		cnt--;
		return true;
	    }
	}
	return false;
    }

protected:
    SpinLock lock;
    uint cnt;
};

inline bool DLLibrary::open(const tchar *dll) {
    close();
    file = dll ? dll : T("self");
    hdl = dll ? LoadLibrary(dll) : GetModuleHandle(NULL);
    if (!hdl && dll && !tstrstr(file.c_str(), ".dll")) {
	file += ".dll";
	hdl = LoadLibrary(file.c_str());
    }
    return hdl != 0;
}

inline bool DLLibrary::close() {
    if (hdl && (HMODULE)hdl != GetModuleHandle(NULL))
	FreeLibrary((HMODULE)hdl);
    hdl = 0;
    return true;
}

inline void *DLLibrary::get(const tchar *symbol) const {
#ifdef _WIN32_WCE
    return GetProcAddress((HMODULE)hdl, symbol);
#else
    return GetProcAddress((HMODULE)hdl, tchartoa(symbol).c_str());
#endif
}

class Process {
public:
    Process(HANDLE hproc): hdl(hproc) {}
    Process(const Process &proc);
    ~Process() { if (hdl) CloseHandle(hdl); }

    static int argc;
    static tchar **argv;
    static tchar **envv;
    static Process self;

    operator HANDLE() const { return hdl; }
    bool mask(uint m) { return SetProcessAffinityMask(hdl, m) != 0; }
    static Process start(tchar * const *args, const int *fds = NULL);

private:
    HANDLE hdl;
};

#else

inline void msleep(ulong msec) {
    struct timespec ts;

    ts.tv_sec = msec / 1000;
    ts.tv_nsec = (msec % 1000) * 1000000;
    nanosleep(&ts, NULL);
}

class Refcount {
 public:
    Refcount(int value = 1): count(value) {}
    void addref(void) { __atomic_add(&count, 1); }
    bool release(void) { return __exchange_and_add(&count, -1) == 1; }
    bool is_zero() { return count == 0; }

 private:
    _Atomic_word count;
};

template<class C>
class TLS: nocopy {
public:
    TLS() { pthread_key_create(&key, NULL); }
    ~TLS() { pthread_key_delete(key); }

    C *data(void) const { return (C *)pthread_getspecific(key); }
    C *get(void) const {
	C *c = data();
	if (!c) {
	    c = new C;
	    set(c);
	}
	return c;
    }
    void set(const C *data) const { pthread_setspecific(key, data); }

private:
    pthread_key_t key;
};

class Lock: nocopy {
public:
    Lock() { pthread_mutex_init(&mtx, NULL); }
    ~Lock() { pthread_mutex_destroy(&mtx); }

    operator pthread_mutex_t *() { return &mtx; }
    uint spin(uint cnt) { return 1; }
    void lock(void) { pthread_mutex_lock(&mtx); }
    bool trylock(void) { return pthread_mutex_trylock(&mtx); }
    void unlock(void) { pthread_mutex_unlock(&mtx); }

private:
    pthread_mutex_t mtx;
};

#if (defined(__i386__) || defined(__x86_64__)) && defined(__GNUC__)

class SpinLock: nocopy {
public:
    SpinLock(): lck(0), spins(50) {}

    uint spin(uint cnt) { return spins = cnt; }
    void lock(void) {
	if (!trylock()) {
	    uint spin = 1;

	    do {
		if (spin++ % spins == 0)
		    sched_yield();
	    } while (!trylock());
	}
    }
    bool trylock(void) {
	int r;
	
	__asm__ __volatile__
	    ("xchgl %0, %1"
	    : "=r" (r), "=m" (lck)
	    : "0" (1), "m" (lck)
	    : "memory");
	return r == 0;
    }
    void unlock(void) {
	int r;

	__asm__ __volatile__
	    ("xchgl %0, %1"
	    : "=r" (r), "=m" (lck)
	    : "0" (0), "m" (lck)
	    : "memory");
    }

private:
    volatile int lck;
    uint spins;
};
#else
typedef Lock SpinLock;
#endif

typedef Lock Mutex;

class Condvar: nocopy {
public:
    Condvar(Lock &lck): lock(lck) { pthread_cond_init(&cv, NULL); }
    ~Condvar() { pthread_cond_destroy(&cv); }
    
    void set(uint count = 1) { while (count--) pthread_cond_signal(&cv); }
    void broadcast(void) { pthread_cond_broadcast(&cv); }
    bool wait(ulong msec = INFINITE, bool hipri = false) {
    	if (msec == INFINITE) {
	    return pthread_cond_wait(&cv, lock) == 0;
	} else {
	    struct timespec ts;
	    struct timeval tv;

	    gettimeofday(&tv, NULL);
	    ts.tv_sec = tv.tv_sec + msec / 1000;
	    ts.tv_nsec = (tv.tv_usec + (msec % 1000)) * 1000;
	    return pthread_cond_timedwait(&cv, lock, &ts) == 0;
	}
    }

private:
    Lock &lock;
    pthread_cond_t cv;
};

inline bool DLLibrary::open(const tchar *dll) {
    close();
    file = dll ? dll : "self";
    hdl = dlopen(dll, RTLD_LAZY | RTLD_GLOBAL);
    if (!hdl && dll && file.find(".so") == file.npos) {
	file += ".so";
	hdl = dlopen(file.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
    if (!hdl && dll && file.find("lib") == file.npos) {
	file = "lib/" + file;
	hdl = dlopen(file.c_str(), RTLD_LAZY | RTLD_GLOBAL);
    }
    if (!hdl) err = dlerror();
    return hdl != 0;
}

inline bool DLLibrary::close() {
    if (hdl)
	dlclose(hdl);
    hdl = 0;
    return true;
}

inline void *DLLibrary::get(const tchar *symbol) const {
    return dlsym(hdl, symbol);
}
#endif

class RWLock: nocopy {
public:
    RWLock(): cv(lck), readers(0), writer(0), wwaiting(0) {}
    ~RWLock() {}
    
    void rlock(void);
    void runlock(void);
    void wlock(void);
    void wunlock(void);

private:
    Lock lck;
    Condvar cv;
    volatile long readers;
    volatile long writer;
    volatile long wwaiting;
};

inline void RWLock::rlock(void) {
    lck.lock();
    while (writer || wwaiting)
	cv.wait();
    readers++;
    lck.unlock();
}

inline void RWLock::runlock(void) {
    lck.lock();
    readers--;
    if (!readers && wwaiting)
	cv.set();
    lck.unlock();
}

inline void RWLock::wlock(void) {
    lck.lock();
    while (readers || writer) {
	wwaiting++;
	cv.wait(INFINITE, true);
	wwaiting--;
    }
    writer = 1;
    lck.unlock();
}

inline void RWLock::wunlock(void) {
    lck.lock();
    writer = 0;
    if (wwaiting)
	cv.set();
    else
	cv.broadcast();
    lck.unlock();
}

typedef LockerTemplate<Lock> Locker;
typedef LockerTemplate<SpinLock> SpinLocker;
typedef LockerTemplate<RWLock, &RWLock::rlock, &RWLock::runlock> RLocker;
typedef LockerTemplate<RWLock, &RWLock::wlock, &RWLock::wunlock> WLocker;
typedef FastLockerTemplate<Lock> FastLocker;
typedef FastLockerTemplate<SpinLock> FastSpinLocker;
typedef FastLockerTemplate<RWLock, &RWLock::rlock, &RWLock::runlock> FastRLocker;
typedef FastLockerTemplate<RWLock, &RWLock::wlock, &RWLock::wunlock> FastWLocker;

template<class C>
class TSNumber: nocopy {
public:
    TSNumber(C init = 0) { c = init; }

    operator C() const { TSLocker lkr(lck); return c; }
    template<class N> bool operator ==(N n) const { TSLocker lkr(lck); return c == n; }
    template<class N> bool operator !=(N n) const { TSLocker lkr(lck); return c != n; }
    C operator ++(void) { TSLocker lkr(lck); return ++c; }
    C operator ++(int) { TSLocker lkr(lck); return c++; }
    C operator --(void) { TSLocker lkr(lck); return --c; }
    C operator --(int) { TSLocker lkr(lck); return c--; }
    template<class N> C operator =(N n) { TSLocker lkr(lck); return c = n; }
    template<class N> C operator =(const TSNumber<N> n) { TSLocker lkr(lck); return c = n; }
    template<class N> C operator +=(N n) { TSLocker lkr(lck); return c += n; }
    template<class N> C operator -=(N n) { TSLocker lkr(lck); return c -= n; }
    template<class N> C operator *=(N n) { TSLocker lkr(lck); return c *= n; }
    template<class N> C operator /=(N n) { TSLocker lkr(lck); return c /= n; }
    template<class N> C operator &=(N n) { TSLocker lkr(lck); return c &= n; }
    template<class N> C operator |=(N n) { TSLocker lkr(lck); return c |= n; }
    template<class N> C operator %=(N n) { TSLocker lkr(lck); return c %= n; }
    template<class N> C operator ^=(N n) { TSLocker lkr(lck); return c ^= n; }
    template<class N> C operator >>=(N n) { TSLocker lkr(lck); return c >>= n; }
    template<class N> C operator <<=(N n) { TSLocker lkr(lck); return c <<= n; }

    // dangerous - do not operate on class directly if using these functions
    C get(void) const { return c; }
    template<class N> C set(N n) { return c = n; }
    void lock(void) { lck.lock(); }
    void unlock(void) { lck.unlock(); }

protected:
    C c;
    mutable SpinLock lck;
    typedef FastSpinLocker TSLocker;

    C *operator &();			// not allowed
};

// Last-in-first-out queue useful for thread pools
class Lifo {
public:
    class Waiting {
    public:
	Condvar cv;
	Waiting *next;

	Waiting(Lifo &lifo): cv(lifo.lock()), next(NULL) {}
    };

    Lifo(Lock &l): lck(l), head(NULL), sz(0) {}

    bool empty(void) const { return sz == 0; }
    uint size(void) const { return sz; }

    Lock &lock(void) { return lck; }
    void broadcast(void) { set((uint)-1); }
    void set(uint count = 1) {
	uint u = 0;

	while (head && count--) {
	    sz--;
	    head->cv.set();
	    head = head->next;
	    if (count > 1 && u++ % 2) {
		lck.unlock();
		lck.lock();
	    }
	}
    }
    bool wait(Waiting &w, ulong msec = INFINITE) {
	w.next = head;
	head = &w;
	sz++;
	if (!w.cv.wait(msec)) {
	    for (Waiting **ww = &head; *ww; ww = &(*ww)->next) {
		if (*ww == &w) {
		    *ww = w.next;
		    sz--;
		    return false;
		}
	    }
	}
	return true;
    }

private:
    Lock &lck;
    Waiting *head;
    uint sz;
};

class Processor: nocopy {
public:
    static uint count(void);
    static void prefer(uint cput);
};

// Thread routines
typedef int (*ThreadRoutine)(void *userdata);
typedef bool (Thread::*ThreadControlRoutine)(void);

enum ThreadState { Init, Running, Suspended, Terminated };

// manage a thread performing some operation
class Thread: nocopy {
public:
    Thread(thread_t handle = 0, ThreadGroup *tg = NULL);
    virtual ~Thread();
    
    static Thread MainThread;

    int exitStatus(void) const { return retval; }
    ThreadState getState(void) const { Locker lkr(lck); return state; }
    thread_t getId(void) const { return id; }
    ThreadGroup *getThreadGroup(void) const { return group; }
    thread_t handle(void) const { return hdl; }
    bool running(void) const { return getState() == Running; }
    bool suspended(void) const { return getState() == Suspended; }
    bool terminated(void) const { return getState() == Terminated; }

    operator thread_t(void) const { return hdl; }
    bool operator ==(const Thread &t) const { return THREAD_EQUAL(id, t.id); }
    bool operator !=(const Thread &t) const { return !operator ==(t); }

    bool start(uint stacksz = 0, bool suspend = false, bool autoterm = false,
	ThreadGroup *tg = NULL);
    bool start(ThreadRoutine main, void *data = NULL, uint stacksz = 0,
	bool suspend = false, bool autoterm = false, ThreadGroup *tg = NULL);
    bool stop(void);
    bool resume(void);
    bool suspend(void);
    bool terminate(void);
    bool wait(ulong timeout = INFINITE);
    bool priority(int pri = 0) { return hdl && priority(hdl, pri); }
    static bool priority(thread_t hdl, int pri);    // -20 -> 20

protected:
    // never used but not pure virtual to allow Thread instantiation
    virtual int onStart(void) { return -1; }
    virtual void onStop(void) {}
    void end(int ret = 0);

private:
    thread_t hdl, id;
    volatile ThreadState state;
    bool autoterm;
    int retval;
    ThreadGroup *group;
    ThreadRoutine main;
    void *data;
    mutable Lock lck;
    Condvar cv;
    
    void clear(bool self = true);
    static THREAD_FUNC threadInit(void *thisp);
    static int init(void *thisp);

    friend class ThreadGroup;
};

// manage a group of one or more, possibly dissimilar threads
typedef void (ThreadGroup::*ThreadGroupControlRoutine)(bool);

class ThreadGroup: nocopy {
public:
    ThreadGroup(bool autoterm = true);
    virtual ~ThreadGroup();
    
    ThreadState getState(void) const { return state; }
    thread_t getId(void) const { return id; }
    thread_t getMainId(void) const { return mainThread.getId(); }
    
    bool operator ==(const ThreadGroup &t) const { return id == t.id; }
    bool operator !=(const ThreadGroup &t) const { return id != t.id; }
    
    bool start(uint stacksz = 0, bool autoterm = true);
    void stop(void) { onStop(); control(Terminated, &Thread::stop); }
    void resume(void) { onResume(); control(Running, &Thread::resume); }
    void suspend(void) { onSuspend(); control(Suspended, &Thread::suspend); }
    void terminate(void) { control(Terminated, &Thread::terminate); }
    Thread *wait(ulong msec = INFINITE, bool all = false, bool main = false);
    void waitForMain(ulong msec = INFINITE) { wait(msec, false, true); }
    void priority(int pri = 0);
    void remove(Thread *thread);
    
    static ThreadGroup MainThreadGroup;
    static ThreadGroup *add(Thread *thread, ThreadGroup *tg);
    
protected:
    void control(ThreadState, ThreadControlRoutine);
    void notify(const Thread *thread) {
	Locker lck(lock);
	if (thread == &mainThread)
	    cv.broadcast();
	else
	    cv.set();
    }
    virtual void onResume(void) {}
    virtual int onStart(void) { return -1; }
    virtual void onStop(void) {}
    virtual void onSuspend(void) {}
    
private:
    bool autoterm;
    thread_t id;
    Lock lock;
    Condvar cv;
    volatile ThreadState state;
    set<Thread *> threads;
    Thread mainThread;
    static Lock grouplck;
    static ulong nextId;
    static set<ThreadGroup *> groups;

    static int init(void *data);
    friend class Thread;
};

#endif // Thread_h
