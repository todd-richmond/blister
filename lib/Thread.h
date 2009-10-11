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

#ifndef Thread_h
#define Thread_h

#include <set>

#ifdef _WIN32
#include <process.h>
#include <windows.h>

typedef HANDLE thread_t;

#define THREAD_EQUAL(x, y)	(x == y)
#define THREAD_FUNC		uint __stdcall
#define THREAD_HDL()		GetCurrentThread()
#define THREAD_ID()		(thread_t)GetCurrentThreadId()
#define THREAD_YIELD()		Sleep(0)

typedef volatile long atomic_t;

// atomic functions that return updated value
#define atomic_ref(i)		InterlockedIncrement(&i)
#define atomic_rel(i)		InterlockedDecrement(&i)

// atomic functions that return previous value
#define atomic_add(i, j)	InterlockedExchangeAdd(&i, j)
#define atomic_and(i, j)	InterlockedAnd(&i, j)
#define atomic_bar()		_ReadWriteBarrier()
#define atomic_clr(i)		InterlockedExchange(&i, 0)
#define atomic_dec(i)		InterlockedExchangeAdd(&i, -1)
#define atomic_exc(i, j)	InterlockedExchange(&i, j)
#define atomic_inc(i)		InterlockedExchangeAdd(&i, 1)
#define atomic_or(i, j)		InterlockedOr(&i, j)
#define atomic_set(i)		InterlockedExchange(&i, 1)
#define atomic_xor(i, j)	InterlockedXor(&i, j)

typedef uint tlskey_t;

#define tls_init(k)		k = TlsAlloc()
#define tls_free(k)		TlsFree(k)
#define tls_get(k)		TlsGetValue(k)
#define tls_set(k, v)		TlsSetValue(key, (void *)v)

#else

#include <dlfcn.h>
#include <pthread.h>

typedef pthread_t thread_t;

#define INFINITE		(ulong)-1
#define THREAD_EQUAL(x, y)	pthread_equal(x, y)
#define THREAD_FUNC		void *
#define THREAD_HDL()		pthread_self()
#define THREAD_ID()		pthread_self()
#define THREAD_YIELD()		sched_yield()

#if defined(__arm__)

#define NO_ATOMIC_OPS

#elif __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)
#if __GNUC__ < 4
#include <bits/atomicity.h>
#else
#include <ext/atomicity.h>
#endif

typedef _Atomic_word atomic_t;

#define __sync_fetch_and_add(i, j)	__exchange_and_add(i, j)

#define atomic_ref(i)		(__sync_fetch_and_add(&i, 1) + 1)
#define atomic_rel(i)		(__sync_fetch_and_add(&i, -1) - 1)

#else

typedef volatile int atomic_t;

#define atomic_ref(i)		__sync_add_and_fetch(&i, 1)
#define atomic_rel(i)		__sync_add_and_fetch(&i, -1)

#endif

#define atomic_add(i, j)	__sync_fetch_and_add(&i, j)
#define atomic_and(i, j)	__sync_fetch_and_and(&i, j)
#define atomic_bar()		__sync_synchronize()
#define atomic_clr(i)		__sync_lock_release(&i)
#define atomic_dec(i)		__sync_fetch_and_add(&i, -1)
#define atomic_exc(i, j)	__sync_fetch_exchange_not_implemented(&i, j)
#define atomic_inc(i)		__sync_fetch_and_add(&i, 1)
#define atomic_or(i, j)		__sync_fetch_and_or(&i, j)
#define atomic_set(i)		__sync_lock_test_and_set(&i, 1)
#define atomic_xor(i, j)	__sync_fetch_and_xor(&i, j)

typedef pthread_key_t tlskey_t;

#define tls_init(k)		pthread_key_create(&key, NULL)
#define tls_free(k)		pthread_key_delete(key)
#define tls_get(k)		pthread_getspecific(key)
#define tls_set(k, v)		pthread_setspecific(key, v)

#endif

#define THREAD_SELF()		THREAD_ID()
#define THREAD_ISSELF(x)	(x && THREAD_EQUAL(x, THREAD_SELF()))

#define atomic_get(i)		atomic_add(i, 0)

class Thread;
class ThreadGroup;

/* Locking templates that unlock upon destruction */
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

/*
 * The DLLibrary class loads shared libraries and dynamically fetches function
 * pointers. Do not specify file extensions in the constructor
 */
class DLLibrary: nocopy {
public:
    DLLibrary(const tchar *dll = NULL): hdl(0) { open(dll); }
    ~DLLibrary() { close(); }

    operator void *(void) const { return hdl; }
    bool operator !(void) const { return hdl == NULL; }

    const tstring &error() const { return err; }
    const tstring &name(void) const { return file; }
    bool close(void);
    void *get(const tchar *symbol) const;
    bool open(const tchar *dll);

private:
    void *hdl;
    tstring err;
    tstring file;
};

/* Thread local storage for simple types */
template<class C>
class ThreadLocal: nocopy {
public:
    ThreadLocal() { tls_init(key); }
    ~ThreadLocal() { tls_free(key); }

    C operator =(C c) const { set(c); return c;  }
    bool exists(void) const { return tls_get(key) != NULL; }

    C get(void) const {
	C c = data();

	if (!c)
	    set(c = 0);
	return c;
    }
    void set(const C data) const { tls_set(key, data); }

protected:
    tlskey_t key;

    C data(void) const { return (C)tls_get(key); }
};

/* Thread local storage for classes with proper destruction when theads exit */
template<class C>
class ThreadLocalClass: public ThreadLocal<C *> {
public:
    ThreadLocalClass() {}

    C &operator *(void) const { return get(); }
    C *operator ->(void) const { return &get(); }
    C &get(void) const {
	C *c = ThreadLocal<C *>::data();

	if (!c)
	    ThreadLocal<C *>::set(c = new C);
	return *c;
    }
};

/*
 * Thread synchronization classes
 *
 * SpinLock: fastest possible lock, but cannot wait for extended periods
 * Lock: fast lock that may spin before sleeping
 * Mutex: lock that does not spin before sleeping
 * RWLock: reader/writer lock
 * CondVar: condition variable around a Lock
 */

#ifdef _WIN32
#define msleep(msec)   Sleep(msec)

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

class Lock: nocopy {
public:
    Lock() { InitializeCriticalSection(&csec); }
    ~Lock() { DeleteCriticalSection(&csec); }

    void lock(void) { EnterCriticalSection(&csec); }
    void unlock(void) { LeaveCriticalSection(&csec); }

protected:
    CRITICAL_SECTION csec;
};

class Mutex: nocopy {
public:
    Mutex(const tchar *name = NULL);
    ~Mutex() { if (hdl) ReleaseMutex(hdl); }

    void lock(void) { WaitForSingleObject(hdl, INFINITE); }
    bool trylock(ulong msec = 0)
	{ return WaitForSingleObject(hdl, msec) == WAIT_OBJECT_0; }
    void unlock(void) { ReleaseMutex(hdl); }

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
	Event &evt;
	waiting *next;

	waiting(Condvar &cv, Event &event, bool hipri): evt(event) {
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
    static ThreadLocalClass<Event> tls;
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
	LockerTemplate<Lock> lkr(lock);

	cnt = 0;
	return Event::clear();
    }
    virtual bool close(void) { cnt = 0; return Event::close(); }
    virtual bool set(void) {
	LockerTemplate<Lock> lkr(lock);

	return ++cnt == 1 ? PulseEvent(hdl) != 0 : true;
    }
    virtual bool wait(ulong msec = INFINITE) {
	LockerTemplate<Lock> lkr(lock);

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
    Lock lock;
    uint cnt;
};

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

inline bool DLLibrary::open(const tchar *dll) {
    close();
    file = dll ? dll : T("self");
    hdl = dll ? LoadLibrary(dll) : GetModuleHandle(NULL);
    if (!hdl && dll && !tstrstr(file.c_str(), T(".dll"))) {
	file += T(".dll");
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
    return GetProcAddress((HMODULE)hdl, tchartoachar(symbol));
#endif
}

#else

inline void msleep(ulong msec) {
    struct timespec ts = { 
	ts.tv_sec = msec / 1000, ts.tv_nsec = (msec % 1000) * 1000000
    };

    nanosleep(&ts, NULL);
}

class Lock: nocopy {
public:
    Lock() { pthread_mutex_init(&mtx, NULL); }
    ~Lock() { pthread_mutex_destroy(&mtx); }

    operator pthread_mutex_t *() { return &mtx; }

    void lock(void) { pthread_mutex_lock(&mtx); }
    bool trylock(void) { return pthread_mutex_trylock(&mtx) == 0; }
    void unlock(void) { pthread_mutex_unlock(&mtx); }

protected:
    pthread_mutex_t mtx;
};

typedef Lock Mutex;

class Condvar: nocopy {
public:
    Condvar(Lock &lck): lock(lck) { pthread_cond_init(&cv, NULL); }
    ~Condvar() { pthread_cond_destroy(&cv); }
    
    void broadcast(void) { pthread_cond_broadcast(&cv); }
    void set(uint count = 1) { while (count--) pthread_cond_signal(&cv); }
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

protected:
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

typedef LockerTemplate<Lock> Locker;
typedef FastLockerTemplate<Lock> FastLocker;

#if (defined(__i386__) || defined(__x86_64__)) && defined(__GNUC__)

class SpinLock: nocopy {
public:
    SpinLock(): lck(0), spins(100) {}

    void lock(void) {
	if (!trylock()) {
	    uint spin = spins;

	    do {
		if (!spin--) {
		    THREAD_YIELD();
		    spin = spins;
		}
	    } while (!trylock());
	}
    }
    void spin(uint cnt) { spins = cnt; }
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

#elif defined(_WIN32) && 0  // slower than atomic ops

class SpinLock: nocopy {
public:
    SpinLock() { InitializeCriticalSection(&csec); }
    ~SpinLock() { DeleteCriticalSection(&csec); }

    void lock(void) { EnterCriticalSection(&csec); }
    void spin(uint cnt) { SetCriticalSectionSpinCount(&csec, cnt); }
    bool trylock(void) { return TryEnterCriticalSection(&csec) != 0; }
    void unlock(void) { LeaveCriticalSection(&csec); }

private:
    CRITICAL_SECTION csec;
};

#elif !defined(NO_ATOMIC_OPS)

class SpinLock: nocopy {
public:
    SpinLock(): lck(0), spins(100) {}

    void lock(void) {
	if (atomic_set(lck)) {
	    uint spin = spins;

	    do {
		if (!spin--) {
		    THREAD_YIELD();
		    spin = spins;
		}
	    } while (atomic_set(lck));
	}
    }
    void spin(uint cnt) { spins = cnt; }
    bool trylock(void) { return atomic_set(lck) == 0; }
    void unlock(void) { atomic_clr(lck); }

private:
    atomic_t lck;
    uint spins;
};

#elif defined(__arm__)

class SpinLock: nocopy {
public:
    SpinLock() { pthread_spin_init(&lck, NULL); }
    ~SpinLock() { pthread_spin_destroy(&lck); }

    operator pthread_spinlock_t *() { return &lck; }

    void lock(void) { pthread_spin_lock(&lck); }
    bool trylock(void) { return pthread_spin_trylock(&lck) == 0; }
    void unlock(void) { pthread_spin_unlock(&lck); }

protected:
    pthread_spinlock_t lck;
};

#else

#error no spinlock mechanism defined

#endif

typedef LockerTemplate<SpinLock> SpinLocker;
typedef FastLockerTemplate<SpinLock> FastSpinLocker;

class RWLock: nocopy {
public:
    RWLock(): cv(lck), readers(0), wwaiting(0), writing(false) {}

    void rlock(void) {
	FastLocker lckr(lck);

	while (writing || wwaiting) {
	    cv.wait();
	    if (writing || wwaiting)
		cv.set();
	}
	readers++;
    }
    void runlock(void) {
	FastLocker lckr(lck);

	if (!--readers && wwaiting)
	    cv.set();
    }
    bool tryrlock(ulong msec = 0) {
	FastLocker lckr(lck);

	if (writing || wwaiting) {
	    if (!msec || !cv.wait(msec))
		return false;
	    // can return early
	    if (writing || wwaiting)
		cv.set();
	}
	readers++;
	return true;
    }
    bool trywlock(ulong msec = 0) {
	FastLocker lckr(lck);

	if (readers || writing) {
	    wwaiting++;
	    if (!msec || !cv.wait(msec, true)) {
		wwaiting--;
		return false;
	    }
	    wwaiting--;
	}
	return writing = true;
    }
    void wlock(void) {
	FastLocker lckr(lck);

	while (readers || writing) {
	    wwaiting++;
	    cv.wait(INFINITE, true);
	    wwaiting--;
	}
	writing = true;
    }
    void wunlock(void) {
	FastLocker lckr(lck);

	writing = false;
	if (wwaiting)
	    cv.set();
	else
	    cv.broadcast();
    }

private:
    Lock lck;
    Condvar cv;
    volatile ulong readers, wwaiting;
    volatile bool writing;
};

typedef LockerTemplate<RWLock, &RWLock::rlock, &RWLock::runlock> RLocker;
typedef LockerTemplate<RWLock, &RWLock::wlock, &RWLock::wunlock> WLocker;
typedef FastLockerTemplate<RWLock, &RWLock::rlock, &RWLock::runlock> FastRLocker;
typedef FastLockerTemplate<RWLock, &RWLock::wlock, &RWLock::wunlock> FastWLocker;

/* Fast reference counter class */
#ifdef NO_ATOMIC_OPS
class RefCount: nocopy {
public:
    RefCount(uint init = 1): cnt(init) {}

    operator bool(void) const { return referenced(); }
    bool referenced(void) const { FastSpinLocker lkr(lck); return cnt != 0; }

    void reference(void) { FastSpinLocker lkr(lck); cnt++; }
    bool release(void) { FastSpinLocker lkr(lck); return --cnt != 0; }

private:
    atomic_t cnt;
    mutable SpinLock lck;
};

#else

class RefCount: nocopy {
public:
    RefCount(uint init = 1): cnt(init) {}

    operator bool(void) const { return referenced(); }
    bool referenced(void) const { return atomic_get(cnt) != 0; }

    void reference(void) { atomic_ref(cnt); }
    bool release(void) { return atomic_rel(cnt) != 0; }

private:
    mutable atomic_t cnt;
};
#endif

/* Thread safe # template */
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

/* Last-in-first-out queue useful for thread pools */
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

    bool priority(int pri = 0) { return hdl && priority(hdl, pri); }
    bool resume(void);
    bool start(uint stacksz = 0, bool suspend = false, bool autoterm = false,
	ThreadGroup *tg = NULL);
    bool start(ThreadRoutine main, void *data = NULL, uint stacksz = 0,
	bool suspend = false, bool autoterm = false, ThreadGroup *tg = NULL);
    bool stop(void);
    bool suspend(void);
    bool terminate(void);
    bool wait(ulong timeout = INFINITE);
    static bool priority(thread_t hdl, int pri);    // -20 -> 20

protected:
    void end(int ret = 0);
    // never used but not pure virtual to allow Thread instantiation
    virtual int onStart(void) { return -1; }
    virtual void onStop(void) {}

private:
    mutable Lock lck;
    Condvar cv;
    bool autoterm;
    void *data;
    thread_t hdl, id;
    ThreadGroup *group;
    ThreadRoutine main;
    int retval;
    volatile ThreadState state;
    
    void clear(bool self = true);
    static int init(void *thisp);
    static THREAD_FUNC threadInit(void *thisp);

    friend class ThreadGroup;
};

// manage a group of one or more, possibly dissimilar threads
typedef void (ThreadGroup::*ThreadGroupControlRoutine)(bool);

class ThreadGroup: nocopy {
public:
    ThreadGroup(bool autoterm = true);
    virtual ~ThreadGroup();

    static ThreadGroup MainThreadGroup;

    ThreadState getState(void) const { return state; }
    thread_t getId(void) const { return id; }
    thread_t getMainThread(void) const { return master; }
    size_t size(void) const { return threads.size(); }
    
    bool operator ==(const ThreadGroup &t) const { return id == t.id; }
    bool operator !=(const ThreadGroup &t) const { return id != t.id; }
    
    void priority(int pri = 0);
    void remove(Thread *thread);
    void resume(void) { onResume(); control(Running, &Thread::resume); }
    bool start(uint stacksz = 0, bool autoterm = true);
    void stop(void) { onStop(); control(Terminated, &Thread::stop); }
    void suspend(void) { onSuspend(); control(Suspended, &Thread::suspend); }
    void terminate(void) { control(Terminated, &Thread::terminate); }
    Thread *wait(ulong msec = INFINITE, bool all = false, bool main = false);
    void waitForMain(ulong msec = INFINITE) { wait(msec, false, true); }
    
    static ThreadGroup *add(Thread *thread, ThreadGroup *tg);
    
protected:
    thread_t id;
    Thread master;

    void control(ThreadState, ThreadControlRoutine);
    void notify(const Thread *thread) {
	lock.lock();
	if (thread == &master)
	    cv.broadcast();
	else
	    cv.set();
	lock.unlock();
    }
    virtual void onResume(void) {}
    virtual int onStart(void) { return -1; }
    virtual void onStop(void) {}
    virtual void onSuspend(void) {}
    
private:
    Lock lock;
    Condvar cv;
    bool autoterm;
    volatile ThreadState state;
    set<Thread *> threads;
    static Lock grouplck;
    static set<ThreadGroup *> groups;
    static ulong nextId;

    static int init(void *data);
    friend class Thread;
};

#endif // Thread_h

