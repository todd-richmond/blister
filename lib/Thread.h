/*
 * Copyright 2001-2010 Todd Richmond
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
#define atomic_lck(i)		InterlockedExchange(&i, 1)
#define atomic_or(i, j)		InterlockedOr(&i, j)
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

#ifdef __GNUC__

#if (defined(__arm__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 4)))

#define NO_ATOMIC_ADD
#define NO_ATOMIC_LOCK

#elif __GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 1)

#if __GNUC__ < 4
#include <bits/atomicity.h>
#else
#include <ext/atomicity.h>
#endif

typedef volatile _Atomic_word atomic_t;

#define __sync_fetch_and_add	__exchange_and_add

#define atomic_ref(i)		(__sync_fetch_and_add(&i, 1) + 1)
#define atomic_rel(i)		(__sync_fetch_and_add(&i, -1) - 1)

#if (defined(__i386__) || defined(__x86_64__)) && defined(__GNUC__)

inline void atomic_clr(atomic_t &lck) {
    atomic_t r;

    __asm__ __volatile__
	("xchgl %0, %1"
	: "=r" (r), "=m" (lck)
	: "0" (0), "m" (lck)
	: "memory");
}

inline atomic_t atomic_lck(atomic_t &lck) {
    atomic_t r;

    __asm__ __volatile__
	("xchgl %0, %1"
	: "=r" (r), "=m" (lck)
	: "0" (1), "m" (lck)
	: "memory");
    return r;
}

#else

#define NO_ATOMIC_LOCK

#endif

#else

typedef volatile int atomic_t;

#define atomic_ref(i)		__sync_add_and_fetch(&i, 1)
#define atomic_rel(i)		__sync_add_and_fetch(&i, -1)

#define atomic_add(i, j)	__sync_fetch_and_add(&i, j)
#define atomic_and(i, j)	__sync_fetch_and_and(&i, j)
#define atomic_bar()		__sync_synchronize()
// sync_lock_release() supposedly fails on some x64 procs
// #define atomic_clr(i)		__sync_lock_release(&i)
#define atomic_clr(i)		__sync_lock_test_and_set(&i, 0)
#define atomic_dec(i)		__sync_fetch_and_add(&i, -1)
#define atomic_exc(i, j)	__sync_fetch_exchange_not_implemented(&i, j)
#define atomic_inc(i)		__sync_fetch_and_add(&i, 1)
#define atomic_lck(i)		__sync_lock_test_and_set(&i, 1)
#define atomic_or(i, j)		__sync_fetch_and_or(&i, j)
#define atomic_xor(i, j)	__sync_fetch_and_xor(&i, j)

#endif

#else

#define NO_ATOMIC_ADD
#define NO_ATOMIC_LOCK

#endif

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
template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() =
    &C::unlock>
class LockerTemplate: nocopy {
public:
    LockerTemplate(C &lock, bool lockit = true):
	lck(lock), locked(lockit) { if (lockit) (lck.*LOCK)(); }
    ~LockerTemplate() { if (locked) (lck.*UNLOCK)(); }

    void lock(void) { if (!locked) { (lck.*LOCK)(); locked = true; } }
    void relock(void) {
	if (locked) {
	    (lck.*UNLOCK)();
	    THREAD_YIELD();
	} else {
	    locked = true;
	}
	(lck.*LOCK)();
    }
    void unlock(void) { if (locked) { locked = false; (lck.*UNLOCK)(); } }

private:
    C &lck;
    bool locked;
};

template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() = &C::unlock>
class FastLockerTemplate: nocopy {
public:
    FastLockerTemplate(C &lock): lck(lock) { (lck.*LOCK)(); }
    ~FastLockerTemplate() { (lck.*UNLOCK)(); }

    void relock(void) { (lck.*UNLOCK)(); THREAD_YIELD(); (lck.*LOCK)(); }

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

class Processor: nocopy {
public:
    static ullong affinity(void);
    static bool affinity(ullong mask);
    static uint count(void);
};

/* Thread local storage for simple types */
template<class C>
class ThreadLocal: nocopy {
public:
    ThreadLocal() { tls_init(key); }
    ~ThreadLocal() { tls_free(key); }

    C operator =(C c) const { set(c); return c;  }
    operator bool() const { return tls_get(key) != NULL; }

    C get(void) const { return (C)tls_get(key); }
    void set(const C c) const { tls_set(key, c); }

protected:
    tlskey_t key;
};

/* Thread local storage for classes with proper destruction when theads exit */
template<class C>
class ThreadLocalClass: nocopy {
public:
    ThreadLocalClass() { tls_init(key); }
    ~ThreadLocalClass() { tls_free(key); }

    C &operator *(void) const { return get(); }
    C *operator ->(void) const { return &get(); }
    void erase(void) { delete (C *)tls_get(key); tls_set(key, 0); }
    C &get(void) const {
	C *c = (C *)tls_get(key);

	if (!c) {
	    c = new C;
	    tls_set(key, c);
	}
	return *c;
    }
    void set(C *c) const { tls_set(key, c); }

protected:
    tlskey_t key;
};

/*
 * Thread synchronization classes
 *
 * SpinLock: fastest possible lock, but cannot wait for extended periods
 * Lock: fast lock that may spin before sleeping
 * Mutex: lock that does not spin before sleeping
 * RWLock: reader/writer lock
 * Condvar: condition variable around a Lock
 */

#define DEFAULT_SPINS 40

#ifndef NO_ATOMIC_LOCK

class SpinLock: nocopy {
public:
    SpinLock(uint cnt = DEFAULT_SPINS): lck(0) { spin(cnt); }

    void lock(void) {
	if (atomic_lck(lck)) {
	    uint spin = spins;

	    do {
		if (!spin--) {
		    THREAD_YIELD();
		    spin = spins;
		}
	    } while (atomic_lck(lck));
	}
    }
    void spin(uint cnt) { spins = Processor::count() == 1 ? 0 : cnt; }
    bool trylock(void) { return atomic_lck(lck) == 0; }
    void unlock(void) { atomic_clr(lck); }

private:
    atomic_t lck;
    uint spins;
};

#else

class SpinLock: nocopy {
public:
    SpinLock(uint cnt = DEFAULT_SPINS) {
	spin(cnt);
	pthread_spin_init(&lck, NULL);
    }
    ~SpinLock() { pthread_spin_destroy(&lck); }

    operator pthread_spinlock_t *() { return &lck; }

    void spin(uint cnt) { (void)cnt; }
    void lock(void) { pthread_spin_lock(&lck); }
    bool trylock(void) { return pthread_spin_trylock(&lck) == 0; }
    void unlock(void) { pthread_spin_unlock(&lck); }

protected:
    pthread_spinlock_t lck;
};

#endif

typedef LockerTemplate<SpinLock> SpinLocker;
typedef FastLockerTemplate<SpinLock> FastSpinLocker;

#ifdef _WIN32
#define msleep(msec)   Sleep(msec)

class Lock: nocopy {
public:
    Lock() { InitializeCriticalSection(&csec); }
    ~Lock() { DeleteCriticalSection(&csec); }

    void lock(void) { EnterCriticalSection(&csec); }
    void spin(uint cnt) { SetCriticalSectionSpinCount(&csec, cnt); }
    bool trylock(void) { return TryEnterCriticalSection(&csec) != 0; }
    void unlock(void) { LeaveCriticalSection(&csec); }

protected:
    CRITICAL_SECTION csec;
};

class Mutex: nocopy {
public:
    Mutex(const tchar *name = NULL);
    ~Mutex() { if (hdl) CloseHandle(hdl); }

    void lock(void) { WaitForSingleObject(hdl, INFINITE); }
    bool trylock(ulong msec = 0) {
	return WaitForSingleObject(hdl, msec) == WAIT_OBJECT_0;
    }
    void unlock(void) { ReleaseMutex(hdl); }

protected:
    HANDLE hdl;
};

class Event: nocopy {
public:
    Event(bool manual = false, bool set = false, const tchar *name = NULL):
	hdl(NULL) { open(manual, set, name); }
    ~Event() { close(); }

    operator HANDLE(void) const { return hdl; }
    HANDLE handle(void) const { return hdl; }

    bool close(void) {
	HANDLE h = hdl;

	hdl = NULL;
	return h ? CloseHandle(h) != 0 : true;
    }
    bool open(bool manual = false, bool set = false, const tchar *name = NULL) {
	close();
	return (hdl = CreateEvent(NULL, manual, set, name)) != NULL;
    }
    bool pulse(void) { return PulseEvent(hdl) != 0; }
    bool reset(void) { return ResetEvent(hdl) != 0; }
    bool set(void) { return SetEvent(hdl) != 0; }
    bool wait(ulong msec = INFINITE) {
	return WaitForSingleObject(hdl, msec) != WAIT_TIMEOUT;
    }

protected:
    HANDLE hdl;
};

class Semaphore: nocopy {
public:
    Semaphore(uint init = 0, uint max = LONG_MAX, const tchar *name = NULL):
	hdl(NULL) { open(init, max, name); }
    ~Semaphore() { close(); }

    operator HANDLE(void) const { return hdl; }
    HANDLE handle(void) const { return hdl; }

    bool close(void) {
	HANDLE h = hdl;

	hdl = NULL;
	return h ? CloseHandle(h) != 0 : true;
    }
    bool open(uint init = 0, uint max = LONG_MAX, const tchar *name = NULL) {
	close();
	return (hdl = CreateSemaphore(NULL, init, max, name)) != NULL;
    }
    bool release(uint cnt = 1) { return ReleaseSemaphore(hdl, cnt, NULL) != 0; }
    bool wait(ulong msec = INFINITE) {
	return WaitForSingleObject(hdl, msec) != WAIT_TIMEOUT;
    }

protected:
    HANDLE hdl;
};

class Condvar: nocopy {
public:
    Condvar(Lock &lock): lck(lock), pending(0), waiting(0) {}

    void broadcast(void) { set((uint)-1); }
    void set(uint count = 1) {
	uint cnt;

	olck.lock();
	cnt = waiting - pending;
	if (cnt) {
	    if (!pending) {
		ilck.lock();
		cnt = waiting - pending;
	    }
	    if (count < cnt)
		cnt = count;
	    pending += cnt;
	    sema4.release(cnt);
	}
	olck.unlock();
    }

    bool wait(ulong msec = INFINITE) {
	bool ret;

	ilck.lock();
	atomic_inc(waiting);
	ilck.unlock();
	lck.unlock();
	ret = sema4.wait(msec);
	olck.lock();
	if (!ret)
	    ret = sema4.wait(0);
	atomic_dec(waiting);
	if (ret && !--pending)
	    ilck.unlock();
	olck.unlock();
	lck.lock();
	return ret;
    }

private:
    SpinLock ilck, olck;
    Lock &lck;
    uint pending;
    Semaphore sema4;
    atomic_t waiting;
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
    bool wait(ulong msec = INFINITE) {
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

#endif

typedef LockerTemplate<Lock> Locker;
typedef FastLockerTemplate<Lock> FastLocker;

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
	    if (!msec || !cv.wait(msec)) {
		wwaiting--;
		return false;
	    }
	    wwaiting--;
	}
	writing = true;
	return true;
    }
    void wlock(void) {
	FastLocker lckr(lck);

	while (readers || writing) {
	    wwaiting++;
	    cv.wait(INFINITE);
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
#ifdef NO_ATOMIC_INC
class RefCount: nocopy {
public:
    RefCount(uint init = 1): cnt(init) {}

    operator bool(void) const { return referenced(); }
    bool referenced(void) const { FastSpinLocker lkr(lck); return cnt != 0; }

    void reference(void) { FastSpinLocker lkr(lck); cnt++; }
    bool release(void) { FastSpinLocker lkr(lck); return --cnt != 0; }

private:
    uint cnt;
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

    Lifo(): head(NULL), preset(false) {}

    bool empty(void) const { return head != NULL; }

    void broadcast(void) { set((uint)-1); }
    Lock &lock(void) { return lck; }
    uint set(uint count = 1) {
	FastLocker lkr(lck);

	if (head) {
	    do {
		head->cv.set();
		head = head->next;
		if (--count)
		    lkr.relock();
		else
		    break;
	    } while (head);
	} else if (!preset) {
	    preset = true;
	    count--;
	}
	return count;
    }
    bool wait(Waiting &w, ulong msec = INFINITE) {
	FastLocker lkr(lck);

	if (preset) {
	    preset = false;
	    return true;
	}
	w.next = head;
	head = &w;
	if (!w.cv.wait(msec)) {
	    for (Waiting **ww = &head; *ww; ww = &(*ww)->next) {
		if (*ww == &w) {
		    *ww = w.next;
		    return false;
		}
	    }
	}
	return true;
    }

private:
    Waiting *head;
    Lock lck;
    bool preset;
};

// Thread routines
typedef int (*ThreadRoutine)(void *userdata);
typedef bool (Thread::*ThreadControlRoutine)(void);

enum ThreadState { Init, Running, Suspended, Terminated };

// manage a thread performing some operation
class Thread: nocopy {
public:
    Thread(thread_t handle, ThreadGroup *tg = NULL, bool autoterm = false);
    Thread(void);
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

    bool priority(int pri = 0);			// -20 -> 20
    bool resume(void);
    bool start(uint stacksz = 0, ThreadGroup *tg = NULL, bool suspend = false,
	bool autoterm = false);
    bool start(ThreadRoutine main, void *data = NULL, uint stacksz = 0,
	ThreadGroup *tg = NULL, bool suspend = false, bool autoterm = false);
    bool stop(void);
    bool suspend(void);
    bool terminate(void);
    bool wait(ulong timeout = INFINITE);

protected:
    void end(int ret = 0);
    virtual int onStart(void) { return -1; }
    virtual void onStop(void) {}

private:
    mutable Lock lck;
    Condvar cv;
    bool autoterm;
    void *data;
    ThreadGroup *group;
    thread_t hdl, id;
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
    const Thread &getMainThread(void) const { return master; }
    size_t size(void) const { return threads.size(); }
    
    bool operator ==(const ThreadGroup &t) const { return id == t.id; }
    bool operator !=(const ThreadGroup &t) const { return id != t.id; }
    
    void priority(int pri = 0);
    void remove(Thread &thread);
    void resume(void) { onResume(); control(Running, &Thread::resume); }
    bool start(uint stacksz = 0, bool suspend = false, bool autoterm = false);
    void stop(void) { onStop(); control(Terminated, &Thread::stop); }
    void suspend(void) { onSuspend(); control(Suspended, &Thread::suspend); }
    void terminate(void) { control(Terminated, &Thread::terminate); }
    Thread *wait(ulong msec = INFINITE, bool all = false, bool main = false);
    void waitForMain(ulong msec = INFINITE) { wait(msec, false, true); }
    
    static ThreadGroup *add(Thread &thread, ThreadGroup *tg = NULL);
    
protected:
    void control(ThreadState, ThreadControlRoutine);
    void notify(const Thread &thread);
    virtual void onResume(void) {}
    virtual int onStart(void) { return -1; }
    virtual void onStop(void) {}
    virtual void onSuspend(void) {}
    
private:
    Lock lock;
    Condvar cv;
    bool autoterm;
    thread_t id;
    volatile ThreadState state;
    set<Thread *> threads;
    Thread master;
    static Lock grouplck;
    static set<ThreadGroup *> groups;
    static ulong nextId;

    static int init(void *thisp);
    friend class Thread;
};

#endif // Thread_h
