/*
 * Copyright 2001-2022 Todd Richmond
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

#ifdef _WIN32
#include <process.h>
#include <windows.h>

typedef HANDLE thread_hdl_t;
typedef DWORD thread_id_t;

#define THREAD_EQUAL(x, y)	((x) == (y))
#define THREAD_FENCE()		MemoryBarrier()
#define THREAD_FUNC		uint __stdcall
#define THREAD_HDL()		GetCurrentThread()
#define THREAD_ID()		GetCurrentThreadId()
#define THREAD_BARRIER()	_ReadWriteBarrier()
#define THREAD_PAUSE()		YieldProcessor()
#define THREAD_YIELD()		if (!SwitchToThread()) Sleep(0)

typedef volatile LONG atomic_t;

// atomic functions that return updated value
#define atomic_reference(i)	InterlockedIncrement(&i)
#define atomic_release(i)	InterlockedDecrement(&i)

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

typedef DWORD tlskey_t;

#define tls_init(k)		k = TlsAlloc()
#define tls_free(k)		TlsFree(k)
#define tls_get(k)		TlsGetValue(k)
#define tls_set(k, v)		TlsSetValue(key, (void *)v)

#else

#include <errno.h>
#include <pthread.h>

typedef pthread_t thread_hdl_t;
#if defined(__FreeBSD__) || defined(__OpenBSD__)
#include <pthread_np.h>
typedef ulong thread_id_t;
#define THREAD_EQUAL(x, y)	((x) == (y))
#define THREAD_ID()		(thread_id_t)pthread_getthreadid_np()
#elif defined(__linux__)
#include <sys/syscall.h>
typedef pid_t thread_id_t;
#define THREAD_EQUAL(x, y)	((x) == (y))
#define THREAD_ID()		(thread_id_t)syscall(__NR_gettid)
#else
typedef pthread_t thread_id_t;
#define THREAD_EQUAL(x, y)	(pthread_equal(x, y) != 0)
#define THREAD_ID()		pthread_self()
#endif

#define INFINITE		(ulong)-1
#define THREAD_FUNC		void *
#define THREAD_HDL()		pthread_self()
#if CPLUSPLUS >= 11
#define THREAD_BARRIER()	atomic_signal_fence(memory_order_acquire);
#define THREAD_FENCE()		atomic_thread_fence(memory_order_relaxed);
#if defined(__i386__) || defined(__x86_64__)
#define THREAD_PAUSE()  	__builtin_ia32_pause()
#endif
#elif defined(__GNUC__) && (defined(__i386__) || defined(__x86_64__))
#define THREAD_BARRIER()	asm volatile("" ::: "memory")
#define THREAD_FENCE()		asm volatile("mfence" ::: "memory")
#if __GNUC_MAJOR__ < 5
#define THREAD_PAUSE()		asm volatile("pause" ::: "memory")
#else
#define THREAD_PAUSE()  	__builtin_ia32_pause()
#endif
#endif
#define THREAD_YIELD()		sched_yield()

#ifdef __GNUC__

#if defined(__arm__) && (__GNUC__ < 4 || (__GNUC__ == 4 && __GNUC_MINOR__ < 4))

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

#define atomic_reference(i)	(__sync_fetch_and_add(&i, 1) + 1)
#define atomic_release(i)	(__sync_fetch_and_add(&i, -1) - 1)

#if (defined(__i386__) || defined(__x86_64__)) && defined(__GNUC__)

inline void atomic_clr(atomic_t &lck) {
    atomic_t r;

    asm volatile(
	"xchgl %0, %1"
	: "=r" (r), "=m" (lck)
	: "0" (0), "m" (lck)
	: "memory");
}

inline atomic_t atomic_lck(atomic_t &lck) {
    atomic_t r;

    asm volatile(
	"xchgl %0, %1"
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

#define atomic_reference(i)	__sync_add_and_fetch(&i, 1)
#define atomic_release(i)	__sync_add_and_fetch(&i, -1)

#define atomic_add(i, j)	__sync_fetch_and_add(&i, j)
#define atomic_and(i, j)	__sync_fetch_and_and(&i, j)
#define atomic_bar()		__sync_synchronize()
#define atomic_clr(i)		__sync_lock_release(&i)
// #define atomic_clr(i)	__sync_lock_test_and_set(&i, 0)
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

#define tls_init(k)		ZERO(k); pthread_key_create(&k, NULL)
#define tls_free(k)		pthread_key_delete(k)
#define tls_get(k)		pthread_getspecific(k)
#define tls_set(k, v)		pthread_setspecific(k, v)

#endif

#define THREAD_ISSELF(x)	THREAD_EQUAL(x, THREAD_ID())

#define atomic_get(i)		atomic_add(i, 0)

#ifdef __cplusplus

#if CPLUSPLUS >= 11
#include <atomic>
#else
typedef volatile atomic_t atomic_flag;
#endif
#include <set>
#include STL_UNORDERED_MAP_H

class Thread;
class ThreadGroup;

/* RAII locking templates */
template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() =
    &C::unlock>
class BLISTER LockerTemplate: nocopy {
public:
    explicit __forceinline LockerTemplate(C &lock, bool lockit = true):
	lck(lock), locked(lockit) {
	if (LIKELY(lockit))
	    (lck.*LOCK)();
    }
    __forceinline ~LockerTemplate() { if (LIKELY(locked)) (lck.*UNLOCK)(); }

    __forceinline operator bool(void) const { return locked; }

    __forceinline void lock(void) {
	if (LIKELY(!locked)) {
	    locked = true;
	    (lck.*LOCK)();
	}
    }
    __forceinline void relock(void) {
	if (LIKELY(locked)) {
	    (lck.*UNLOCK)();
	    THREAD_YIELD();
	} else {
	    locked = true;
	}
	(lck.*LOCK)();
    }
    __forceinline void unlock(void) {
	if (LIKELY(locked)) {
	    (lck.*UNLOCK)();
	    locked = false;
	}
    }

private:
    C &lck;
    bool locked;
};

template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() = &C::unlock>
class BLISTER FastLockerTemplate: nocopy {
public:
    explicit __forceinline FastLockerTemplate(C &lock): lck(lock) {
	(lck.*LOCK)();
    }
    __forceinline ~FastLockerTemplate() { (lck.*UNLOCK)(); }

    __forceinline void relock(void) {
	(lck.*UNLOCK)();
	THREAD_YIELD();
	(lck.*LOCK)();
    }

private:
    C &lck;
};

template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() = &C::unlock>
class BLISTER FastUnlockerTemplate: nocopy {
public:
    explicit __forceinline FastUnlockerTemplate(C &lock): lck(lock) {
	(lck.*UNLOCK)();
    }
    __forceinline ~FastUnlockerTemplate() { (lck.*LOCK)(); }

private:
    C &lck;
};

/*
 * The DLLibrary class loads shared libraries and dynamically fetches function
 * pointers. Do not specify file extensions in the constructor
 */
class BLISTER DLLibrary: nocopy {
public:
    explicit DLLibrary(const tchar *dll = NULL): hdl(0) { open(dll); }
    ~DLLibrary() { close(); }

    operator void *(void) const { return hdl; }
    bool operator !(void) const { return hdl == NULL; }

    const tstring &error(void) const { return err; }
    const tstring &name(void) const { return file; }
    bool close(void);
    void *get(const tchar *symbol) const;
    bool open(const tchar *dll);

private:
    tstring err;
    tstring file;
    void *hdl;
};

class BLISTER Processor: nocopy {
public:
    static ullong affinity(void);
    static bool affinity(ullong mask);
    static uint count(void);
};

/* Thread local storage for simple types */
template<class C>
class BLISTER ThreadLocal: nocopy {
public:
    // cppcheck-suppress useInitializationList
    ThreadLocal() { tls_init(key); }
    ~ThreadLocal() { tls_free(key); }

    __forceinline ThreadLocal &operator =(C c) { set(c); return *this; }
    // cppcheck-suppress returnDanglingLifetime
    __forceinline C *operator ->(void) const { return &get(); }
    __forceinline operator bool(void) const { return tls_get(key) != NULL; }
    __forceinline operator C() const { return (C)tls_get(key); }

    __forceinline C get(void) const { return (C)tls_get(key); }
    __forceinline void set(const C c) const { tls_set(key, c); }

protected:
    tlskey_t key;
};

/* Thread local storage for classes with proper destruction when theads exit */
typedef void (*ThreadLocalFree)(void *data);

template<class C>
class BLISTER ThreadLocalClass: nocopy {
public:
    // cppcheck-suppress useInitializationList
    ThreadLocalClass() { tls_init(key); }
    ~ThreadLocalClass() { tls_free(key); }

    __forceinline C &operator *(void) const { return get(); }
    __forceinline C *operator ->(void) const { return &get(); }
    void erase(void) {
	C *c = (C *)tls_get(key);

	tls_set(key, 0);
	Thread::thread_cleanup(c, NULL);
    }
    C &get(void) const {
	C *c = (C *)tls_get(key);

	if (UNLIKELY(!c)) {
	    c = new C;
	    tls_set(key, c);
	    Thread::thread_cleanup(c, cleanup);
	}
	return *c;
    }
    __forceinline void set(C *c) const { tls_set(key, c); }

protected:
    tlskey_t key;

    static void cleanup(void *data) { delete (C *)data; }
};

/*
 * Thread synchronization classes
 * Condvar: condition variable around a Lock
 * Lock: fast lock that may spin before sleeping
 * Mutex: lock that does not spin before sleeping
 * RWLock: reader/writer lock. r->w uplock allow intervening writers
 * SpinLock: fastest lock with exponential backoff but no sleep
 * SpinRWLock: fast spinning reader/writer lock
 */
#if defined(NO_ATOMIC_LOCK)

class BLISTER SpinLock: nocopy {
public:
    SpinLock() { pthread_spin_init(&lck, 0); }
    ~SpinLock() { pthread_spin_destroy(&lck); }

    __forceinline operator pthread_spinlock_t *(void) { return &lck; }

    __forceinline void lock(void) { pthread_spin_lock(&lck); }
    __forceinline bool trylock(void) { return pthread_spin_trylock(&lck) == 0; }
    __forceinline void unlock(void) { pthread_spin_unlock(&lck); }

protected:
    pthread_spinlock_t lck;
};

#else

class BLISTER SpinLock: nocopy {
public:
    explicit SpinLock(uint lmt = 16):
#ifdef _WIN32
#elif CPLUSPLUS >= 11 && !defined(__GNUC__)
	lck(ATOMIC_FLAG_INIT),
#else
	lck(0),
#endif
	spins(Processor::count() == 1 ? 0 : lmt) {}
    __forceinline __no_sanitize_thread void lock(void) {
	if (testlock() || UNLIKELY(!trylock())) {
#ifdef THREAD_PAUSE
	    uint u = 0;

	    do {
		if (LIKELY(u < spins)) {
		    ++u;
		    THREAD_PAUSE();
		} else {
		    u = 0;
		    THREAD_YIELD();
		}
	    } while (LIKELY(testlock()) || UNLIKELY(!trylock()));
#else
	    do {
		THREAD_YIELD();
	    } while (LIKELY(testlock()) || UNLIKELY(!trylock()));
#endif
	}
    }
#if CPLUSPLUS >= 11 && !defined(__GNUC__)
    __forceinline bool testlock(void) const {
#ifdef __cpp_lib_atomic_flag_test
	return lck.test(memory_order_relaxed);
#else
	return false;
#endif
    }
    __forceinline __no_sanitize_thread bool trylock(void) {
	return !lck.test_and_set(memory_order_acquire);
    }
    __forceinline __no_sanitize_thread void unlock(void) {
	lck.clear(memory_order_release);
    }
#else
    __forceinline __no_sanitize_thread bool testlock(void) const { return lck; }
    __forceinline __no_sanitize_thread bool trylock(void) {
	return !atomic_lck(lck);
    }
    __forceinline __no_sanitize_thread void unlock(void) { atomic_clr(lck); }
#endif

private:
#if CPLUSPLUS >= 11 && !defined(__GNUC__)
    atomic_flag lck;
#else
    atomic_t lck;
#endif
    const uint spins;
};

#endif

typedef FastLockerTemplate<SpinLock> FastSpinLocker;
typedef FastUnlockerTemplate<SpinLock> FastSpinUnlocker;
typedef LockerTemplate<SpinLock> SpinLocker;

#ifdef _WIN32
#define msleep(msec)	Sleep(msec)

class BLISTER Lock: nocopy {
public:
    Lock() { InitializeCriticalSection(&cs); }
    ~Lock() { DeleteCriticalSection(&cs); }

    __forceinline void lock(void) { EnterCriticalSection(&cs); }
    __forceinline void spin(uint cnt) { SetCriticalSectionSpinCount(&cs, cnt); }
    __forceinline bool trylock(void) {
	return TryEnterCriticalSection(&cs) != 0;
    }
    __forceinline void unlock(void) { LeaveCriticalSection(&cs); }

protected:
    CRITICAL_SECTION cs;
};

class BLISTER Mutex: nocopy {
public:
    explicit Mutex(const tchar *name = NULL);
    ~Mutex() { if (hdl) CloseHandle(hdl); }

    __forceinline void lock(void) { WaitForSingleObject(hdl, INFINITE); }
    __forceinline bool trylock(ulong msec = 0) {
	return WaitForSingleObject(hdl, msec) == WAIT_OBJECT_0;
    }
    __forceinline void unlock(void) { ReleaseMutex(hdl); }

protected:
    HANDLE hdl;
};

class BLISTER Event: nocopy {
public:
    explicit Event(bool manual = false, bool set = false, const tchar *name =
	NULL): hdl(NULL) { open(manual, set, name); }
    ~Event() { close(); }

    __forceinline operator HANDLE(void) const { return hdl; }
    __forceinline HANDLE handle(void) const { return hdl; }

    bool close(void) {
	HANDLE h = hdl;

	hdl = NULL;
	return h ? CloseHandle(h) != 0 : true;
    }
    bool open(bool manual = false, bool set = false, const tchar *name = NULL) {
	close();
	return (hdl = CreateEvent(NULL, manual, set, name)) != NULL;
    }
    __forceinline bool pulse(void) { return PulseEvent(hdl) != 0; }
    __forceinline bool reset(void) { return ResetEvent(hdl) != 0; }
    __forceinline bool set(void) { return SetEvent(hdl) != 0; }
    __forceinline bool wait(ulong msec = INFINITE) {
	return WaitForSingleObject(hdl, msec) != WAIT_TIMEOUT;
    }

protected:
    HANDLE hdl;
};

class BLISTER _Semaphore {
public:
    explicit _Semaphore(const tchar *name = NULL, uint init = 0): hdl(NULL) {
	if (init != (uint)-1)
	    _open(name, init);
    }
    ~_Semaphore() { close(); }

    __forceinline operator HANDLE(void) const { return hdl; }
    __forceinline HANDLE handle(void) const { return hdl; }

    bool close(void) {
	HANDLE h = hdl;

	hdl = NULL;
	return h == NULL || CloseHandle(h) != 0;
    }
    __forceinline bool set(uint cnt = 1) {
	return ReleaseSemaphore(hdl, (LONG)cnt, NULL) != 0;
    }
    __forceinline bool trywait(void) {
	return WaitForSingleObject(hdl, 0) == WAIT_OBJECT_0;
    }
    __forceinline bool wait(ulong msec = INFINITE) {
	return WaitForSingleObject(hdl, msec) == WAIT_OBJECT_0;
    }

protected:
    HANDLE hdl;

    bool _open(const tchar *name, uint init, bool exclusive = false) {
	close();
	hdl = CreateSemaphore(NULL, (LONG)init, LONG_MAX, name);
	if (hdl == NULL && !exclusive)
	    hdl = OpenSemaphore(SEMAPHORE_ALL_ACCESS, 0, name);
	return hdl != NULL;
    }
};

class BLISTER Semaphore: public _Semaphore, private nocopy {
public:
    explicit Semaphore(uint init = 0): _Semaphore(NULL, init) {}

    bool open(uint init = 0) { return _open(NULL, init); }
};

class BLISTER SharedSemaphore: public _Semaphore, private nocopy {
public:
    explicit SharedSemaphore(const tchar *name, uint init = 0): _Semaphore(name,
	init) {}

    bool open(const tchar *name = NULL, uint init = 0, bool exclusive = false) {
	return _open(name, init, exclusive);
    }
};

class BLISTER Condvar: nocopy {
public:
    explicit Condvar(Lock &lock): lck(lock), pending(0), waiting(0) {}

    __forceinline void broadcast(void) { set((uint)-1); }
    __forceinline void set(uint count = 1) {
	uint cnt;

	olck.lock();
	cnt = waiting - pending;
	if (LIKELY(cnt)) {
	    if (!pending) {
		ilck.lock();
		cnt = waiting - pending;
	    }
	    if (count < cnt)
		cnt = count;
	    pending += cnt;
	    sema4.set(cnt);
	}
	olck.unlock();
    }
    __forceinline bool wait(ulong msec = INFINITE) {
	bool ret;

	ilck.lock();
	atomic_inc(waiting);
	ilck.unlock();
	lck.unlock();
	ret = sema4.wait(msec);
	olck.lock();
	if (UNLIKELY(!ret))
	    ret = sema4.trywait();
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

class BLISTER Process {
public:
    explicit Process(HANDLE hproc): hdl(hproc) {}
    ~Process() { if (hdl) CloseHandle(hdl); }

    static int argc;
    static tchar **argv;
    static tchar **envv;
    static Process self;

    operator HANDLE(void) const { return hdl; }
    bool mask(ulong m) { return SetProcessAffinityMask(hdl, m) != 0; }
    static Process start(tchar * const *args, const int *fds = NULL);

private:
    HANDLE hdl;
};

#else

inline void msleep(ulong msec) {
    struct timespec ts;

    ts.tv_sec = (time_t)(msec / 1000U);
    *(ulong *)&ts.tv_nsec = (msec % 1000U) * 1000000U;
    nanosleep(&ts, NULL);
}

class BLISTER Lock: nocopy {
public:
    Lock() { pthread_mutex_init(&mtx, NULL); }
    ~Lock() { (void)pthread_mutex_destroy(&mtx); }

    __forceinline operator pthread_mutex_t *(void) { return &mtx; }

    __forceinline void lock(void) { (void)pthread_mutex_lock(&mtx); }
    __forceinline bool trylock(void) { return pthread_mutex_trylock(&mtx) == 0; }
    __forceinline void unlock(void) { (void)pthread_mutex_unlock(&mtx); }

protected:
    pthread_mutex_t mtx;
};

typedef Lock Mutex;

#ifdef __APPLE__
#include <mach/mach_init.h>
#include <mach/semaphore.h>
#include <mach/task.h>

class BLISTER Semaphore: nocopy {
public:
    explicit Semaphore(uint init = 0): hdl(0) {
	if (init != (uint)-1)
	    open(init);
    }
    ~Semaphore() { close(); }

    __forceinline operator semaphore_t(void) const { return hdl; }
    __forceinline semaphore_t handle(void) const { return hdl; }

    __forceinline bool broadcast(void) {
	return semaphore_signal_all(hdl) == KERN_SUCCESS;
    }
    bool __no_sanitize_thread close(void) {
	semaphore_t h = hdl;

	hdl = 0;
	return h == 0 || semaphore_destroy(mach_task_self(), h) == KERN_SUCCESS;
    }
    bool open(uint init = 0, bool fifo = true) {
	close();
	return semaphore_create(mach_task_self(), &hdl, fifo ?
	    SYNC_POLICY_FIFO : SYNC_POLICY_LIFO, (int)init) == KERN_SUCCESS;
    }
    __forceinline bool set(uint cnt = 1) {
	while (cnt--) {
	    if (UNLIKELY(semaphore_signal(hdl) != KERN_SUCCESS))
		return false;
	}
	return true;
    }
    __forceinline bool trywait(void) {
	static mach_timespec ts = { 0, 0 };

	return semaphore_timedwait(hdl, ts) == KERN_SUCCESS;
    }
    __forceinline bool wait(ulong msec = INFINITE) {
	if (msec == INFINITE)
	    return semaphore_wait(hdl) == KERN_SUCCESS;

	mach_timespec ts = {
	    (uint)(msec / 1000), ((clock_res_t)msec % 1000) * 1000000
	};

	return semaphore_timedwait(hdl, ts) == KERN_SUCCESS;
    }

protected:
    semaphore_t hdl;
};

#else

#include <semaphore.h>

class BLISTER Semaphore: nocopy {
public:
    explicit Semaphore(uint init = 0): valid(false) {
	if (init != (uint)-1)
	    open(init);
    }
    ~Semaphore() { close(); }

    __forceinline operator sem_t(void) const { return hdl; }
    __forceinline uint get(void) const {
	int ret;

	return (uint)(!valid || sem_getvalue((sem_t *)&hdl, &ret) ? -1 : ret);
    }
    __forceinline sem_t handle(void) const { return hdl; }

    bool close(void) {
	if (valid) {
	    valid = false;
	    return sem_destroy(&hdl) == 0;
	}
	return true;
    }
    bool open(uint init = 0) {
	close();
	return valid = (sem_init(&hdl, 0, init) == 0);
    }
    __forceinline bool set(uint cnt = 1) {
	while (cnt--) {
	    if (UNLIKELY(sem_post(&hdl)))
		return false;
	}
	return true;
    }
    __forceinline bool trywait(void) {
	do {
	    if (!sem_trywait(&hdl))
		return true;
	} while (errno == EINTR);
	return false;
    }
    __forceinline bool wait(ulong msec = INFINITE) {
	if (msec == INFINITE) {
	    do {
		if (!sem_wait(&hdl))
		    return true;
	    } while (errno == EINTR);
	} else {
	    timespec ts;

	    clock_gettime(CLOCK_REALTIME_COARSE, &ts);
	    time_adjust_msec(&ts, msec);
	    do {
		if (!sem_timedwait(&hdl, &ts))
		    return true;
	    } while (errno == EINTR);
	}
	return false;
    }

protected:
    sem_t hdl;
    bool valid;
};

#endif

#include <sys/ipc.h>
#include <sys/sem.h>

class BLISTER SharedSemaphore: nocopy {
public:
    explicit SharedSemaphore(const tchar *name = NULL, uint init = 0): hdl(-1) {
	open(name, init);
    }
    ~SharedSemaphore() { close(); }

    __forceinline operator int(void) const { return hdl; }
    __forceinline int get(void) const { return semctl(hdl, 0, GETVAL); }
    __forceinline int handle(void) const { return hdl; }

    bool close(void) { return true; }
    bool erase(void) {
	int h = hdl;

	hdl = -1;
	return h == -1 || semctl(h, 0, IPC_RMID) == 0;
    }
    bool open(const tchar *name = NULL, uint init = 0, bool exclusive = false);
    __forceinline bool set(uint cnt = 1) {
	sembuf op;

	op.sem_num = 0;
	op.sem_op = (short)cnt;
	op.sem_flg = 0;
	return semop(op);
    }
    __forceinline bool trywait(void) {
	sembuf op;

	op.sem_num = 0;
	op.sem_op = -1;
	op.sem_flg = IPC_NOWAIT;
	return semop(op);
    }
    __forceinline bool wait(ulong msec = INFINITE) {
	sembuf op;

	op.sem_num = 0;
	op.sem_op = -1;
	op.sem_flg = 0;
	if (msec == INFINITE)
	    return semop(op);
#ifdef BSD_BASE
	(void)msec;
	return semop(op);
#else
	timespec ts;

	clock_gettime(CLOCK_REALTIME_COARSE, &ts);
	time_adjust_msec(&ts, msec);
	do {
	    if (LIKELY(!semtimedop(hdl, &op, 1, &ts)))
		return true;
	} while (errno == EINTR);
	return false;
#endif
    }

protected:
    int hdl;

    __forceinline bool semop(sembuf &op) const {
	do {
	    if (LIKELY(!::semop(hdl, &op, 1)))
		return true;
	} while (errno == EINTR);
	return false;
    }
};

class BLISTER Condvar: nocopy {
public:
    explicit Condvar(Lock &lck): lock(lck) {
#ifdef __APPLE__
	pthread_cond_init(&cv, NULL);
#else
	pthread_condattr_t attr;

	pthread_condattr_init(&attr);
	pthread_condattr_setclock(&attr, CLOCK_MONOTONIC);
	pthread_cond_init(&cv, &attr);
	pthread_condattr_destroy(&attr);
#endif
    }
    ~Condvar() { pthread_cond_destroy(&cv); }

    __forceinline void broadcast(void) { pthread_cond_broadcast(&cv); }
    __forceinline void set(uint count = 1) {
	while (count) {
	    pthread_cond_signal(&cv);
	    --count;
	}
    }
    __forceinline bool wait(ulong msec = INFINITE) {
	if (msec == INFINITE) {
	    return pthread_cond_wait(&cv, lock) == 0;
	} else {
	    timespec ts;
#ifdef __APPLE__
	    ts.tv_sec = (uint)(msec / 1000);
	    ts.tv_nsec = (msec % 1000) * 1000000;
	    return !pthread_cond_timedwait_relative_np(&cv, lock, &ts);
#else
	    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
	    time_adjust_msec(&ts, msec);
	    return !pthread_cond_timedwait(&cv, lock, &ts);
#endif
	}
    }

protected:
    pthread_cond_t cv;
    Lock &lock;
};

#endif

typedef LockerTemplate<Lock> Locker;
typedef FastLockerTemplate<Lock> FastLocker;

class BLISTER SpinRWLock: nocopy {
public:
    SpinRWLock(): readers(0), wwaiting(0), writing(false) {}

    __forceinline void downlock(void) {
	FastSpinLocker lckr(lck);

	++readers;
	writing = false;
    }
    __forceinline void rlock(void) {
	FastSpinLocker lckr(lck);

	while (UNLIKELY(writing || wwaiting))
	    lckr.relock();
	++readers;
    }
    __forceinline bool rtrylock(ulong spins = 0) {
	FastSpinLocker lckr(lck);

	while (writing || wwaiting) {
	    if (LIKELY(!spins))
		return false;
	    --spins;
	    lckr.relock();
	}
	++readers;
	return true;
    }
    __forceinline void runlock(void) {
	FastSpinLocker lckr(lck);

	--readers;
    }
    __forceinline bool tryuplock(ulong spins = 0) {
	FastSpinLocker lckr(lck);

	if (readers > 1 || writing) {
	    if (LIKELY(!spins))
		return false;
	    ++wwaiting;
	    do {
		lckr.relock();
	    } while ((readers > 1 || writing) && --spins);
	    --wwaiting;
	    if (!spins)
		return false;
	}
	writing = true;
	return true;
    }
    __forceinline void uplock(void) {
	FastSpinLocker lckr(lck);

	if (readers > 1 || writing) {
	    ++wwaiting;
	    do {
		lckr.relock();
	    } while (readers > 1 || writing);
	    --wwaiting;
	}
	writing = true;
    }
    __forceinline void wlock(void) {
	FastSpinLocker lckr(lck);

	if (readers || writing) {
	    ++wwaiting;
	    do {
		lckr.relock();
	    } while (readers || writing);
	    --wwaiting;
	}
	writing = true;
    }
    __forceinline bool wtrylock(ulong spins = 0) {
	FastSpinLocker lckr(lck);

	if (readers || writing) {
	    if (LIKELY(!spins))
		return false;
	    ++wwaiting;
	    do {
		lckr.relock();
	    } while ((readers || writing) && --spins);
	    --wwaiting;
	    if (!spins)
		return false;
	}
	writing = true;
	return true;
    }
    __forceinline void wunlock(void) {
	FastSpinLocker lckr(lck);

	writing = false;
    }

private:
    SpinLock lck;
    volatile ulong readers, wwaiting;
    volatile bool writing;
};

typedef LockerTemplate<SpinRWLock, &SpinRWLock::rlock, &SpinRWLock::runlock>
    SpinRLocker;
typedef LockerTemplate<SpinRWLock, &SpinRWLock::wlock, &SpinRWLock::wunlock>
    SpinWLocker;
typedef FastLockerTemplate<SpinRWLock, &SpinRWLock::rlock, &SpinRWLock::runlock>
    FastSpinRLocker;
typedef FastLockerTemplate<SpinRWLock, &SpinRWLock::wlock, &SpinRWLock::wunlock>
    FastSpinWLocker;

class BLISTER RWLock: nocopy {
public:
    RWLock(): rcv(lck), wcv(lck), readers(0), wwaiting(0), writing(false) {}

    __forceinline void downlock(void) {
	FastLocker lckr(lck);

	++readers;
	writing = false;
	if (wwaiting)
	    wcv.set();
	else
	    rcv.broadcast();
    }
    __forceinline void rlock(void) {
	FastLocker lckr(lck);

	while (UNLIKELY(writing || wwaiting))
	    rcv.wait();
	++readers;
    }
    __forceinline bool rtrylock(ulong msec = 0) {
	FastLocker lckr(lck);

	if (UNLIKELY(writing || wwaiting)) {
	    if (!msec || !rcv.wait(msec))
		return false;
	}
	++readers;
	return true;
    }
    __forceinline void runlock(void) {
	FastLocker lckr(lck);

	if (UNLIKELY(!--readers && wwaiting))
	    wcv.set();
    }
    __forceinline void uplock(void) {
	FastLocker lckr(lck);

	--readers;
	if (readers) {
	    ++wwaiting;
	    do {
		wcv.wait();
	    } while (readers || writing);
	    --wwaiting;
	}
	writing = true;
    }
    __forceinline void wlock(void) {
	FastLocker lckr(lck);

	while (readers || writing) {
	    ++wwaiting;
	    wcv.wait();
	    --wwaiting;
	}
	writing = true;
    }
    __forceinline bool wtrylock(ulong msec = 0) {
	FastLocker lckr(lck);

	if (readers || writing) {
	    if (!msec)
		return false;
	    ++wwaiting;
	    if (!wcv.wait(msec)) {
		--wwaiting;
		return false;
	    }
	    --wwaiting;
	}
	writing = true;
	return true;
    }
    __forceinline void wunlock(void) {
	FastLocker lckr(lck);

	writing = false;
	if (LIKELY(wwaiting))
	    wcv.set();
	else
	    rcv.broadcast();
    }

private:
    Lock lck;
    Condvar rcv, wcv;
    volatile ulong readers, wwaiting;
    volatile bool writing;
};

typedef LockerTemplate<RWLock, &RWLock::rlock, &RWLock::runlock> RLocker;
typedef LockerTemplate<RWLock, &RWLock::wlock, &RWLock::wunlock> WLocker;
typedef FastLockerTemplate<RWLock, &RWLock::rlock, &RWLock::runlock> FastRLocker;
typedef FastLockerTemplate<RWLock, &RWLock::wlock, &RWLock::wunlock> FastWLocker;

/* Fast reference counter class */
#ifdef NO_ATOMIC_ADD
class BLISTER RefCount: nocopy {
public:
    explicit RefCount(uint init = 1): cnt(init) {}

    __forceinline operator bool(void) const { return referenced(); }
    __forceinline bool referenced(void) const {
	FastSpinLocker lkr(lck);

	return cnt != 0;
    }

    __forceinline void reference(void) { FastSpinLocker lkr(lck); ++cnt; }
    __forceinline bool release(void) {
	FastSpinLocker lkr(lck);

	return --cnt == 0;
    }

private:
    uint cnt;
    mutable SpinLock lck;
};

#else

class BLISTER RefCount: nocopy {
public:
    explicit RefCount(uint init = 1): cnt((int)init) {}

    __forceinline operator bool(void) const { return referenced(); }
    __forceinline bool referenced(void) const { return atomic_get(cnt) != 0; }

    __forceinline void reference(void) { atomic_reference(cnt); }
    __forceinline bool release(void) { return atomic_release(cnt) == 0; }

private:
    mutable atomic_t cnt;
};
#endif

/* Thread safe # template */
#if CPLUSPLUS >= 11
#define TSNumber atomic
#else
template<class C>
class TSNumber: nocopy {
public:
    explicit TSNumber(C init = 0): c(init) {}
    TSNumber(const TSNumber<C> &init): c(init) {}

    operator C() const { TSLocker lkr(lck); return c; }
    template<class N> bool operator ==(N n) const { TSLocker lkr(lck); return c == n; }
    template<class N> bool operator !=(N n) const { TSLocker lkr(lck); return c != n; }
    TSNumber<C> &operator ++(void) { TSLocker lkr(lck); ++c; return *this; }
    C operator ++(int) { TSLocker lkr(lck); return c++; }
    TSNumber<C> &operator --(void) { TSLocker lkr(lck); --c; return *this; }
    C operator --(int) { TSLocker lkr(lck); return c--; }
    template<class N> TSNumber<C> &operator =(const N &n) {
	TSLocker lkr(lck); c = (C)n; return *this;
    }
    TSNumber<C> &operator =(const TSNumber<C> &n) { return operator =((C)n); }
    template<class N> C operator +=(N n) { TSLocker lkr(lck); return c += (C)n; }
    template<class N> C operator -=(N n) { TSLocker lkr(lck); return c -= (C)n; }
    template<class N> C operator *=(N n) { TSLocker lkr(lck); return c *= (C)n; }
    template<class N> C operator /=(N n) { TSLocker lkr(lck); return c /= (C)n; }
    template<class N> C operator &=(N n) { TSLocker lkr(lck); return c &= (C)n; }
    template<class N> C operator |=(N n) { TSLocker lkr(lck); return c |= (C)n; }
    template<class N> C operator %=(N n) { TSLocker lkr(lck); return c %= (C)n; }
    template<class N> C operator ^=(N n) { TSLocker lkr(lck); return c ^= (C)n; }
    template<class N> C operator >>=(N n) { TSLocker lkr(lck); return c >>= n; }
    template<class N> C operator <<=(N n) { TSLocker lkr(lck); return c <<= n; }

    C load(void) const { TSLocker lkr(lck); return c; }
    template<class N> C store(N n) { TSLocker lkr(lck); return c = (C)n; }
    template<class N> C fetch_add(N n) {
	TSLocker lkr(lck);
	C ret = c;

	c += (C)(n);
	return ret;
    }
    template<class N> C fetch_and(N n) {
	TSLocker lkr(lck);
	C ret = c;

	c &= (C)(n);
	return ret;
    }
    template<class N> C fetch_or(N n) {
	TSLocker lkr(lck);
	C ret = c;

	c |= (C)(n);
	return ret;
    }
    template<class N> C fetch_sub(N n) {
	TSLocker lkr(lck);
	C ret = c;

	c -= (C)(n);
	return ret;
    }
    template<class N> C fetch_xor(N n) {
	TSLocker lkr(lck);
	C ret = c;

	c ^= (C)(n);
	return ret;
    }
    void lock(void) { lck.lock(); }
    void unlock(void) { lck.unlock(); }

protected:
    volatile C c;
    mutable SpinLock lck;
    typedef FastSpinLocker TSLocker;

    C *operator &();	// NOLINT
};
#endif

/* Last-in-first-out queue useful for thread pools */
class BLISTER Lifo {
public:
    class Waiting: nocopy {
    public:
	Waiting *next;
	Semaphore sema4;

	Waiting(): next(NULL) {}
    };

    Lifo(): head(NULL), sz(0) {}
    ~Lifo() { close(); }

    __forceinline operator bool(void) const {
	FastSpinLocker lkr(lck);

	return sz != 0;
    }
    __forceinline bool empty(void) const {
	FastSpinLocker lkr(lck);

	return sz == 0;
    }
    __forceinline uint size(void) const {
	FastSpinLocker lkr(lck);

	return sz;
    }
    __forceinline uint broadcast(void) {
	Waiting *w, *next;
	uint ret;

	lck.lock();
	w = head;
	head = NULL;
	ret = sz;
	sz = 0;
	lck.unlock();
	while (w) {
	    next = w->next;
	    w->sema4.set();
	    w = next;
	}
	return ret;
    }
    bool close(void) { broadcast(); return true; }
    bool open(void) {
	head = NULL;
	sz = 0;
	return true;
    }
    __forceinline uint set(uint count = 1) {
	lck.lock();
	while (LIKELY(head && count)) {
	    Waiting *w = head;

	    head = w->next;
	    --sz;
	    lck.unlock();
	    w->sema4.set();
	    if (!--count)
		return 0;
	    lck.lock();
	}
	lck.unlock();
	return count;
    }
    __forceinline bool wait(Waiting &w, ulong msec = INFINITE) {
	lck.lock();
	w.next = head;
	head = &w;
	++sz;
	lck.unlock();
	if (UNLIKELY(!w.sema4.wait(msec))) {
	    lck.lock();
	    for (Waiting **ww = (Waiting **)&head; *ww; ww = &(*ww)->next) {
		if (*ww == &w) {
		    *ww = w.next;
		    --sz;
		    lck.unlock();
		    return false;
		}
	    }
	    lck.unlock();
	}
	return true;
    }

private:
    Waiting *head;
    mutable SpinLock lck;
    uint sz;
};

// Thread routines
typedef int (*ThreadRoutine)(void *userdata);
typedef bool (Thread::*ThreadControlRoutine)(void);

enum ThreadState { Init, Running, Suspended, Terminated };

/* manage OS native threads */
class BLISTER Thread: nocopy {
public:
    explicit Thread(thread_hdl_t handle, ThreadGroup *tg = NULL, bool autoterm =
	false);
    Thread(void);
    virtual ~Thread();

    static Thread MainThread;

    int exitStatus(void) const { return retval; }
    thread_hdl_t getHandle(void) const { return hdl; }
    thread_id_t getId(void) const { FastLocker lkr(lck); return id; }
    ThreadState getState(void) const { FastLocker lkr(lck); return state; }
    ThreadGroup *getThreadGroup(void) const { return group; }
    bool running(void) const { return getState() == Running; }
    bool suspended(void) const { return getState() == Suspended; }
    bool terminated(void) const { return getState() == Terminated; }

    operator thread_hdl_t(void) const { return hdl; }
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
    static void thread_cleanup(void *data, ThreadLocalFree func);

protected:
    void end(int ret = 0);
    virtual int onStart(void) { return -1; }
    virtual void onStop(void) {}

private:
    typedef unordered_map<void *, ThreadLocalFree> ThreadLocalMap;

    mutable Lock lck;
    Condvar cv;
    void *argument;
    bool autoterm;
    ThreadGroup *group;
    thread_hdl_t hdl;
    thread_id_t id;
    ThreadRoutine main;
    int retval;
    volatile ThreadState state;
    static ThreadLocal<ThreadLocalMap *> flocal;

    void clear(void);
    void thread_cleanup(void);
    static int init(void *thisp);
    static THREAD_FUNC thread_init(void *thisp);

    friend class ThreadGroup;
};

/* manage a group of one or more, possibly dissimilar threads */
typedef void (ThreadGroup::*ThreadGroupControlRoutine)(bool);

class BLISTER ThreadGroup: nocopy {
public:
    explicit ThreadGroup(bool autoterm = true);
    virtual ~ThreadGroup();

    static ThreadGroup MainThreadGroup;

    ThreadState getState(void) const { return state; }
    thread_id_t getId(void) const { return id; }
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
    // only the caller may delete returned Thread
    Thread *wait(ulong msec = INFINITE, bool all = false);
    bool waitForMain(ulong msec = INFINITE) { return master.wait(msec); }

    static ThreadGroup *add(Thread &thread, ThreadGroup *tg = NULL);

protected:
    void control(ThreadState, ThreadControlRoutine);
    void notify(const Thread &thread);
    virtual void onResume(void) {}
    virtual int onStart(void) { return -1; }
    virtual void onStop(void) {}
    virtual void onSuspend(void) {}

private:
    Lock cvlck;
    Condvar cv;
    bool autoterm;
    thread_id_t id;
    volatile ThreadState state;
    set<Thread *> threads;
    Thread master;
    static Lock grouplck;
    static set<ThreadGroup *> groups;
    static atomic_t next_id;

    static int init(void *thisp);
    friend class Thread;
};

#endif
#endif // Thread_h
