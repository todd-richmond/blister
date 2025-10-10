/*
 * Copyright 2001-2023 Todd Richmond
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

#define THREAD_BARRIER()	_ReadWriteBarrier()
#define THREAD_EQUAL(x, y)	((x) == (y))
#define THREAD_FENCE()		MemoryBarrier()
#define THREAD_FUNC		uint __stdcall
#define THREAD_HDL()		GetCurrentThread()
#define THREAD_ID()		GetCurrentThreadId()
#define THREAD_PAUSE()		YieldProcessor()
#define THREAD_YIELD()		if (!SwitchToThread()) Sleep(0)

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
#define THREAD_BARRIER()	atomic_signal_fence(memory_order_acquire);
#define THREAD_FENCE()		atomic_thread_fence(memory_order_relaxed);
#define THREAD_FUNC		void *
#define THREAD_HDL()		pthread_self()
#if defined(__i386__) || defined(__x86_64__)
#define THREAD_PAUSE()  	__builtin_ia32_pause()
#endif
#define THREAD_YIELD()		sched_yield()

typedef pthread_key_t tlskey_t;

#define tls_init(k)		ZERO(k); pthread_key_create(&k, NULL)
#define tls_free(k)		pthread_key_delete(k)
#define tls_get(k)		pthread_getspecific(k)
#define tls_set(k, v)		pthread_setspecific(k, v)
#endif

#define THREAD_ISSELF(x)	THREAD_EQUAL(x, THREAD_ID())

#ifdef __cplusplus

#include <atomic>
#include <set>

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
    void erase(void);
    C &get(void) const;
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
 * RWLock: reader/writer lock with r->w tryuplock
 * SpinLock: fastest unfair spinning lock
 * SpinRWLock: fast spinning reader/writer lock
 * TicketLock: fastest fair spinning lock
 */
#ifdef __cpp_lib_atomic_flag_test
class BLISTER atomic_bit: public atomic_flag {
public:
    explicit atomic_bit(void) { clear(); }
};

#else

class BLISTER atomic_bit: private atomic_bool {
public:
    explicit atomic_bit(void): atomic_bool(false) {}

    __forceinline void clear(memory_order order = memory_order_release) {
	store(false, order);
    }
    __forceinline bool test(memory_order order = memory_order_relaxed) const {
	return load(order);
    }
    __forceinline bool test_and_set(memory_order order = memory_order_acquire) {
	bool b = false;

	return !compare_exchange_strong(b, true, order);
    }
};
#endif

class BLISTER SpinLock: nocopy {
public:
    explicit SpinLock(uint lmt = 16): spins(Processor::count() == 1 ? 0 : lmt) {
    }
    __forceinline __no_sanitize_thread void lock(void) {
	while (!trylock()) {
#ifdef THREAD_PAUSE
	    uint u = 0;
#endif
	    do {
#ifdef THREAD_PAUSE
		if (LIKELY(u < spins)) {
		    ++u;
		    THREAD_PAUSE();
		} else {
		    u = 0;
		    THREAD_YIELD();
		}
#else
		THREAD_YIELD();
#endif
	    } while (testlock());
	}
    }
    __forceinline bool testlock(void) const {
	return lck.test(memory_order_relaxed);
    }
    __forceinline __no_sanitize_thread bool trylock(void) {
	return !lck.test_and_set(memory_order_acquire);
    }
    __forceinline __no_sanitize_thread void unlock(void) {
	lck.clear(memory_order_release);
    }

private:
    atomic_bit lck;
    const uint spins;
};

typedef FastLockerTemplate<SpinLock> FastSpinLocker;
typedef FastUnlockerTemplate<SpinLock> FastSpinUnlocker;
typedef LockerTemplate<SpinLock> SpinLocker;

class TicketLock: nocopy {
public:
    explicit TicketLock(uint lmt = 0): current(0), next(0), yield(lmt ? lmt :
	Processor::count() / 2) {}
    __forceinline void lock() {
	uint pos;
	uint ticket = (uint)next.fetch_add(1, memory_order_relaxed);

	while ((pos = ticket - (uint)current.load(memory_order_acquire)) != 0) {
#ifdef THREAD_PAUSE
	    if (LIKELY(pos < yield))
		THREAD_PAUSE();
	    else
		THREAD_YIELD();
#else
	    THREAD_YIELD();
#endif
	}
    }
    __forceinline void unlock() {
	// slight improvement over current.fetch_add(1, memory_order_release);
	current.store(current.load(memory_order_relaxed) + 1,
	    memory_order_release);
    }

private:
    atomic_uint_fast16_t current, next;
    const uint yield;
};

typedef FastLockerTemplate<TicketLock> FastTicketLocker;
typedef FastUnlockerTemplate<TicketLock> FastTicketUnlocker;
typedef LockerTemplate<TicketLock> TicketLocker;

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

class BLISTER RWLock: nocopy {
public:
    __forceinline RWLock() { InitializeSRWLock(&lck); }
    __forceinline ~RWLock() {}

    __forceinline void rlock(void) { AcquireSRWLockShared(&lck); }
    __forceinline bool rtrylock(void) { return TryAcquireSRWLockShared(&lck); }
    __forceinline void runlock(void) { ReleaseSRWLockShared(&lck); }
    __forceinline void wlock(void) { AcquireSRWLockExclusive(&lck); }
    __forceinline bool wtrylock(void) {
	return TryAcquireSRWLockExclusive(&lck);
    }
    __forceinline void wunlock(void) { ReleaseSRWLockExclusive(&lck); }

private:
    SRWLOCK lck;
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

	++waiting;
	lck.unlock();
	ret = sema4.wait(msec);
	olck.lock();
	if (UNLIKELY(!ret))
	    ret = sema4.trywait();
	--waiting;
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
    atomic_uint_fast16_t waiting;
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

class BLISTER RWLock: nocopy {
public:
    RWLock() { pthread_rwlock_init(&lck, NULL); }
    ~RWLock() { pthread_rwlock_destroy(&lck); }

    __forceinline void rlock(void) { pthread_rwlock_rdlock(&lck); }
    __forceinline bool rtrylock(void) {
	return !pthread_rwlock_tryrdlock(&lck);
    }
    __forceinline void runlock(void) { pthread_rwlock_unlock(&lck); }
    __forceinline void wlock(void) { pthread_rwlock_wrlock(&lck); }
    __forceinline bool wtrylock(void) {
	return !pthread_rwlock_trywrlock(&lck);
    }
    __forceinline void wunlock(void) { pthread_rwlock_unlock(&lck); }

private:
    pthread_rwlock_t lck;
};

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
    SpinRWLock(): state(0) {}

    __forceinline void downlock(void) { state.store(1, memory_order_release); }
    __forceinline void rlock(void) {
	uint_fast32_t expected = state.load(std::memory_order_relaxed);

	while (true) {
	    if (UNLIKELY(expected & (WRITE_BIT | UPGRADE_BIT))) {
		THREAD_YIELD();
		expected = state.load(memory_order_relaxed);
	    } else {
		if (LIKELY(state.compare_exchange_weak(expected, expected + 1,
		    memory_order_acquire, memory_order_relaxed)))
		    return;
	    }
	}
    }
    __forceinline bool rtrylock(void) {
	uint_fast32_t expected = state.load(memory_order_relaxed);

	while (true) {
	    if (UNLIKELY(expected & (WRITE_BIT | UPGRADE_BIT)))
		return false;
	    if (LIKELY(state.compare_exchange_weak(expected, expected + 1,
		memory_order_acquire, memory_order_relaxed)))
		return true;
	}
    }
    __forceinline void runlock(void) {
	state.fetch_sub(1, memory_order_release);
    }
    bool tryuplock(void) {
	uint_fast32_t expected = 1;

	return state.compare_exchange_strong(expected, WRITE_BIT,
	    memory_order_acquire, memory_order_relaxed);
    }
    __forceinline void wlock(void) {
	uint_fast32_t expected = 0;

	while (!state.compare_exchange_weak(expected, WRITE_BIT,
	    memory_order_acquire, memory_order_relaxed)) {
	    expected = 0;
	    THREAD_YIELD();
	}
    }
    __forceinline bool wtrylock() {
	uint_fast32_t expected = 0;

	return state.compare_exchange_strong(expected, WRITE_BIT,
	    memory_order_acquire, memory_order_relaxed);
    }
    __forceinline void wunlock(void) { state.store(0, memory_order_release); }

private:
    atomic_uint_fast32_t state;

    static constexpr uint_fast32_t UPGRADE_BIT = 1U << 30;
    static constexpr uint_fast32_t WRITE_BIT = 1U << 31;
};

typedef LockerTemplate<SpinRWLock, &SpinRWLock::rlock, &SpinRWLock::runlock>
    SpinRLocker;
typedef LockerTemplate<SpinRWLock, &SpinRWLock::wlock, &SpinRWLock::wunlock>
    SpinWLocker;
typedef FastLockerTemplate<SpinRWLock, &SpinRWLock::rlock, &SpinRWLock::runlock>
    FastSpinRLocker;
typedef FastLockerTemplate<SpinRWLock, &SpinRWLock::wlock, &SpinRWLock::wunlock>
    FastSpinWLocker;

typedef LockerTemplate<RWLock, &RWLock::rlock, &RWLock::runlock> RLocker;
typedef LockerTemplate<RWLock, &RWLock::wlock, &RWLock::wunlock> WLocker;
typedef FastLockerTemplate<RWLock, &RWLock::rlock, &RWLock::runlock> FastRLocker;
typedef FastLockerTemplate<RWLock, &RWLock::wlock, &RWLock::wunlock> FastWLocker;

/* Fast reference counter class */
class BLISTER RefCount: nocopy {
public:
    explicit RefCount(uint init = 1): cnt(init) {}

    __forceinline operator bool(void) const { return referenced(); }
    __forceinline bool referenced(void) const { return cnt != 0; }

    __forceinline void reference(void) { ++cnt; }
    __forceinline bool release(void) { return --cnt == 0; }

private:
    atomic_uint cnt;
};

/* Last-in-first-out queue useful for thread pools */
class BLISTER Lifo {
public:
    class Waiting: nocopy {
    public:
	Waiting *next;
	Semaphore sema4;

	Waiting(): next(NULL) {}
    };

    Lifo(): head(NULL), sz(0) { (void)unused;}
    ~Lifo() { close(); }

    // Fast-path checks without lock for common case
    __forceinline operator bool(void) const {
        return sz.load(memory_order_relaxed);
    }
    __forceinline bool empty(void) const {
        return !sz.load(memory_order_relaxed);
    }
    __forceinline uint size(void) const {
        return sz.load(memory_order_relaxed);
    }
    __forceinline uint broadcast(void) {
	Waiting *w, *ww;
	uint ret;

	if (UNLIKELY(!sz.load(memory_order_acquire)))
	    return 0;
	lck.lock();
	w = head;
	head = NULL;
	ret = sz.load(memory_order_relaxed);
	sz.store(0, memory_order_relaxed);
	lck.unlock();
	while (LIKELY(w)) {
	    ww = w->next;
	    w->sema4.set();
	    w = ww;
	}
	return ret;
    }
    bool close(void) { broadcast(); return true; }
    bool open(void) {
	head = NULL;
	sz.store(0, memory_order_relaxed);
	return true;
    }
    __forceinline uint set(uint count = 1) {
	uint_fast16_t released;
	Waiting *w, *ww, *www;

	if (UNLIKELY(!sz.load(memory_order_acquire)))
	    return count;
	released = 0;
	lck.lock();
	for (w = ww = head; w && count; w = w->next) {
	    --count;
	    ++released;
	}
	head = w;
	sz.fetch_sub(released, memory_order_relaxed);
	lck.unlock();
	while (LIKELY(ww != w)) {
	    www = ww->next;
	    ww->sema4.set();
	    ww = www;
	}
	return count;
    }
    __forceinline bool wait(Waiting &w, ulong msec = INFINITE) {
	lck.lock();
	w.next = head;
	head = &w;
	sz.fetch_add(1, memory_order_relaxed);
	lck.unlock();
	if (UNLIKELY(!w.sema4.wait(msec))) {
	    lck.lock();
	    for (Waiting **ww = &head; *ww; ww = &(*ww)->next) {
		if (*ww == &w) {
		    *ww = w.next;
		    sz.fetch_sub(1, memory_order_relaxed);
		    lck.unlock();
		    return false;
		}
	    }
	    lck.unlock();
	}
	return true;
    }

private:
    alignas(64) Waiting *head;
    mutable SpinLock lck;
    atomic_uint_fast16_t sz;
    char unused[64 - sizeof (Waiting *) - sizeof (SpinLock) -
	sizeof (atomic_uint)];
};

// Thread routines
class Thread;
class ThreadGroup;

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
    static atomic_ulong next_id;

    static int init(void *thisp);
    friend class Thread;
};

template<class C>
void ThreadLocalClass<C>::erase(void) {
    C *c = (C *)tls_get(key);

    tls_set(key, 0);
    Thread::thread_cleanup(c, NULL);
}

template<class C>
C &ThreadLocalClass<C>::get(void) const {
    C *c = (C *)tls_get(key);

    if (UNLIKELY(!c)) {
	c = new C;
	tls_set(key, c);
	Thread::thread_cleanup(c, cleanup);
    }
    return *c;
}

#endif
#endif // Thread_h
