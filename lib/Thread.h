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

#ifndef Thread_h
#define Thread_h

#ifndef stdapi_h
#include "stdapi.h"
#endif

#ifdef _WIN32
#include <process.h>
#include <Windows.h>

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
#define tls_set(k, v)		TlsSetValue(k, (void *)v)

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
#elif defined(__ARM_ARCH)
#define THREAD_PAUSE()  	asm volatile("yield")
#endif
#define THREAD_YIELD()		sched_yield()

typedef pthread_key_t tlskey_t;

#define tls_init(k)		ZERO(k); pthread_key_create(&k, NULL)
#define tls_free(k)		pthread_key_delete(k)
#define tls_get(k)		pthread_getspecific(k)
#define tls_set(k, v)		pthread_setspecific(k, v)
#endif

#if defined(__ARM_ARCH)
#define SPIN_LIMIT		128
#elif defined(__AVX2__)
#define SPIN_LIMIT		16
#elif defined(THREAD_PAUSE)
#define SPIN_LIMIT		64
#else
#define SPIN_LIMIT		0
#endif

#define THREAD_ISSELF(x)	THREAD_EQUAL(x, THREAD_ID())

#ifdef __cplusplus

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <semaphore>
#include <set>
#include <shared_mutex>
#include <unordered_map>

#ifdef THREAD_PAUSE
// exponential spin backoff with constant-fold optimization
static __forceinline void spin_backoff(uint &limit, uint spins) {
    for (uint u = 0; u < limit; ++u)
	THREAD_PAUSE();
    if (limit < spins)
	limit += limit;
    else
	THREAD_YIELD();
}

static __forceinline void spin_release(bool pause = true, bool = false) {
    if (pause)
	THREAD_PAUSE();
    else
	THREAD_YIELD();
}
#else
static __forceinline void spin_backoff(uint &, uint) { THREAD_YIELD(); }

static __forceinline void spin_release(bool = true, bool yield = false) {
    if (yield)
	THREAD_YIELD();
}
#endif

/*
 * The DLLibrary class loads shared libraries and dynamically fetches function
 * pointers. Do not specify file extensions in the constructor
 */
class BLISTER DLLibrary: nocopy {
public:
    explicit DLLibrary(const tchar *dll = nullptr): hdl(0) { open(dll); }
    ~DLLibrary() { close(); }

    operator void *(void) const { return hdl; }
    friend bool operator !(const DLLibrary &dll) { return dll.hdl == nullptr; }

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
    static uint count(void) { static const uint n = init(); return n; }

private:
    static uint init(void);
};

// Thread local storage for simple types
template<class C>
class BLISTER ThreadLocal: nocopy {
public:
    // cppcheck-suppress useInitializationList
    ThreadLocal() { tls_init(key); }
    ~ThreadLocal() { tls_free(key); }

    __forceinline ThreadLocal &operator =(C c) { set(c); return *this; }
    // cppcheck-suppress returnDanglingLifetime
    __forceinline C *operator ->(void) const { return &get(); }
    explicit __forceinline operator bool(void) const {
	return tls_get(key) != nullptr;
    }
    explicit __forceinline operator C() const { return (C)tls_get(key); }

    __forceinline C get(void) const { return (C)tls_get(key); }
    __forceinline void set(const C c) const { tls_set(key, c); }

protected:
    tlskey_t key;
};

// Thread local storage for classes with proper destruction when theads exit
using ThreadLocalFree = void (*)(void *data);

/*
 * Thread synchronization classes
 *
 * Condvar: condition variable around a Lock
 * Lock: unique lock
 * RWLock: shared lock
 * SpinLock: fastest unfair spinning lock
 * SpinRWLock: fast spinning shared lock with r->w tryuplock
 * TicketLock: fastest fair spinning lock
 * UnfairLock: fastest unfair lock
 *
 * RAII locking templates
 */
template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() = &C::unlock>
class BLISTER FastLockerTemplate: nocopy {
public:
    explicit __forceinline FastLockerTemplate(C &lock): lck(lock) {
	invoke(LOCK, lck);
    }
    __forceinline ~FastLockerTemplate() { invoke(UNLOCK, lck); }

    __forceinline void relock(void) {
	invoke(UNLOCK, lck);
	THREAD_YIELD();
	invoke(LOCK, lck);
    }

private:
    C &lck;
};

template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() = &C::unlock>
class BLISTER FastUnlockerTemplate: nocopy {
public:
    explicit __forceinline FastUnlockerTemplate(C &lock): lck(lock) {
	invoke(UNLOCK, lck);
    }
    __forceinline ~FastUnlockerTemplate() { invoke(LOCK, lck); }

private:
    C &lck;
};

template<class C, void (C::*LOCK)() = &C::lock, void (C::*UNLOCK)() =
    &C::unlock>
class BLISTER LockerTemplate: nocopy {
public:
    explicit __forceinline LockerTemplate(C &lock, bool lockit = true):
	lck(lock), locked(lockit) {
	if (LIKELY(lockit))
	    invoke(LOCK, lck);
    }
    __forceinline ~LockerTemplate() { if (LIKELY(locked)) invoke(UNLOCK, lck); }

    explicit __forceinline operator bool(void) const { return locked; }

    __forceinline void lock(void) {
	if (LIKELY(!locked)) {
	    locked = true;
	    invoke(LOCK, lck);
	}
    }
    __forceinline void relock(void) {
	if (LIKELY(locked)) {
	    invoke(UNLOCK, lck);
	    THREAD_YIELD();
	} else {
	    locked = true;
	}
	invoke(LOCK, lck);
    }
    __forceinline void unlock(void) {
	if (LIKELY(locked)) {
	    invoke(UNLOCK, lck);
	    locked = false;
	}
    }

private:
    C &lck;
    bool locked;
};

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
	return exchange(true, order);
    }
};
#endif

using Lock = mutex;
using FastLocker = FastLockerTemplate<Lock>;
using Locker = LockerTemplate<Lock>;

using RWLock = shared_mutex;
using FastRLocker = FastLockerTemplate<RWLock, &RWLock::lock_shared,
    &RWLock::unlock_shared>;
using FastWLocker = FastLockerTemplate<RWLock, &RWLock::lock, &RWLock::unlock>;
using RLocker = LockerTemplate<RWLock, &RWLock::lock_shared,
    &RWLock::unlock_shared>;
using WLocker = LockerTemplate<RWLock, &RWLock::lock, &RWLock::unlock>;

class BLISTER SpinLock: nocopy {
public:
    explicit SpinLock(uint lmt = SPIN_LIMIT): spins(Processor::count() == 1 ?
	0 : lmt) {}
    __forceinline __no_sanitize_thread void lock(void) {
	while (UNLIKELY(!try_lock())) {
	    uint limit = spins > 0;

	    do {
		spin_backoff(limit, spins);
	    } while (test_lock());
	}
    }
    __forceinline bool test_lock(void) const {
	return lck.test(memory_order_relaxed);
    }
    __forceinline __no_sanitize_thread bool try_lock(void) {
	return !lck.test_and_set(memory_order_acquire);
    }
    __forceinline __no_sanitize_thread void unlock(void) {
	lck.clear(memory_order_release);
    }

private:
    alignas(64) atomic_bit lck;
    const uint spins;
};

using FastSpinLocker = FastLockerTemplate<SpinLock>;
using FastSpinUnlocker = FastUnlockerTemplate<SpinLock>;
using SpinLocker = LockerTemplate<SpinLock>;

class BLISTER SpinRWLock: nocopy {
public:
    explicit SpinRWLock(uint lmt = SPIN_LIMIT): state(0),
	spins(Processor::count() == 1 ? 0 : lmt) {}

    __forceinline void downlock(void) { state.store(1, memory_order_release); }
    __forceinline void lock(void) {
	uint_fast32_t expected = 0;

	while (!state.compare_exchange_weak(expected, WRITE_BIT,
	    memory_order_acquire, memory_order_relaxed)) {
	    uint limit = spins > 0;

	    do {
		spin_backoff(limit, spins);
	    } while (state.load(memory_order_relaxed) != 0);
	    expected = 0;
	}
    }
    __forceinline void lock_shared(void) {
	do {
	    uint_fast32_t expected = state.load(memory_order_relaxed);

	    if (UNLIKELY(expected & WRITE_BIT)) {
		uint limit = spins > 0;

		do {
		    spin_backoff(limit, spins);
		} while (state.load(memory_order_relaxed) & WRITE_BIT);
	    } else if (LIKELY(state.compare_exchange_weak(expected, expected +
		1, memory_order_acquire, memory_order_relaxed))) {
		return;
	    } else {
		spin_release();
	    }
	} while (true);
    }
    __forceinline bool try_lock(void) {
	uint_fast32_t expected = 0;

	return state.compare_exchange_strong(expected, WRITE_BIT,
	    memory_order_acquire, memory_order_relaxed);
    }
    __forceinline bool try_lock_shared(void) {
	uint_fast32_t expected = state.load(memory_order_relaxed);

	return !(expected & WRITE_BIT) && state.compare_exchange_weak(expected,
	    expected + 1, memory_order_acquire, memory_order_relaxed);
    }
    __forceinline bool try_uplock(void) {
	uint_fast32_t expected = 1;

	return state.compare_exchange_strong(expected, WRITE_BIT,
	    memory_order_acquire, memory_order_relaxed);
    }
    __forceinline void unlock(void) { state.store(0, memory_order_release); }
    __forceinline void unlock_shared(void) {
	state.fetch_sub(1, memory_order_release);
    }

private:
    alignas(64) atomic_uint_fast32_t state;
    const uint spins;

    static constexpr uint_fast32_t WRITE_BIT = 1U << 31;
};

using FastSpinRLocker = FastLockerTemplate<SpinRWLock, &SpinRWLock::lock_shared,
    &SpinRWLock::unlock_shared>;
using FastSpinWLocker = FastLockerTemplate<SpinRWLock, &SpinRWLock::lock,
    &SpinRWLock::unlock>;
using SpinRLocker = LockerTemplate<SpinRWLock, &SpinRWLock::lock_shared,
    &SpinRWLock::unlock_shared>;
using SpinWLocker = LockerTemplate<SpinRWLock, &SpinRWLock::lock,
    &SpinRWLock::unlock>;

class TicketLock: nocopy {
public:
    explicit TicketLock(uint lmt = 0): current(0), next(0), yield(lmt ? lmt :
	Processor::count() / 2) {}
    __forceinline void lock() {
	uint pos;
	uint ticket = (uint)next.fetch_add(1, memory_order_relaxed);

	while ((pos = ticket - (uint)current.load(memory_order_acquire)) != 0)
	    spin_release(LIKELY(pos < yield), true);
    }
    __forceinline bool try_lock() {
	uint_fast16_t n = next.load(memory_order_relaxed);

	return current.load(memory_order_acquire) == n &&
	    next.compare_exchange_strong(n, (uint_fast16_t)(n + 1),
		memory_order_acquire, memory_order_relaxed);
    }
    __forceinline void unlock() {
	// slight improvement over current.fetch_add(1, memory_order_release);
	current.store(current.load(memory_order_relaxed) + 1,
	    memory_order_release);
    }

private:
    alignas(64) atomic_uint_fast16_t current;
    alignas(64) atomic_uint_fast16_t next;
    const uint yield;
};

using FastTicketLocker = FastLockerTemplate<TicketLock>;
using FastTicketUnlocker = FastUnlockerTemplate<TicketLock>;
using TicketLocker = LockerTemplate<TicketLock>;

class BLISTER UnfairLock: nocopy {
public:
    UnfairLock(): state(0) {}
    ~UnfairLock() = default;

    __forceinline void lock(void) {
	uint32_t expected = 0;

	if (UNLIKELY(!state.compare_exchange_strong(expected, 1,
	    memory_order_acquire, memory_order_relaxed)))
	    lock_contended(expected);
    }
    __forceinline bool try_lock(void) {
	uint32_t expected = 0;

	return state.compare_exchange_strong(expected, 1,
	    memory_order_acquire, memory_order_relaxed);
    }
    __forceinline void unlock(void) {
	if (UNLIKELY(state.exchange(0, memory_order_release) != 1))
	    state.notify_one();
    }

private:
    void lock_contended(uint32_t expected) {
	if (expected == 2 || state.exchange(2, memory_order_acquire) != 0) {
	    do {
		state.wait(2, memory_order_relaxed);
	    } while (state.exchange(2, memory_order_acquire) != 0);
	}
    }

    alignas(64) atomic<uint32_t> state;
};

using FastUnfairLocker = FastLockerTemplate<UnfairLock>;
using UnfairLocker = LockerTemplate<UnfairLock>;

class BLISTER Condvar: nocopy {
public:
    explicit Condvar(Lock &lck): lock(lck) {}
    ~Condvar() = default;

    __forceinline void broadcast(void) { cv.notify_all(); }
    __forceinline void set(uint count = 1) {
	while (count--)
	    cv.notify_one();
    }
    __forceinline bool wait(ulong msec = INFINITE) {
	unique_lock<mutex> ulck(lock, adopt_lock);
	bool ret;

	if (msec == INFINITE) {
	    cv.wait(ulck);		// NOSONAR
	    ulck.release();
	    return true;
	}
	ret = cv.wait_for(ulck, chrono::milliseconds(msec)) !=
	    cv_status::timeout;		// NOSONAR
	ulck.release();
	return ret;
    }

protected:
    Lock &lock;
    condition_variable cv;
};

template<class C>
class BLISTER _Semaphore: public C, nocopy {
public:
    explicit _Semaphore() : C(0) {}
    ~_Semaphore() = default;

    using C::acquire;
    using C::release;
    using C::try_acquire;
    using C::try_acquire_for;
    __forceinline bool try_acquire_for(ulong msec) {
	if (UNLIKELY(msec == INFINITE)) {
	    this->acquire();
	    return true;
	}
	return this->try_acquire_for(chrono::milliseconds(msec));
    }
};

typedef _Semaphore<binary_semaphore> FastSemaphore;
typedef _Semaphore<counting_semaphore<>> Semaphore;

/* semaphore with tracking counter */
class BLISTER CountedSemaphore: nocopy {
public:
    explicit CountedSemaphore() = default;
    ~CountedSemaphore() = default;

    explicit __forceinline operator bool(void) const { return waiting() != 0; }
    __forceinline uint waiting(void) const {
	int_fast32_t c = cnt.load(memory_order_acquire);

	return c < 0 ? (uint)-c : 0;
    }

    void acquire(void) {
	int_fast32_t c = cnt.fetch_sub(1, memory_order_acq_rel);

	if (LIKELY(c > 0))
	    return;
	sema4.acquire();
    }
    __forceinline uint broadcast(void) {
	int_fast32_t c = cnt.load(memory_order_acquire);
	uint wake = c < 0 ? (uint)-c : 0;

	return wake - release(wake);
    }
    uint release(uint count = 1) {
	int_fast32_t c;
	uint wake;

	if (UNLIKELY(!count))
	    return 0;
	c = cnt.fetch_add((int_fast32_t)count, memory_order_acq_rel);
	if (LIKELY(c >= 0))
	    return count;
	wake = (uint)-c;
	if (wake > count)
	    wake = count;
	sema4.release(wake);
	return count - wake;
    }
    bool try_acquire(void) {
	int_fast32_t c = cnt.load(memory_order_acquire);

	while (LIKELY(c > 0)) {
	    if (LIKELY(cnt.compare_exchange_weak(c, c - 1,
		memory_order_acq_rel, memory_order_acquire)))
		return true;
	}
	return false;
    }
    bool try_acquire_for(ulong msec) {
	int_fast32_t c = cnt.fetch_sub(1, memory_order_acq_rel);

	if (LIKELY(c > 0))
	    return true;
	if (LIKELY(sema4.try_acquire_for(msec)))
	    return true;
	do {
	    c = cnt.load(memory_order_acquire);
	    if (LIKELY(c >= 0))
		break;
	} while (!cnt.compare_exchange_weak(c, c + 1, memory_order_acq_rel,
	    memory_order_acquire));
	if (LIKELY(c < 0))
	    return false;
	sema4.acquire();
	return true;
    }

private:
    atomic_int_fast32_t cnt = 0;
    Semaphore sema4;
};

/* LIFO semaphore useful for thread pools */
class BLISTER LifoSemaphore: nocopy {
public:
    class Waiting: nocopy {
    public:
	atomic<Waiting *> next;
	FastSemaphore sema4;

	Waiting(): next(nullptr) {}
    };

    explicit LifoSemaphore() = default;
    ~LifoSemaphore() { broadcast(); }

    explicit __forceinline operator bool(void) const {
	return waiters.load(memory_order_acquire) != 0;
    }
    __forceinline uint waiting(void) const {
	return (uint)waiters.load(memory_order_acquire);
    }

    __forceinline void acquire(Waiting &w) {
	Waiting *h;

	waiters.fetch_add(1, memory_order_acq_rel);
	do {
	    h = head.load(memory_order_relaxed);
	    w.next.store(h, memory_order_relaxed);
	} while (!head.compare_exchange_weak(h, &w, memory_order_release,
	    memory_order_relaxed));
	w.sema4.acquire();
    }
    __forceinline void acquire(void) {
	Waiting w;

	acquire(w);
    }
    __forceinline uint broadcast(void) { return (uint)-1 - release((uint)-1); }
    __forceinline uint release(uint count = 1) {
	uint c;
	Waiting *h, *w, *ww;

	while (LIKELY(count)) {
	    h = claim(count, w, c);
	    if (UNLIKELY(!h))
		return c;
	    while (LIKELY(h != w)) {
		ww = h->next.load(memory_order_acquire);
		h->sema4.release();
		h = ww;
	    }
	    count = c;
	}
	return 0;
    }

    __forceinline bool try_acquire(void) { return false; }
    __forceinline bool try_acquire_for(Waiting &w, ulong msec) {
	Waiting *h;

	waiters.fetch_add(1, memory_order_acq_rel);
	do {
	    h = head.load(memory_order_relaxed);
	    w.next.store(h, memory_order_relaxed);
	} while (!head.compare_exchange_weak(h, &w, memory_order_release,
	    memory_order_relaxed));
	if (UNLIKELY(!w.sema4.try_acquire_for(msec))) {
	    if (LIKELY(remove(w)))
		return false;
	    w.sema4.acquire();
	}
	return true;
    }
    __forceinline bool try_acquire_for(ulong msec) {
	Waiting w;

	return try_acquire_for(w, msec);
    }

private:
    alignas(64) atomic<Waiting *> head {nullptr};
    alignas(64) atomic_uint_fast32_t waiters {0};

    __forceinline Waiting *claim(uint count, Waiting *&w, uint &remain) {
	for (;;) {
	    Waiting *h = retryhead();

	    if (UNLIKELY(!h)) {
		remain = count;
		return nullptr;
	    } else if (LIKELY(count == 1)) {
		w = h->next.load(memory_order_acquire);
		remain = 0;
	    } else {
		remain = count;
		for (w = h; w && remain; w = w->next.load(memory_order_acquire))
		    --remain;
	    }
	    if (LIKELY(head.compare_exchange_weak(h, w, memory_order_release,
		memory_order_acquire))) {
		waiters.fetch_sub(count - remain, memory_order_acq_rel);
		return h;
	    }
	}
    }
    __forceinline bool remove(Waiting &w) {
	Waiting *h, *prev, *ww;

	do {
	    prev = nullptr;
	    ww = h = head.load(memory_order_acquire);
	    while (ww && ww != &w) {
		prev = ww;
		ww = ww->next.load(memory_order_acquire);
	    }
	    if (!ww)
		return false;
	    if (prev) {
		Waiting *expected = &w;

		if (!prev->next.compare_exchange_strong(expected,
		    w.next.load(memory_order_relaxed), memory_order_release,
		    memory_order_acquire))
		    continue;
	    } else if (!head.compare_exchange_strong(h, w.next.load(
		memory_order_relaxed), memory_order_release,
		memory_order_acquire)) {
		continue;
	    }
	    waiters.fetch_sub(1, memory_order_acq_rel);
	    return true;
	} while (true);
    }
    __forceinline Waiting *retryhead(void) const {
	for (uint i = 0; ; ++i) {
	    Waiting *h = head.load(memory_order_acquire);

	    if (LIKELY(h) || LIKELY(!waiters.load(memory_order_acquire)))
		return h;
	    spin_release(LIKELY(i < 128), true);
	}
    }
};

#ifdef _WIN32
#define msleep(msec)	Sleep(msec)

class BLISTER Event: nocopy {
public:
    explicit Event(bool manual = false, bool set = false, const tchar *name =
	nullptr): hdl(nullptr) { open(manual, set, name); }
    ~Event() { close(); }

    __forceinline operator HANDLE(void) const { return hdl; }
    __forceinline HANDLE handle(void) const { return hdl; }

    bool close(void) {
	HANDLE h = hdl;

	hdl = nullptr;
	return h ? CloseHandle(h) != 0 : true;
    }
    bool open(bool manual = false, bool set = false, const tchar *name = nullptr) {
	close();
	return (hdl = CreateEvent(NULL, manual, set, name)) != nullptr;
    }
    __forceinline bool pulse(void) const { return PulseEvent(hdl) != 0; }
    __forceinline bool reset(void) const { return ResetEvent(hdl) != 0; }
    __forceinline bool set(void) const { return SetEvent(hdl) != 0; }
    __forceinline bool wait(ulong msec = INFINITE) const {
	return WaitForSingleObject(hdl, msec) != WAIT_TIMEOUT;
    }

protected:
    HANDLE hdl;
};

class BLISTER SharedSemaphore: nocopy {
public:
    explicit SharedSemaphore(const tchar *name = nullptr, uint init = 0):
	hdl(nullptr) {
	if (init != (uint)-1)
	    open(name, init);
    }
    ~SharedSemaphore() { close(); }

    __forceinline operator HANDLE(void) const { return hdl; }
    __forceinline HANDLE handle(void) const { return hdl; }

    bool close(void) {
	HANDLE h = hdl;

	hdl = nullptr;
	return h == nullptr || CloseHandle(h) != 0;
    }
    bool open(const tchar *name, uint init, bool exclusive = false) {
	close();
	hdl = CreateSemaphore(NULL, (LONG)init, LONG_MAX, name);
	if (hdl == nullptr && !exclusive)
	    hdl = OpenSemaphore(SEMAPHORE_ALL_ACCESS, 0, name);
	return hdl != nullptr;
    }
    __forceinline bool set(uint cnt = 1) const {
	return ReleaseSemaphore(hdl, (LONG)cnt, NULL) != 0;
    }
    __forceinline bool trywait(void) const {
	return WaitForSingleObject(hdl, 0) == WAIT_OBJECT_0;
    }
    __forceinline bool wait(ulong msec = INFINITE) const {
	return WaitForSingleObject(hdl, msec) == WAIT_OBJECT_0;
    }

protected:
    HANDLE hdl;
};

class BLISTER Process: nocopy {
public:
    explicit Process(HANDLE hproc): hdl(hproc) {}
    ~Process() { if (hdl) CloseHandle(hdl); }

    static int argc;
    static tchar **argv;
    static tchar **envv;
    static Process self;

    operator HANDLE(void) const { return hdl; }
    bool mask(ulong m) const { return SetProcessAffinityMask(hdl, m) != 0; }
    static Process start(tchar * const *args, const int *fds = nullptr);

private:
    HANDLE hdl;
};

#else

inline void msleep(ulong msec) {
    struct timespec ts;

    ts.tv_sec = (time_t)(msec / 1000UL);
    ts.tv_nsec = (long)((msec % 1000UL) * 1000000UL);
    nanosleep(&ts, NULL);
}

#include <sys/ipc.h>
#include <sys/sem.h>

class BLISTER SharedSemaphore: nocopy {
public:
    explicit SharedSemaphore(const tchar *name = nullptr, uint init = 0):
	hdl(-1) {
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
    bool open(const tchar *name = nullptr, uint init = 0, bool exclusive = false);
    __forceinline bool set(uint cnt = 1) {		// NOSONAR
	sembuf op;

	op.sem_num = 0;
	op.sem_op = (short)cnt;
	op.sem_flg = 0;
	return semop(op);
    }
    __forceinline bool trywait(void) {			// NOSONAR
	sembuf op;

	op.sem_num = 0;
	op.sem_op = -1;
	op.sem_flg = IPC_NOWAIT;
	return semop(op);
    }
    __forceinline bool wait(ulong msec = INFINITE) {	// NOSONAR
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

	clock_gettime(CLOCK_REALTIME_COARSE, &ts);	// NOSONAR
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

    __forceinline bool semop(sembuf &op) {		// NOSONAR
	do {
	    if (LIKELY(!::semop(hdl, &op, 1)))
		return true;
	} while (errno == EINTR);
	return false;
    }
};

#endif

// Fast reference counter class
class BLISTER RefCount: nocopy {
public:
    explicit RefCount(uint init = 1): cnt(init) {}

    explicit __forceinline operator bool(void) const { return referenced(); }
    __forceinline bool referenced(void) const { return cnt != 0; }

    __forceinline void reference(void) { ++cnt; }
    __forceinline bool release(void) { return --cnt == 0; }

private:
    atomic_uint cnt;
};

// Thread routines
class Thread;
class ThreadGroup;

using ThreadRoutine = int (*)(void *userdata);
using ThreadControlRoutine = bool (Thread::*)(void);

enum ThreadState { Init, Running, Suspended, Terminated };

// manage OS native threads
class BLISTER Thread: nocopy {
public:
    explicit Thread(thread_hdl_t handle, ThreadGroup *tg = nullptr, bool
	autoterm = false);
    Thread(void);
    virtual ~Thread();

    static Thread MainThread;

    int exitStatus(void) const { return retval; }
    thread_hdl_t getHandle(void) const { return hdl; }
    thread_id_t getId(void) const { FastLocker lkr(lck); return id; }
    ThreadState getState(void) const {
	return state.load(memory_order_acquire);
    }
    ThreadGroup *getThreadGroup(void) const { return group; }
    bool running(void) const { return getState() == Running; }
    bool terminated(void) const { return getState() == Terminated; }

    operator thread_hdl_t(void) const { return hdl; }
    friend bool operator ==(const Thread &a, const Thread &b) {
	return THREAD_EQUAL(a.id, b.id);
    }

    bool priority(int pri = 0);			// -20 -> 20
    bool start(uint stacksz = 0, ThreadGroup *tg = nullptr, bool suspend =
	false, bool autoterm = false);
    bool start(ThreadRoutine main, void *data = nullptr, uint stacksz = 0,
	ThreadGroup *tg = nullptr, bool suspend = false, bool autoterm = false);
    bool stop(void);
    bool terminate(void);
    bool wait(ulong timeout = INFINITE);
    static void thread_cleanup(void *data, ThreadLocalFree func);

protected:
    void end(int ret = 0);
    virtual int onStart(void) { return -1; }
    virtual void onStop(void) {}

private:
    using ThreadLocalMap = unordered_map<void *, ThreadLocalFree>;

    mutable Lock lck;
    Condvar cv;
    void *argument;
    bool autoterm;
    ThreadGroup *group;
    thread_hdl_t hdl;
    thread_id_t id;
    ThreadRoutine main;
    int retval;
    atomic<ThreadState> state;
    static ThreadLocal<ThreadLocalMap *> flocal;

    void clear(void);
    void thread_cleanup(void);
    static int init(void *thisp);
    static THREAD_FUNC thread_init(void *thisp);

    friend class ThreadGroup;
};

// manage a group of one or more, possibly dissimilar threads
using ThreadGroupControlRoutine = void (ThreadGroup::*)(bool);

class BLISTER ThreadGroup: nocopy {
public:
    explicit ThreadGroup(bool autoterm = true);
    virtual ~ThreadGroup();

    static ThreadGroup MainThreadGroup;

    ThreadState getState(void) const { return state; }
    thread_id_t getId(void) const { return id; }
    const Thread &getMainThread(void) const { return master; }
    size_t size(void) const { return threads.size(); }

    friend bool operator ==(const ThreadGroup &a, const ThreadGroup &b) {
	return a.id == b.id;
    }

    void priority(int pri = 0);
    void remove(Thread &thread);
    bool start(uint stacksz = 0, bool suspend = false, bool autoterm = false);
    void stop(void) { onStop(); control(Terminated, &Thread::stop); }
    void terminate(void) { control(Terminated, &Thread::terminate); }
    // only the caller may delete returned Thread
    Thread *wait(ulong msec = INFINITE, bool all = false);
    bool waitForMain(ulong msec = INFINITE) { return master.wait(msec); }

    static ThreadGroup *add(Thread &thread, ThreadGroup *tg = nullptr);

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
    atomic<ThreadState> state;
    set<Thread *> threads;
    Thread master;
    static Lock grouplck;
    static set<ThreadGroup *> groups;
    static atomic_ulong next_id;

    static int init(void *thisp);
    friend class Thread;
};

template<class C> class BLISTER ThreadLocalClass: nocopy {
public:
    // cppcheck-suppress useInitializationList
    ThreadLocalClass() { tls_init(key); }
    ~ThreadLocalClass() { tls_free(key); }

    __forceinline C &operator*(void) const { return get(); }
    __forceinline C *operator->(void) const { return &get(); }
    void erase(void) {
	C *c = (C *)tls_get(key);

	tls_set(key, 0);
	Thread::thread_cleanup(c, nullptr);
    }
    __forceinline C &get(void) const {
	C *c = (C *)tls_get(key);

	if (UNLIKELY(!c))
	    c = allocate();
	return *c;
    }
    __forceinline void set(C *c) const { tls_set(key, c); }
protected:
    tlskey_t key;

    C *allocate(void) const {
	C *c = new C;

	tls_set(key, c);
	Thread::thread_cleanup(c, cleanup);
	return c;
    }
    static void cleanup(void *data) { delete (C *)data; }
};

#endif
#endif // Thread_h
