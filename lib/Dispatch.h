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

#ifndef Dispatch_h
#define Dispatch_h

#include <set>
#include <unordered_map>
#include <unordered_set>
#include "Config.h"
#include "Log.h"
#include "Socket.h"
#include "Thread.h"

#ifdef _WIN32
/*
 * select() is faster on Windows for normal fd set sizes
 #define DSP_WIN32_ASYNC
 */
#define DSP_POLL
#elif defined(__linux__)
#define DSP_EPOLL
#elif defined(BSD_BASE)
#define DSP_KQUEUE
#elif defined(__sun__)
#define DSP_DEVPOLL
#else
#define DSP_POLL
#endif

#define DSP_DECLARE(cls, func) \
    static __forceinline void func(DispatchObj *obj) { \
	((cls *)obj)->func(); \
    } \
    void func(void)

// Dispatch messages
enum DispatchMsg {
    DispatchRead, DispatchWrite, DispatchReadWrite, DispatchAccept,
    DispatchConnect, DispatchClose, DispatchTimeout, DispatchNone
};

using dspflag_t = uint_fast32_t;

// Dispatch flags
enum DispatchFlag: dspflag_t {
    DSP_Grouped = 0x0001,
    DSP_Detached = 0x0002,
    DSP_Connecting = 0x0004,
    DSP_Scheduled = 0x0008,
    DSP_Ready = 0x0010,
    DSP_ReadyGroup = 0x0020,
    DSP_Active = 0x0040,
    DSP_Freed = 0x0080,
    DSP_Acceptable = 0x0100,
    DSP_Readable = 0x0200,
    DSP_Writeable = 0x0400,
    DSP_Closeable = 0x0800,
    DSP_SelectAccept = 0x1000,
    DSP_SelectRead = 0x2000,
    DSP_SelectWrite = 0x4000,
    DSP_SelectClose = 0x8000,
    DSP_Polled = 0x10000,
    DSP_Armed = 0x20000
};

class DispatchObj;
class DispatchSocket;
class DispatchTimer;

using dspcb_t = void (*)(DispatchObj *);

class BLISTER Dispatcher: public ThreadGroup {
public:
    using dspsema4_t = LifoSemaphore;
    explicit Dispatcher(const Config &config);

    const Config &config(void) const { return cfg; }

    [[nodiscard]] bool start(uint maxthreads = 100, uint stacksz = 0);

protected:
    int onStart(void) override;
    void onStop(void) override;

    const Config &cfg;

private:
#if defined(DSP_WIN32_ASYNC) || defined(DSP_DEVPOLL) || defined(DSP_POLL)
    using socketmap = unordered_map<socket_t, DispatchSocket *>;

    __forceinline DispatchSocket *get_socket(socket_t fd) const {
	auto it = smap.find(fd);

	return it == smap.end() ? nullptr : it->second;
    }
#endif
    // Lock optimized SizedObjectList counter
    struct ObjectListAtomicSize {
	__forceinline void inc(void) { n.fetch_add(1, memory_order_seq_cst); }
	__forceinline void dec(void) {
	    n.store(n.load(memory_order_relaxed) - 1, memory_order_relaxed);
	}
	__forceinline void add(uint v) { n.fetch_add(v, memory_order_relaxed); }
	__forceinline void zero(void) { n.store(0, memory_order_relaxed); }
	__forceinline uint get(void) const {
	    return n.load(memory_order_seq_cst);
	}

	atomic<uint> n = 0;
    };

    class DLL_LOCAL TimerSet: ::nocopy {
    public:
	struct compare {
	    bool operator ()(const DispatchTimer *a, const DispatchTimer *b)
		const;
	};

	using sorted_timerset = ::set<DispatchTimer *, compare>;
	using unsorted_timerset = unordered_set<DispatchTimer *,
	    ptrhash<DispatchTimer>>;

	TimerSet() = default;

	bool empty(void) const { return unsorted.empty(); }
	msec_t half(void) const { return split; }
	DispatchTimer *peek(void) const {
	    auto it = sorted.cbegin();

	    return it == sorted.cend() ? nullptr : *it;
	}

	void clear(void) {
	    sorted.clear();
	    unsorted.clear();
	}
	void erase(DispatchTimer &dt);
	DispatchTimer *claim(uint u) {
	    return firing[u].exchange(nullptr, memory_order_acq_rel);
	}
	uint get(msec_t when, DispatchTimer **batch, uint maxcnt);
	void insert(DispatchTimer &dt) { unsorted.insert(&dt); }
	DispatchTimer *reorder(msec_t when);
	void set(DispatchTimer &dt, msec_t when);

	static constexpr uint BATCHSZ = 32;

    private:
	atomic<DispatchTimer *> firing[BATCHSZ] = {};
	uint nfiring = 0;
	sorted_timerset sorted;
	msec_t split = 0;
	unsorted_timerset unsorted;
    };

    friend class DispatchObj;
    void addReady(DispatchObj &obj, dspcb_t cb, bool hipri, DispatchMsg reason);
    void adopt(DispatchObj &obj);
    void cancelReady(DispatchObj &ob, bool del = false);
    void disown(DispatchObj &obj);
    void removeReady(DispatchObj &obj);
    void ready(DispatchObj &obj, bool hipri = false);

    friend class DispatchTimer;
    void addTimer(DispatchTimer &dt);
    void cancelTimer(DispatchTimer &dt, bool del = false);
    void eraseTimer(DispatchTimer &dt);
    void removeTimer(DispatchTimer &dt);
    void setTimer(DispatchTimer &dt, dspcb_t cb, ulong tm);

    friend class DispatchSocket;
    void cancelSocket(DispatchSocket &ds, bool del = false);
    void pollSocket(DispatchSocket &ds, dspcb_t cb, ulong timeout,
	DispatchMsg msg);
    void unmapSocket(DispatchSocket &ds, socket_t fd);

    void cleanup(void);
    bool exec(void);
    void handleEvents(const void *evts, uint cnt);
    DispatchTimer *handleTimers(msec_t now);
    void reap(DispatchObj &obj);
    void reclaim(void);
    void reset(void);
    int run(void);
    void wake(void);
    void wakeup(ulong msec);
    void worker() {
	Thread *t;

	workers++;
	t = new Thread();
	t->start(worker, this, stacksz, this);
	while ((t = wait(0)) != nullptr)
	    delete t;
    }
    static int worker(void *param);

    uint maxthreads = 0;
    atomic_bool shutdown = true;
    uint stacksz = 0;
    atomic_uint_fast32_t workers = 0;
#ifdef DSP_WIN32_ASYNC
    HWND wnd = nullptr;
    static uint socketmsg;
    static constexpr int DSP_TimerID = 1;
#elif defined(DSP_POLL)
    Socket rsock, wsock;
    SocketSet rset, wset;
#else
    int evtfd = -1;
#ifdef DSP_EPOLL
    int wfd = -1;
#endif
#endif
    alignas(64) SpinLock olock;
    atomic_bool polling = false;
    SizedObjectList<DispatchObj, ObjectListAtomicSize> rlist;
    ObjectList<DispatchObj> zlist;
    atomic_bool zpending = false;
    unordered_set<DispatchObj *> owned;
    alignas(64) atomic_uint_fast32_t scanning = 0;
    dspsema4_t sema4;
    alignas(64) SpinLock tlock;
    atomic<msec_t> cache = 0;
    msec_t due;
#ifdef DSP_WIN32_ASYNC
    atomic_ulong interval;
#endif
    TimerSet timers;
#if defined(DSP_WIN32_ASYNC) || defined(DSP_DEVPOLL) || defined(DSP_POLL)
    alignas(64) SpinLock slock;
    socketmap smap;
#endif
};

// base classes for event objects
class BLISTER DispatchObj: public ObjectList<DispatchObj>::Node {
public:
    using DispatchObjCB = dspcb_t;

    struct child_t {};
    static constexpr child_t child{};

    explicit DispatchObj(Dispatcher &d, DispatchObjCB cb = nullptr): dcb(cb),
	dspr(d), flags(0) {}
    DispatchObj(child_t, DispatchObj &parent, DispatchObjCB cb = nullptr);
    virtual ~DispatchObj();

    Dispatcher &dispatcher(void) const { return dspr; }
    bool error(void) const {
	return msg == DispatchClose || msg == DispatchTimeout;
    }
    DispatchMsg reason(void) const { return msg; }

    bool grouped(const DispatchObj &obj) const {
	return group && obj.group == group;
    }
    // hand ownership to the dispatcher which erases it at shutdown
    void detach(void) { dspr.adopt(*this); }
    void ready(DispatchObjCB cb = nullptr, bool hipri = false,
	DispatchMsg reason = DispatchNone) {
	dspr.addReady(*this, cb, hipri, reason);
    }
    virtual void cancel(void) { dspr.cancelReady(*this); }
    virtual void erase(void) { dspr.cancelReady(*this, true); }

protected:
    void callback(DispatchObjCB cb) { if (cb) dcb = cb; }

    DispatchObjCB dcb;
    Dispatcher &dspr;
    dspflag_t flags;
    DispatchMsg msg = DispatchNone;

private:
    class BLISTER Group: nocopy {
    public:
	Group() = default;

	ObjectList<DispatchObj> glist;
	RefCount refcount;
	bool active = false;

	Group &add(void) { refcount.reference(); return *this; }
    };

    Group *group = nullptr;

    DispatchObj &operator =(const DispatchObj &obj) = delete;
    friend class Dispatcher;
};

// handle objects with timeouts
class BLISTER DispatchTimer: public DispatchObj {
public:
    static constexpr ulong DSP_NEVER = (ulong)-1;
    static constexpr ulong DSP_PREVIOUS = (ulong)-2;
    static constexpr msec_t DSP_NEVER_DUE = (msec_t)-1;
    static constexpr msec_t DSP_FIRING = DSP_NEVER_DUE - 1;

    DispatchTimer(const DispatchTimer &dt): DispatchTimer((DispatchObj &)dt) {}
    explicit DispatchTimer(Dispatcher &d, ulong msec = DSP_NEVER):
	DispatchObj(d), to(msec) { init(); }
    DispatchTimer(Dispatcher &d, ulong msec, DispatchObjCB cb):
	DispatchObj(d) { init(); timeout(cb, msec); }
    explicit DispatchTimer(DispatchObj &parent, ulong msec = DSP_NEVER):
	DispatchObj(child, parent), to(msec) { init(); }
    DispatchTimer(DispatchObj &parent, ulong msec, DispatchObjCB cb):
	DispatchObj(child, parent) {
	init();
	timeout(cb, msec);
    }
    virtual ~DispatchTimer() { dspr.eraseTimer(*this); }

    msec_t expires(void) const { return due(); }
    ulong timeout(void) const { return to; }

    void timeout(DispatchObjCB cb, ulong msec = DSP_PREVIOUS) {
	if (msec != DSP_PREVIOUS)
	    to = msec;
	dspr.setTimer(*this, cb, to);
    }
    void cancel(void) override { dspr.cancelTimer(*this); }
    void erase(void) override { dspr.cancelTimer(*this, true); }

protected:
    ulong to = 0;

private:
    __forceinline msec_t due(void) const {
	return tm.load(memory_order_relaxed);
    }
    __forceinline void due(msec_t msec) {
	tm.store(msec, memory_order_relaxed);
    }
    void init(void) { dspr.addTimer(*this); }

    atomic<msec_t> tm = DSP_NEVER_DUE;

    friend class Dispatcher;
};

// handle socket events
// NOLINTNEXTLINE(misc-multiple-inheritance)
class BLISTER DispatchSocket: public DispatchTimer, public Socket {
public:
    explicit DispatchSocket(Dispatcher &d, int type = SOCK_STREAM, ulong msec =
	DSP_NEVER): DispatchTimer(d, msec), Socket(type) {}
    DispatchSocket(const DispatchSocket &) = delete;
    DispatchSocket(Dispatcher &d, const Socket &s, ulong msec = DSP_NEVER):
	DispatchTimer(d, msec), Socket(s) {}
    explicit DispatchSocket(DispatchObj &parent, int type = SOCK_STREAM, ulong
	msec = DSP_NEVER): DispatchTimer(parent, msec), Socket(type) {}
    DispatchSocket(DispatchObj &parent, const Socket &s, ulong msec =
	DSP_NEVER): DispatchTimer(parent, msec), Socket(s) {}
    virtual ~DispatchSocket() { DispatchSocket::cancel(); }

    void cancel(void) override { dspr.cancelSocket(*this); }
    void erase(void) override { dspr.cancelSocket(*this, true); }
    // NOLINTNEXTLINE(bugprone-derived-method-shadowing-base-method)
    bool close(void) {
	dspr.unmapSocket(*this, fd());
	return Socket::close();
    }
    int read(void *buf, uint len) {
	return drained(Socket::read(buf, len), len);
    }
    int read(void *buf, uint len, Sockaddr &sa) {
	return drained(Socket::read(buf, len, sa), len);
    }
    template<class C> int read(C &c) { return read(&c, sizeof (c)); }
    long readv(iovec *iov, int count) {
	return drained(Socket::readv(iov, count), iovlen(iov, count));
    }
    long readv(iovec *iov, int count, Sockaddr &sa) {
	return drained(Socket::readv(iov, count, sa), iovlen(iov, count));
    }

protected:
    void poll(DispatchObjCB cb, ulong msec, DispatchMsg reason) {
	if (msec != DSP_PREVIOUS)
	    to = msec;
	dspr.pollSocket(*this, cb, to, reason);
    }

#ifdef DSP_EPOLL
    uint32_t evmask = 0;
#endif
    bool mapped = false;
    bool rdrain = false;

private:
    template<typename N> __forceinline N drained(N n, ulong len) {
	rdrain = n == 0 ? blocked() : n > 0 && (ulong)n < len && stream();
	return n;
    }
    static ulong iovlen(const iovec *iov, int count) {
	ulong len = 0;

	while (count-- > 0)
	    len += (ulong)iov++->iov_len;
	return len;
    }

    friend class Dispatcher;
};

class BLISTER DispatchIOSocket: public DispatchSocket {
public:
    using DispatchSocket::DispatchSocket;

    void acceptable(DispatchObjCB cb = nullptr, ulong msec = DSP_PREVIOUS) {
	poll(cb, msec, DispatchAccept);
    }
    void closeable(DispatchObjCB cb = nullptr, ulong msec = 15000) {
	poll(cb, msec, DispatchClose);
    }
    void readable(DispatchObjCB cb = nullptr, ulong msec = DSP_PREVIOUS) {
	poll(cb, msec, DispatchRead);
    }
    void writeable(DispatchObjCB cb = nullptr, ulong msec = DSP_PREVIOUS) {
	poll(cb, msec, DispatchWrite);
    }
    void rwable(DispatchObjCB cb = nullptr, ulong msec = DSP_PREVIOUS) {
	poll(cb, msec, DispatchReadWrite);
    }
};

class BLISTER DispatchClientSocket: public DispatchIOSocket {
public:
    using DispatchIOSocket::DispatchIOSocket;

    void connect(const Sockaddr &addr, ulong msec = 30000, DispatchObjCB cb =
	connected);

protected:
    virtual void onConnect(void) = 0;

private:
    DSP_DECLARE(DispatchClientSocket, connected);
};

class BLISTER DispatchServerSocket: public DispatchIOSocket {
public:
    using DispatchIOSocket::DispatchIOSocket;

    virtual void start(void) = 0;
};

class BLISTER DispatchListenSocket: public DispatchSocket {
public:
    using DispatchSocket::DispatchSocket;
    DispatchListenSocket(Dispatcher &d, const Sockaddr &addr,
	int type = SOCK_STREAM, bool reuse = true, int backlog = SOCK_BACKLOG,
	DispatchObjCB cb = connection);

    const Sockaddr &address(void) const { return addr; }
    [[nodiscard]] bool listen(const Sockaddr &addr, bool reuse = true, int
	backlog = SOCK_BACKLOG, DispatchObjCB cb = nullptr, bool start = true);
    [[nodiscard]] bool listen(const tchar *addrstr, bool reuse = true, int
	backlog = SOCK_BACKLOG, DispatchObjCB cb = nullptr, bool start = true) {
	return listen(Sockaddr(addrstr), reuse, backlog, cb, start);
    }
    void relisten(void) { poll(nullptr, DSP_PREVIOUS, DispatchAccept); }

protected:
    virtual void onAccept(Socket &sock) = 0;

    Sockaddr addr;

private:
    DSP_DECLARE(DispatchListenSocket, connection);
};

template<class D, class C>
class SimpleDispatchListenSocket: public DispatchListenSocket {
public:
    explicit SimpleDispatchListenSocket(D &d, int type = SOCK_STREAM,
	bool detached = true): DispatchListenSocket(d, type) {
	if (detached)
	    detach();
    }

    bool listen(const Sockaddr &sa, bool enable = true) {
	const Config &cfg = dspr.config();
	int backlog = cfg.get(T("socket.backlog"), SOCK_BACKLOG, C::section());
	bool reuse = cfg.get(T("socket.reuse"), true, C::section());

	if (!cfg.get(T("enable"), enable, C::section())) {
	    return true;
	} else if (!DispatchListenSocket::listen(sa, reuse, backlog)) {
	    dloge(Log::mod(C::section()), Log::cmd(T("listen")),
		Log::kv(T("addr"), sa.str()), Log::error(errstr()));
	    return false;
	}
	dlogi(Log::mod(C::section()), Log::cmd(T("listen")), Log::kv(T("addr"),
	    sa.str()));
	return true;
    }
    bool listen(const tchar *host = nullptr, bool enable = true) {
	// cppcheck-suppress nullPointerDefaultArg
	tstring s(dspr.config().get(T("host"), host,	// NOSONAR: null ok
	    C::section()));

	return listen(Sockaddr(s.c_str()), enable);
    }

protected:
    void onAccept(Socket &sock) override {
	C *c = new(nothrow) C((D &)dspr, sock);

	if (c == nullptr) {
	    sock.close();
	} else {
	    c->detach();
	    start(*c);
	}
    }

    virtual void start(C &ssock) { ssock.start(); }
};

/*
 * AsyncCondvar acts like a std::condition_variable, but queues a callback
 * to be called instead of blocking the thread. The lock must be held
 * but wait() returns with it unlocked. A Waiter must not be destroyed or
 * cancelled while its thread holds the lock. A Waiter may wait on any
 * AsyncCondvar that shares its lock
 */
class BLISTER AsyncCondvar: nocopy {
public:
    class BLISTER Waiter: public DispatchObj {
    public:
	explicit Waiter(AsyncCondvar &a): DispatchObj(a.dispatcher()),
	    lck(a.lck), ac(&a), link(*this) {}
	Waiter(AsyncCondvar &a, DispatchObj &parent): DispatchObj(child,
	    parent), lck(a.lck), ac(&a), link(*this) {}
	~Waiter() override { unwait(); }

	void wait(DispatchObjCB cb) {
	    callback(cb);
	    ac->wait(*this);
	}
	void wait(DispatchObjCB cb, AsyncCondvar &cv) {
	    callback(cb);
	    cv.wait(*this);
	}
	void cancel(void) override {
	    unwait();
	    DispatchObj::cancel();
	}

    private:
	// own node so a queued ready() cannot corrupt the waiter list
	struct Link: ObjectList<Link>::Node {
	    explicit Link(Waiter &w): waiter(w) {}

	    Waiter &waiter;
	};

	void unwait(void) {
	    lck.lock();
	    if (waiting) {
		waiting = false;
		ac->waiters.pop(link);
	    }
	    lck.unlock();
	}

	Lock &lck;
	AsyncCondvar *ac;		// guarded by lck
	Link link;
	bool waiting = false;

	friend class AsyncCondvar;
    };

    AsyncCondvar(Dispatcher &d, Lock &l): dspr(d), lck(l) {}

    __forceinline explicit operator bool(void) const { return !waiters.empty(); }

    __forceinline Dispatcher &dispatcher(void) const { return dspr; }
    __forceinline uint size(void) const { return waiters.size(); }
    __forceinline Waiter *peek(void) const {
	Waiter::Link *l = waiters.peek();

	return l ? &l->waiter : nullptr;
    }

    void broadcast(void) {
	while (waiters)
	    wake();
    }
    // move all waiters to another AsyncCondvar sharing the same held lock
    void requeue(AsyncCondvar &other) {
	if (!waiters)
	    return;
	for (const Waiter::Link &l : waiters)
	    l.waiter.ac = &other;
	other.waiters.push_back(waiters);
	if (other.signaled) {
	    other.signaled = false;
	    other.set();
	}
    }
    uint set(uint count = 1) {
	uint woken = 0;

	while (count && waiters) {
	    wake();
	    --count;
	    ++woken;
	}
	signaled = !woken;
	return woken;
    }
    void wait(Waiter &waiter) {
	if (signaled) {
	    signaled = false;
	    lck.unlock();
	    waiter.ready();
	} else {
	    if (!waiter.waiting) {
		waiter.waiting = true;
		waiter.ac = this;
		waiters.push_back(waiter.link);
	    }
	    lck.unlock();
	}
    }

private:
    void wake(void) {
	Waiter &waiter = waiters.pop_front()->waiter;

	waiter.waiting = false;
	waiter.ready();
    }

    Dispatcher &dspr;
    Lock &lck;
    atomic_bool signaled = false;
    SizedObjectList<Waiter::Link> waiters;
};

#endif // Dispatch_h
