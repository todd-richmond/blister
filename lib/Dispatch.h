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
#include <new>
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
	(static_cast<cls *>(obj))->func(); \
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
    DSP_SelectClose = 0x8000
};

class Dispatcher;

// base classes for event objects
class BLISTER DispatchObj: public ObjectList<DispatchObj>::Node {
public:
    using DispatchObjCB = void (*)(DispatchObj *);

    struct child_t {};
    static constexpr child_t child{};

    explicit DispatchObj(Dispatcher &d, DispatchObjCB cb = nullptr): dcb(cb),
	dspr(d), flags(0), msg(DispatchNone), group(nullptr) {}
    DispatchObj(child_t, DispatchObj &parent, DispatchObjCB cb = nullptr):
	dcb(cb), dspr(parent.dspr), flags(DSP_Grouped), msg(DispatchNone), group(nullptr) {
	if (!parent.group)
	    parent.group = new Group();
	group = &parent.group->add();
    }
    virtual ~DispatchObj() {
	DispatchObj::cancel();
	if (group && group->refcount.release())
	    delete group;
    }

    Dispatcher &dispatcher(void) const { return dspr; }
    bool error(void) const {
	return msg == DispatchClose || msg == DispatchTimeout;
    }
    DispatchMsg reason(void) const { return msg; }

    void detach(void) { flags |= DSP_Detached; }
    void ready(DispatchObjCB cb = nullptr, bool hipri = false, DispatchMsg reason =
	DispatchNone);
    virtual void cancel(void);
    virtual void erase(void);

protected:
    void callback(DispatchObjCB cb) { if (cb) dcb = cb; }

    DispatchObjCB dcb;
    Dispatcher &dspr;
    dspflag_t flags;
    DispatchMsg msg;

private:
    class BLISTER Group: nocopy {
    public:
	Group(): active(false) {}

	ObjectList<DispatchObj> glist;
	RefCount refcount;
	bool active;

	Group &add(void) { refcount.reference(); return *this; }
    };

    Group *group;

    DispatchObj &operator =(const DispatchObj &obj) = delete;
    friend class Dispatcher;
};

// handle objects with timeouts
class BLISTER DispatchTimer: public DispatchObj {
public:
    static constexpr ulong DSP_NEVER = (ulong)-1;
    static constexpr ulong DSP_PREVIOUS = (ulong)-2;
    static constexpr msec_t DSP_NEVER_DUE = (msec_t)-1;

    DispatchTimer(const DispatchTimer &dt): DispatchTimer((DispatchObj &)dt) {}
    explicit DispatchTimer(Dispatcher &d, ulong msec = DSP_NEVER):
	DispatchObj(d), to(msec), due(DSP_NEVER_DUE) { init(); }
    DispatchTimer(Dispatcher &d, ulong msec, DispatchObjCB cb):
	DispatchObj(d), to(0), due(DSP_NEVER_DUE) { init(); timeout(cb, msec); }
    explicit DispatchTimer(DispatchObj &parent, ulong msec = DSP_NEVER):
	DispatchObj(child, parent), to(msec), due(DSP_NEVER_DUE) { init(); }
    DispatchTimer(DispatchObj &parent, ulong msec, DispatchObjCB cb):
	DispatchObj(child, parent), to(0), due(DSP_NEVER_DUE) {
	init();
	timeout(cb, msec);
    }
    virtual ~DispatchTimer() { DispatchTimer::cancel(); }

    msec_t expires(void) const { return due; }
    ulong timeout(void) const { return to; }

    void timeout(DispatchObjCB cb, ulong msec = DSP_PREVIOUS);
    void cancel(void) override;
    void erase(void) override;

protected:
    struct compare {
	bool operator()(const DispatchTimer *a, const DispatchTimer *b) const {
	    return a->due == b->due ? a < b : a->due < b->due;
	}
    };

    ulong to;

private:
    void init(void);

    msec_t due;

    friend class Dispatcher;
};

// handle socket events
// NOLINTNEXTLINE(misc-multiple-inheritance)
class BLISTER DispatchSocket: public DispatchTimer, public Socket {
public:
    explicit DispatchSocket(Dispatcher &d, int type = SOCK_STREAM, ulong msec =
	DSP_NEVER): DispatchTimer(d, msec), Socket(type), mapped(false) {}
    DispatchSocket(Dispatcher &d, const Socket &s, ulong msec = DSP_NEVER):
	DispatchTimer(d, msec), Socket(s), mapped(false) {}
    explicit DispatchSocket(DispatchObj &parent, int type = SOCK_STREAM, ulong
	msec = DSP_NEVER): DispatchTimer(parent, msec), Socket(type),
	mapped(false) {}
    DispatchSocket(DispatchObj &parent, const Socket &s, ulong msec =
	DSP_NEVER): DispatchTimer(parent, msec), Socket(s), mapped(false) {}
    virtual ~DispatchSocket() { DispatchSocket::cancel(); }

    void cancel(void) override;
    void erase(void) override;

protected:
    void poll(DispatchObjCB cb, ulong msec, DispatchMsg msg);

    bool mapped;

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

class BLISTER Dispatcher: public ThreadGroup {
public:
    explicit Dispatcher(const Config &config);
    virtual ~Dispatcher() { stop(); }

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

    class BLISTER TimerSet: ::nocopy {
    public:
	using sorted_timerset = ::set<DispatchTimer *, DispatchTimer::compare>;
	using unsorted_timerset = unordered_set<DispatchTimer *,
	    ptrhash<DispatchTimer>>;

	TimerSet(): split(0) {}

	bool empty(void) const { return unsorted.empty(); }
	msec_t half(void) const { return split; }
	DispatchTimer *peek(void) const {
	    auto it = sorted.cbegin();

	    return it == sorted.cend() ? nullptr : *it;
	}

	void erase(void) {
	    while (!unsorted.empty())
		(*unsorted.begin())->erase();
	}
	void erase(DispatchTimer &dt) {
	    if (dt.due <= split)
		sorted.erase(&dt);
	    unsorted.erase(&dt);
	}
	uint get(msec_t when, DispatchTimer **batch, uint maxcnt) {
	    uint cnt = 0;
	    auto it = sorted.begin();

	    while (cnt < maxcnt && it != sorted.end() && (*it)->due <= when) {
		(*it)->due = DispatchTimer::DSP_NEVER_DUE;
		batch[cnt++] = *it++;
	    }
	    sorted.erase(sorted.begin(), it);
	    batch[cnt] = cnt < maxcnt && it != sorted.end() ? *it : nullptr;
	    return cnt;
	}
	void insert(DispatchTimer &dt) { unsorted.insert(&dt); }
	DispatchTimer *reorder(msec_t when) {
	    for (DispatchTimer *dt : unsorted) {
		if (dt->due < when && dt->due > split)
		    sorted.insert(dt);
	    }
	    split = when;
	    return peek();
	}
	void set(DispatchTimer &dt, msec_t when) {
	    if (UNLIKELY(dt.due == when))
		return;
	    if (UNLIKELY(dt.due <= split)) {
		if (when <= split) {
		    sorted_timerset::node_type node = sorted.extract(&dt);
		    dt.due = when;
		    sorted.insert(std::move(node));
		    return;
		}
		sorted.erase(&dt);
	    }
	    dt.due = when;
	    if (when <= split)
		sorted.insert(&dt);
	}

    private:
	sorted_timerset sorted;
	msec_t split;
	unsorted_timerset unsorted;
    };

    friend class DispatchObj;
    void addReady(DispatchObj &obj, bool hipri, DispatchMsg reason);
    void cancelReady(DispatchObj &ob, bool del = false);
    void removeReady(DispatchObj &obj);
    void ready(DispatchObj &obj, bool hipri = false);

    friend class DispatchTimer;
    void addTimer(DispatchTimer &dt) {
	tlock.lock();
	timers.insert(dt);
	tlock.unlock();
    }
    void cancelTimer(DispatchTimer &dt, bool del = false);
    void removeTimer(DispatchTimer &dt) {
	if (dt.due == DispatchTimer::DSP_NEVER_DUE)
	    return;
	tlock.lock();
	timers.set(dt, DispatchTimer::DSP_NEVER_DUE);
	tlock.unlock();
    }
    void setTimer(DispatchTimer &dt, ulong tm);

    friend class DispatchSocket;
    void cancelSocket(DispatchSocket &ds, bool del = false);
    void pollSocket(DispatchSocket &ds, ulong timeout, DispatchMsg msg);

    void cleanup(void);
    bool exec(void);
    void handleEvents(const void *evts, uint cnt);
    DispatchTimer *handleTimers(msec_t now);
    void reset(void);
    int run(void);
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

    SpinLock olock;
    uint maxthreads;
    ObjectList<DispatchObj> rlist;
    atomic<uint> rsize;
    atomic_bool polling, shutdown;
    alignas(64) atomic_uint_fast32_t scanning, workers;
    SpinLock tlock;
    atomic<msec_t> cache;
    msec_t due;
    TimerSet timers;
#ifdef DSP_WIN32_ASYNC
    atomic_ulong interval;
    HWND wnd;
    static uint socketmsg;
    static constexpr int DSP_TimerID = 1;
#elif defined(DSP_POLL)
    SocketSet rset, wset;
    Socket rsock, wsock;
#else
    int evtfd;
#ifdef DSP_EPOLL
    int wfd;
#endif
#endif
    Lifo lifo;
#if defined(DSP_WIN32_ASYNC) || defined(DSP_DEVPOLL) || defined(DSP_POLL)
    SpinLock slock;
    socketmap smap;
#endif
    uint stacksz;
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
	tstring s(dspr.config().get(T("host"), host, C::section()));

	return listen(Sockaddr(s.c_str()), enable);
    }

protected:
    virtual void onAccept(Socket &sock) {
	C *c = new(std::nothrow) C(static_cast<D &>(dspr), sock);

	if (c == nullptr) {
	    sock.close();
	} else {
	    c->detach();
	    start(*c);
	}
    }

    virtual void start(C &ssock) { ssock.start(); }
};

inline void DispatchObj::cancel(void) { dspr.cancelReady(*this); }
inline void DispatchObj::erase(void) { dspr.cancelReady(*this, true); }
inline void DispatchObj::ready(DispatchObjCB cb, bool hipri, DispatchMsg
    reason) {
    callback(cb);
    dspr.addReady(*this, hipri, reason);
}

inline void DispatchTimer::cancel(void) { dspr.cancelTimer(*this); }
inline void DispatchTimer::erase(void) { dspr.cancelTimer(*this, true); }
inline void DispatchTimer::init(void) { dspr.addTimer(*this); }
inline void DispatchTimer::timeout(DispatchObjCB cb, ulong msec) {
    callback(cb);
    if (msec != DSP_PREVIOUS)
	to = msec;
    dspr.setTimer(*this, to);
}

inline void DispatchSocket::cancel(void) { dspr.cancelSocket(*this); }
inline void DispatchSocket::erase(void) { dspr.cancelSocket(*this, true); }
inline void DispatchSocket::poll(DispatchObjCB cb, ulong msec, DispatchMsg
    reason) {
    callback(cb);
    if (msec != DSP_PREVIOUS)
	to = msec;
    dspr.pollSocket(*this, to, reason);
}

/*
 * AsyncCondvar acts like a std::condition_variable, but queues a callback
 * to be called instead of blocking the thread. The lock must be held
 * but wait() returns with it unlocked
 */
class BLISTER AsyncCondvar: nocopy {
public:
    class BLISTER Waiter: public DispatchObj {
    public:
	explicit Waiter(AsyncCondvar &a): DispatchObj(a.dispatcher()), ac(a) {}

	void wait(DispatchObjCB cb) {
	    callback(cb);
	    ac.wait(*this);
	}
	void cancel(void) override { ac.cancel(*this); }

    private:
	AsyncCondvar &ac;
    };

    AsyncCondvar(Dispatcher &d, Lock &l): dspr(d), lck(l), signaled(false) {}

    __forceinline operator bool(void) const { return !waiters.empty(); }
    __forceinline Dispatcher &dispatcher(void) const { return dspr; }
    __forceinline uint size(void) const { return waiters.size(); }
    __forceinline Waiter *peek(void) const { return waiters.peek(); }

    void broadcast(void) {
	while (waiters)
	    waiters.pop_front()->ready();
    }
    uint set(uint count = 1) {
	uint woken = 0;

	while (count && waiters) {
	    Waiter *waiter = waiters.pop_front();

	    waiter->ready();
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
	} else  {
	    waiters.push_back(waiter);
	    lck.unlock();
	}
    }
protected:
    void cancel(Waiter &waiter) {
	lck.lock();
	waiters.pop(waiter);
	lck.unlock();
    }

private:
    Dispatcher &dspr;
    Lock &lck;
    atomic_bool signaled;
    ObjectList<Waiter> waiters;
};

#endif // Dispatch_h
