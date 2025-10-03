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

// Dispatch flags
enum DispatchFlag: uint_fast32_t {
    DSP_Socket = 0x0001,
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
class BLISTER DispatchObj: ObjectList<DispatchObj>::Node {
public:
    typedef void (*DispatchObjCB)(DispatchObj *);

    explicit DispatchObj(Dispatcher &d, DispatchObjCB cb = NULL): dcb(cb),
	dspr(d), flags(0), msg(DispatchNone), group(new Group) {}
    DispatchObj(DispatchObj &parent, DispatchObjCB cb = NULL): dcb(cb),
	dspr(parent.dspr), flags(0), msg(DispatchNone),
	group(&parent.group->add()) {}
    virtual ~DispatchObj() {
	if (group->refcount.release())
	    delete group;
    }

    Dispatcher &dispatcher(void) const { return dspr; }
    bool error(void) const {
	return msg == DispatchClose || msg == DispatchTimeout;
    }
    DispatchMsg reason(void) const { return msg; }

    void detach(void) { flags |= DSP_Detached; }
    void ready(DispatchObjCB cb = NULL, bool hipri = false, DispatchMsg reason =
	DispatchNone);
    virtual void cancel(void);
    virtual void erase(void);
    virtual void terminate(void);

protected:
    void callback(DispatchObjCB cb) { if (cb) dcb = cb; }

    DispatchObjCB dcb;
    Dispatcher &dspr;
    uint_fast32_t flags;
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

    DispatchObj &operator =(const DispatchObj &obj);
    friend class Dispatcher;
    friend class ObjectList<DispatchObj>;
};

// handle objects with timeouts
class BLISTER DispatchTimer: public DispatchObj {
public:
    static const ulong DSP_NEVER = (ulong)-1;
    static const ulong DSP_PREVIOUS = (ulong)-2;
    static const msec_t DSP_NEVER_DUE = (msec_t)-1;

    DispatchTimer(const DispatchTimer &dt): DispatchTimer((DispatchObj &)dt) {}
    explicit DispatchTimer(Dispatcher &d, ulong msec = DSP_NEVER):
	DispatchObj(d), to(msec), due(DSP_NEVER_DUE) { init(); }
    DispatchTimer(Dispatcher &d, ulong msec, DispatchObjCB cb):
	DispatchObj(d), to(0), due(DSP_NEVER_DUE) { init(); timeout(cb, msec); }
    explicit DispatchTimer(DispatchObj &parent, ulong msec = DSP_NEVER):
	DispatchObj(parent), to(msec), due(DSP_NEVER_DUE) { init(); }
    DispatchTimer(DispatchObj &parent, ulong msec, DispatchObjCB cb):
	DispatchObj(parent), to(0), due(DSP_NEVER_DUE) {
	init();
	timeout(cb, msec);
    }
    virtual ~DispatchTimer() {}

    msec_t expires(void) const { return due; }
    ulong timeout(void) const { return to; }

    void timeout(DispatchObjCB cb, ulong msec = DSP_PREVIOUS);
    virtual void cancel(void);
    virtual void erase(void);

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
class BLISTER DispatchSocket: public DispatchTimer, public Socket {
public:
    explicit DispatchSocket(Dispatcher &d, int type = SOCK_STREAM, ulong msec =
	DSP_NEVER);
    DispatchSocket(Dispatcher &d, const Socket &sock, ulong msec = DSP_NEVER);
    explicit DispatchSocket(DispatchObj &parent, int type = SOCK_STREAM, ulong
	msec = DSP_NEVER);
    DispatchSocket(DispatchObj &parent, const Socket &sock, ulong msec =
	DSP_NEVER);
    virtual ~DispatchSocket() {}

    virtual void cancel(void);
    virtual void erase(void);

protected:
    void poll(DispatchObjCB cb, ulong msec, DispatchMsg msg);

    bool mapped;

    friend class Dispatcher;
};

class BLISTER DispatchIOSocket: public DispatchSocket {
public:
    explicit DispatchIOSocket(Dispatcher &d, int type = SOCK_STREAM,
	ulong msec = DSP_NEVER): DispatchSocket(d, type, msec) {}
    DispatchIOSocket(Dispatcher &d, const Socket &sock, ulong msec = DSP_NEVER):
	DispatchSocket(d, sock, msec) {}
    explicit DispatchIOSocket(DispatchObj &parent, int type = SOCK_STREAM,
	ulong msec = DSP_NEVER): DispatchSocket(parent, type, msec) {}
    DispatchIOSocket(DispatchObj &parent, const Socket &sock, ulong msec =
	DSP_NEVER): DispatchSocket(parent, sock, msec) {}

    void acceptable(DispatchObjCB cb = NULL, ulong msec = DSP_PREVIOUS) {
	poll(cb, msec, DispatchAccept);
    }
    void closeable(DispatchObjCB cb = NULL, ulong msec = 15000) {
	poll(cb, msec, DispatchClose);
    }
    void readable(DispatchObjCB cb = NULL, ulong msec = DSP_PREVIOUS) {
	poll(cb, msec, DispatchRead);
    }
    void writeable(DispatchObjCB cb = NULL, ulong msec = DSP_PREVIOUS) {
	poll(cb, msec, DispatchWrite);
    }
    void rwable(DispatchObjCB cb = NULL, ulong msec = DSP_PREVIOUS) {
	poll(cb, msec, DispatchReadWrite);
    }
};

class BLISTER DispatchClientSocket: public DispatchIOSocket {
public:
    explicit DispatchClientSocket(Dispatcher &d, int type = SOCK_STREAM,
	ulong msec = DSP_NEVER): DispatchIOSocket(d, type, msec) {}
    DispatchClientSocket(Dispatcher &d, const Socket &sock,
	ulong msec = DSP_NEVER): DispatchIOSocket(d, sock, msec) {}
    explicit DispatchClientSocket(DispatchObj &parent, int type = SOCK_STREAM,
	ulong msec = DSP_NEVER): DispatchIOSocket(parent, type, msec) {}
    DispatchClientSocket(DispatchObj &parent, const Socket &sock,
	ulong msec = DSP_NEVER): DispatchIOSocket(parent, sock, msec) {}

    void connect(const Sockaddr &addr, ulong msec = 30000, DispatchObjCB cb =
	connected);

protected:
    virtual void onConnect(void) = 0;

private:
    DSP_DECLARE(DispatchClientSocket, connected);
};

class BLISTER DispatchServerSocket: public DispatchIOSocket {
public:
    DispatchServerSocket(Dispatcher &d, const Socket &sock,
	ulong msec = DSP_NEVER): DispatchIOSocket(d, sock, msec) {}

    virtual void start(void) = 0;
};

class BLISTER DispatchListenSocket: public DispatchSocket {
public:
    explicit DispatchListenSocket(Dispatcher &d, int type = SOCK_STREAM):
	DispatchSocket(d, type) {}
    DispatchListenSocket(Dispatcher &d, const Sockaddr &addr,
	int type = SOCK_STREAM, bool reuse = true, int backlog = SOCK_BACKLOG,
	DispatchObjCB cb = connection);

    const Sockaddr &address(void) const { return addr; }
    bool listen(const Sockaddr &addr, bool reuse = true, int backlog =
	SOCK_BACKLOG, DispatchObjCB cb = NULL, bool start = true);
    bool listen(const tchar *addrstr, bool reuse = true, int backlog =
	SOCK_BACKLOG, DispatchObjCB cb = NULL, bool start = true) {
	return listen(Sockaddr(addrstr), reuse, backlog, cb, start);
    }
    void relisten(void) { poll(NULL, DSP_PREVIOUS, DispatchAccept); }

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

    bool start(uint maxthreads = 100, uint stacksz = 0);

protected:
    virtual int onStart(void);
    virtual void onStop(void);

    const Config &cfg;

private:
    typedef unordered_map<socket_t, DispatchSocket *> socketmap;

    class BLISTER TimerSet {
    public:
	typedef ::set<DispatchTimer *, DispatchTimer::compare> sorted_timerset;
	typedef unordered_set<DispatchTimer *, ptrhash<DispatchTimer> >
	    unsorted_timerset;

	TimerSet(): split(0) {}
	TimerSet(const TimerSet &) = delete;

	TimerSet & operator =(const TimerSet &) = delete;

	bool empty(void) const { return unsorted.empty() && sorted.empty(); }
	msec_t half(void) const { return split; }
	size_t size(void) const { return unsorted.size(); }
	size_t soon(void) const { return sorted.size(); }

	void erase(DispatchTimer &dt) {
	    if (dt.due <= split)
		sorted.erase(&dt);
	    unsorted.erase(&dt);
	}
	DispatchTimer *get(msec_t when) {
	    sorted_timerset::const_iterator it = sorted.begin();

	    if (it != sorted.end()) {
		DispatchTimer *dt = *it;

		if (dt->due <= when) {
		    sorted.erase(it);
		    dt->due = DispatchTimer::DSP_NEVER_DUE;
		    return dt;
		}
	    }
	    return NULL;
	}
	void insert(DispatchTimer &dt) { unsorted.insert(&dt); }
	DispatchTimer *peek(void) {
	    sorted_timerset::const_iterator it = sorted.begin();

	    return it == sorted.end() ? NULL : *it;
	}
	void reorder(msec_t when) {
	    for (unsorted_timerset::const_iterator it = unsorted.begin(); it !=
		unsorted.end(); ++it) {
		DispatchTimer *dt = *it;

		if (dt->due != DispatchTimer::DSP_NEVER_DUE && dt->due >
		    split && dt->due < when)
		    sorted.insert(dt);
	    }
	    split = when;
	}
	void set(DispatchTimer &dt, msec_t when) {
	    if (dt.due == when)
		return;
	    if (dt.due <= split)
		sorted.erase(&dt);
	    dt.due = when;
	    if (when <= split)
		sorted.insert(&dt);
	}
	void terminate(void) {
	    unsorted_timerset::const_iterator it;

	    while ((it = unsorted.begin()) != unsorted.end())
		(*it)->terminate();
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
    void handleTimers(msec_t now);
    int run(void);
    void wakeup(ulong msec);
    static int worker(void *param);

    msec_t due;
    ObjectList<DispatchObj> rlist;
    Lifo lifo;
    uint maxthreads;
    SpinLock olock, slock, tlock;
    atomic_uint_fast16_t running;
    atomic_bool shutdown;
    socketmap smap;
    uint stacksz;
    TimerSet timers;
    atomic_uint_fast16_t workers;
#ifdef DSP_WIN32_ASYNC
    atomic_ulong interval;
    HWND wnd;
    static uint socketmsg;
    static const int DSP_TimerID = 1;
#else
    int evtfd, wfd;
    atomic_bool polling;
    SocketSet rset, wset;
    Socket rsock, wsock;

    void reset(void);
#endif
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
    bool listen(const tchar *host = NULL, bool enable = true) {
	tstring s(dspr.config().get(T("host"), host, C::section()));

	return listen(Sockaddr(s.c_str()), enable);
    }

protected:
    virtual void onAccept(Socket &sock) {
	C *c = new(nothrow) C(static_cast<D &>(dspr), sock);

	if (c == NULL) {
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

#endif // Dispatch_h
