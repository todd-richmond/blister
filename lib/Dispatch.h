/*
 * Copyright 2001-2017 Todd Richmond
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
#include STL_UNORDERED_MAP_H
#include STL_UNORDERED_SET_H
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

class Dispatcher;
class DispatchObj;

typedef void (*DispatchObjCB)(DispatchObj *);

#define DSP_DECLARE(cls, func) \
    static void func(DispatchObj *obj) { (static_cast<cls *>(obj))->func(); } \
    void func(void)

// Dispatch messages
enum DispatchMsg {
    DispatchRead, DispatchWrite, DispatchReadWrite, DispatchAccept,
    DispatchConnect, DispatchClose, DispatchTimeout, DispatchNone
};

// base classes for event objects
class BLISTER DispatchObj: nocopy {
public:
    explicit DispatchObj(Dispatcher &d, DispatchObjCB cb = NULL): dcb(cb),
	dspr(d), flags(0), msg(DispatchNone), group(new Group), next(NULL) {}
    DispatchObj(DispatchObj &parent, DispatchObjCB cb = NULL): nocopy(),
	dcb(cb), dspr(parent.dspr), flags(0), msg(DispatchNone),
	group(&parent.group->add()), next(NULL) {}
    virtual ~DispatchObj() {
	if (!group->refcount.release())
	    delete group;
    }

    Dispatcher &dispatcher(void) const { return dspr; }
    bool error(void) const {
	return msg == DispatchClose || msg == DispatchTimeout;
    }
    DispatchMsg reason(void) const { return msg; }

    void detach(void);
    void ready(DispatchObjCB cb = NULL, bool hipri = false, DispatchMsg reason =
	DispatchNone);
    virtual void cancel(void);
    virtual void erase(void);
    virtual void terminate(void);

protected:
    void callback(DispatchObjCB cb) { if (cb) dcb = cb; }

    DispatchObjCB dcb;
    Dispatcher &dspr;
    uint flags;
    DispatchMsg msg;

private:
    class Group {
    public:
	Group(): active(false) {}

	ObjectList<DispatchObj> glist;
	RefCount refcount;
	bool active;

	Group &add() { refcount.reference(); return *this; }
    };

    Group *group;
    DispatchObj *next;

    DispatchObj &operator =(const DispatchObj &obj);
    friend class Dispatcher;
    friend class ObjectList<DispatchObj>;
};

// handle objects with timeouts
#define DSP_NEVER	(ulong)-1
#define DSP_PREVIOUS	(ulong)-2
#define DSP_NEVER_DUE	(msec_t)-1

class BLISTER DispatchTimer: public DispatchObj {
public:
    explicit DispatchTimer(Dispatcher &d, ulong msec = DSP_NEVER):
	DispatchObj(d), to(msec), due(DSP_NEVER_DUE) { init(); }
    DispatchTimer(Dispatcher &d, ulong msec, DispatchObjCB cb):
	DispatchObj(d), due(DSP_NEVER_DUE) {  init(); timeout(cb, msec); }
    explicit DispatchTimer(DispatchObj &parent, ulong msec = DSP_NEVER):
	DispatchObj(parent), to(msec), due(DSP_NEVER_DUE) { init(); }
    DispatchTimer(DispatchObj &parent, ulong msec, DispatchObjCB cb):
	DispatchObj(parent), due(DSP_NEVER_DUE) { init(); timeout(cb, msec); }
    virtual ~DispatchTimer();

    msec_t expires(void) const { return due; }
    ulong timeout(void) const { return to; }

    void timeout(DispatchObjCB cb, ulong msec = DSP_PREVIOUS);
    virtual void cancel(void);

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
    virtual ~DispatchSocket() { close(); }

    void close(void);
    virtual void cancel(void);
    virtual void erase(void);

protected:
    bool closesocket(void) { return Socket::close(); }
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
	ulong msec = DSP_NEVER) : DispatchSocket(parent, type, msec) {}
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
	ulong msec = DSP_NEVER) : DispatchIOSocket(parent, type, msec) {}
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

    const Sockaddr address(void) { return addr; }
    bool listen(const Sockaddr &addr, bool reuse = true, int backlog =
	SOCK_BACKLOG, DispatchObjCB cb = NULL);
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

	bool empty(void) const { return unsorted.empty() && sorted.empty(); }
	msec_t half(void) const { return split; }
	size_t size(void) const { return unsorted.size(); }
	size_t soon(void) const { return sorted.size(); }

	void erase(DispatchTimer &dt) {
	    if (dt.due <= split)
		sorted.erase(&dt);
	    unsorted.erase(&dt);
	}
	DispatchTimer *get(void) {
	    unsorted_timerset::iterator it = unsorted.begin();

	    if (it != unsorted.end()) {
		DispatchTimer *dt = *it;

		if (dt->due <= split)
		    sorted.erase(dt);
		unsorted.erase(it);
		dt->due = DSP_NEVER_DUE;
		return dt;
	    }
	    return NULL;
	}
	DispatchTimer *get(msec_t when) {
	    sorted_timerset::iterator it = sorted.begin();

	    if (it != sorted.end()) {
		DispatchTimer *dt = *it;

		if (dt->due <= when) {
		    sorted.erase(it);
		    dt->due = DSP_NEVER_DUE;
		    return dt;
		}
	    }
	    return NULL;
	}
	void insert(DispatchTimer &dt) { unsorted.insert(&dt); }
	DispatchTimer *peek(void) {
	    return sorted.empty() ? NULL : *sorted.begin();
	}
	bool reorder(msec_t when) {
	    bool ret = false;

	    for (unsorted_timerset::const_iterator it = unsorted.begin(); it !=
		unsorted.end(); ++it) {
		DispatchTimer *dt = *it;

		if (dt->due != DSP_NEVER_DUE) {
		    ret = true;
		    if (dt->due > split && dt->due < when)
			sorted.insert(dt);
		}
	    }
	    split = when;
	    return ret;
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

    private:
	sorted_timerset sorted;
	msec_t split;
	unsorted_timerset unsorted;
    };

    friend class DispatchObj;
    void addReady(DispatchObj &obj, bool hipri, DispatchMsg reason);
    void cancelReady(DispatchObj &obj);
    void removeReady(DispatchObj &obj);
    bool ready(DispatchObj &obj, bool hipri = false);

    friend class DispatchTimer;
    void addTimer(DispatchTimer &dt) {
	FastSpinLocker lkr(lock);

	timers.insert(dt);
    }
    void cancelTimer(DispatchTimer &dt, bool del = false);
    void removeTimer(DispatchTimer &dt) { timers.set(dt, DSP_NEVER_DUE); }
    void setTimer(DispatchTimer &dt, ulong tm);

    friend class DispatchSocket;
    void cancelSocket(DispatchSocket &ds, bool close = false, bool del = false);
    void pollSocket(DispatchSocket &ds, ulong timeout, DispatchMsg msg);

    void cleanup(void);
    bool exec(void);
    uint handleEvents(const void *evts, uint cnt);
    int run(void);
    void wake(uint tasks, bool master);
    void wakeup(ulong msec);
    static int worker(void *parm);

    SpinLock lock;
    msec_t due;
    ObjectList<DispatchObj> flist, rlist;
    Lifo lifo;
    uint maxthreads;
    volatile uint running;
    volatile bool shutdown;
    socketmap smap;
    uint stacksz;
    TimerSet timers;
    volatile uint workers;
#ifdef DSP_WIN32_ASYNC
    volatile ulong interval;
    HWND wnd;
    static uint socketmsg;
    static const int DSP_TimerID = 1;
#else
    int evtfd, wfd;
    Socket isock;
    volatile bool polling;
    SocketSet rset, wset;
    Socket wsock;

    void reset(void);
#endif
};

template<class D, class S>
class SimpleDispatchListenSocket: public DispatchListenSocket {
public:
    explicit SimpleDispatchListenSocket(D &d, int type = SOCK_STREAM):
	DispatchListenSocket(d, type) {}

    bool listen(const Sockaddr &sa, bool enable = true) {
	const Config &cfg = dspr.config();
	int backlog = cfg.get(T("socket.backlog"), SOCK_BACKLOG, S::section());
	bool reuse = cfg.get(T("socket.reuse"), true, S::section());

	if (!cfg.get(T("enable"), enable, S::section())) {
	    return true;
	} else if (!DispatchListenSocket::listen(sa, reuse, backlog)) {
	    dloge(Log::mod(S::section()), Log::cmd(T("listen")),
		Log::kv(T("addr"), sa.str()), Log::error(errstr()));
	    return false;
	}
	dlogi(Log::mod(S::section()), Log::cmd(T("listen")), Log::kv(T("addr"),
	    sa.str()));
	return true;
    }
    bool listen(const tchar *host = NULL, bool enable = true) {
	tstring s(dspr.config().get(T("host"), host, S::section()));

	return listen(Sockaddr(s.c_str()), enable);
    }

protected:
    virtual void onAccept(Socket &sock) {
	S *s = new(nothrow) S(static_cast<D &>(dspr), sock);

	if (s == NULL) {
	    sock.close();
	} else {
	    s->detach();
	    start(*s);
	}
    }

    virtual void start(S &ssock) { ssock.start(); }
};

inline void DispatchObj::cancel(void) { dspr.cancelReady(*this); }

inline void DispatchObj::ready(DispatchObjCB cb, bool hipri, DispatchMsg
    reason) {
    callback(cb);
    dspr.addReady(*this, hipri, reason);
}

inline DispatchTimer::~DispatchTimer() {
    dspr.cancelTimer(*this, true);
}

inline void DispatchTimer::cancel(void) { dspr.cancelTimer(*this); }

inline void DispatchTimer::init(void) { dspr.addTimer(*this); }

inline void DispatchTimer::timeout(DispatchObjCB cb, ulong msec) {
    callback(cb);
    if (msec != DSP_PREVIOUS)
	to = msec;
    dspr.setTimer(*this, to);
}

inline void DispatchSocket::cancel(void) { dspr.cancelSocket(*this); }

inline void DispatchSocket::close(void) { dspr.cancelSocket(*this, true); }

inline void DispatchSocket::erase(void) { dspr.cancelSocket(*this, true, true); }

inline void DispatchSocket::poll(DispatchObjCB cb, ulong msec, DispatchMsg
    reason) {
    callback(cb);
    if (msec != DSP_PREVIOUS)
	to = msec;
    dspr.pollSocket(*this, to, reason);
}

#endif // Dispatch_h
