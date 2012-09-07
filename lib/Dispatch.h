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

#ifndef Dispatch_h
#define Dispatch_h

#include <set>
#include STL_HASH_MAP
#include "Config.h"
#include "Log.h"
#include "Socket.h"
#include "Thread.h"

class DispatchObj;
class DispatchSocket;
class DispatchTimer;

// base classes for event objects
typedef void (*DispatchObjCB)(DispatchObj *);

#ifdef _WIN32
/*
 * select() is faster on Windows for normal fd set sizes
#define DSP_WIN32_ASYNC
 */
#endif

class DispatchObjList: nocopy {
public:
    DispatchObjList(): back(NULL), front(NULL) {}

    bool operator !(void) const { return front == NULL; }
    operator bool(void) const { return front != NULL; }
    bool empty(void) const { return front == NULL; }
    const DispatchObj *peek(void) const { return front; }

    void pop(DispatchObj *obj);
    DispatchObj *pop_front(void);
    void push_back(DispatchObj *obj);
    void push_front(DispatchObj *obj);
    void push_front(DispatchObjList &lst);

private:
    DispatchObj *back, *front;
};

class Dispatcher: public ThreadGroup {
public:
    enum Msg {
	Read, Write, ReadWrite, Accept, Connect, Close, Timeout, Resume, Nomsg
    };

    Dispatcher(const Config &config);
    virtual ~Dispatcher() { stop(); }

    const Config &config(void) const { return cfg; }
    
    bool start(uint maxthreads = 100, uint stacksz = 0, bool suspend = false,
	bool autoterm = false);
    void stop(void);

protected:
    virtual int onStart(void);

    const Config &cfg;

private:
    typedef hash_map<socket_t, DispatchSocket *> socketmap;
    typedef set<DispatchTimer *, bool(*)(const DispatchTimer *a,
	const DispatchTimer *b)> timerset;

    friend class DispatchObj;
    void addReady(DispatchObj &obj, bool hipri, Msg reason);
    void cancelReady(DispatchObj &obj);
    void removeReady(DispatchObj &obj);
    bool ready(DispatchObj &obj, bool hipri = false);

    friend class DispatchTimer;
    void addTimer(DispatchTimer &dt, ulong tm);
    void cancelTimer(DispatchTimer &dt);
    void removeTimer(DispatchTimer &dt);
    bool timer(DispatchTimer &dt, msec_t to);

    friend class DispatchSocket;
    void cancelSocket(DispatchSocket &ds);
    void pollSocket(DispatchSocket &ds, ulong timeout, Msg msg);

    void cleanup(void);
    bool exec(void);
    uint handleEvents(void *evts, int cnt);
    int run(void);
    void wake(uint tasks, bool master);
    static int worker(void *parm);

    SpinLock lock;
    msec_t due;
    DispatchObjList rlist;
    Lifo lifo;
    uint maxthreads;
    volatile bool shutdown;
    socketmap smap;
    uint stacksz;
    volatile uint threads, waking;
    timerset timers;
#ifdef DSP_WIN32_ASYNC
    volatile ulong interval;
    HWND wnd;
    static uint socketmsg;
    static const int DSP_TimerID = 1;

    void wakeup(msec_t now, msec_t when) {
	interval = (ulong)(when - now);
	do {
	    when = interval;
	    SetTimer(wnd, DSP_TimerID, interval, NULL);
	} while (interval != when);
    }
#else
    int evtfd;
    Socket isock;
    volatile bool polling;
    SocketSet rset, wset;
    Socket wsock;

    void reset(void) {
	char buf[16];

	lock.unlock();
	isock.read(buf, sizeof (buf));
	lock.lock();
    }
    void wakeup(msec_t, msec_t) {
	if (polling) {
	    polling = false;
	    wsock.write("", 1);
	}
    }
#endif
};

#define DSP_DECLARE(cls, func) \
    static void func(DispatchObj *obj) { (static_cast<cls *>(obj))->func(); } \
    void func(void)

class DispatchObj: nocopy {
private:
    class Group {
    public:
	Group(): active(false) {}

	bool active;
	DispatchObjList glist;
	RefCount refcount;

	Group &add() { refcount.reference(); return *this; }
    };

public:
    DispatchObj(Dispatcher &d, DispatchObjCB cb = NULL): dcb(cb), dspr(d),
	flags(0), msg(Dispatcher::Nomsg), group(new Group), next(NULL) {}
    DispatchObj(DispatchObj &parent, DispatchObjCB cb = NULL):
	dcb(cb), dspr(parent.dspr), flags(0), msg(Dispatcher::Nomsg),
	group(&parent.group->add()), next(NULL) {}
    virtual ~DispatchObj() {
	if (!group->refcount.release())
	    delete group;
    }

    Dispatcher &dispatcher(void) const { return dspr; }
    Dispatcher::Msg reason(void) const { return msg; }

    void detach(void);
    void erase(void);
    void ready(DispatchObjCB cb = NULL, bool hipri = false,
	Dispatcher::Msg reason = Dispatcher::Nomsg) {
	callback(cb);
	dspr.addReady(*this, hipri, reason);
    }
    virtual void cancel(void) { dspr.cancelReady(*this); }
    virtual void terminate(void);

protected:
    void callback(DispatchObjCB cb) { if (cb) dcb = cb; }

    DispatchObjCB dcb;
    Dispatcher &dspr;
    uint flags;
    Dispatcher::Msg msg;

private:
    Group *group;
    DispatchObj *next;

    friend class Dispatcher;
    friend class DispatchObjList;
};

// handle objects with timeouts
#define DSP_NEVER	static_cast<ulong>(-1)
#define DSP_PREVIOUS	static_cast<ulong>(-2)
#define DSP_NEVER_DUE	static_cast<msec_t>(-1)

class DispatchTimer: public DispatchObj {
public:
    DispatchTimer(Dispatcher &d, ulong msec = DSP_NEVER):
	DispatchObj(d), to(msec), due(DSP_NEVER_DUE) {}
    DispatchTimer(Dispatcher &d, ulong msec, DispatchObjCB cb):
	DispatchObj(d), due(DSP_NEVER_DUE) { timeout(cb, msec); }
    DispatchTimer(DispatchObj &parent, ulong msec = DSP_NEVER):
	DispatchObj(parent), to(msec), due(DSP_NEVER_DUE) {}
    DispatchTimer(DispatchObj &parent, ulong msec, DispatchObjCB cb):
	DispatchObj(parent), due(DSP_NEVER_DUE) { timeout(cb, msec); }
    virtual ~DispatchTimer() { DispatchTimer::cancel(); }

    msec_t expires(void) const { return due; }
    ulong timeout(void) const { return to; }

    void timeout(DispatchObjCB cb = NULL, ulong msec = DSP_PREVIOUS) {
	callback(cb);
	if (msec != DSP_PREVIOUS)
	    to = msec;
	dspr.addTimer(*this, to);
    }
    virtual void cancel(void) { dspr.cancelTimer(*this); }
    static bool less(const DispatchTimer *a, const DispatchTimer *b) {
	return a->due < b->due || (a->due == b->due && a < b);
    }

protected:
    ulong to;

private:
    msec_t due;

    friend class Dispatcher;
};

// handle socket events
class DispatchSocket: public DispatchTimer, public Socket {
public:
    DispatchSocket(Dispatcher &d, int type = SOCK_STREAM, ulong msec =
	DSP_NEVER);
    DispatchSocket(Dispatcher &d, const Socket &sock, ulong msec = DSP_NEVER);
    DispatchSocket(DispatchObj &parent, int type = SOCK_STREAM, ulong msec =
	DSP_NEVER);
    DispatchSocket(DispatchObj &parent, const Socket &sock, ulong msec =
	DSP_NEVER);
    virtual ~DispatchSocket() { DispatchSocket::cancel(); }

    bool close(void) { cancel(); return Socket::close(); }
    virtual void cancel(void) { dspr.cancelSocket(*this); }

protected:
    void poll(DispatchObjCB cb, ulong msec, Dispatcher::Msg msg) {
	callback(cb);
	if (msec != DSP_PREVIOUS)
	    to = msec;
	dspr.pollSocket(*this, to, msg);
    }

    bool mapped;

    friend class Dispatcher;
};

class DispatchIOSocket: public DispatchSocket {
public:
    DispatchIOSocket(Dispatcher &d, int type = SOCK_STREAM,
    	ulong msec = DSP_NEVER): DispatchSocket(d, type, msec) {}
    DispatchIOSocket(DispatchObj &parent, int type = SOCK_STREAM,
    	ulong msec = DSP_NEVER): DispatchSocket(parent, type, msec) {}
    DispatchIOSocket(Dispatcher &d, const Socket &sock, ulong msec = DSP_NEVER):
	DispatchSocket(d, sock, msec) {}
    DispatchIOSocket(DispatchObj &parent, const Socket &sock, ulong msec =
	DSP_NEVER): DispatchSocket(parent, sock, msec) {}

    void closeable(DispatchObjCB cb = NULL, ulong msec = 15000)
	{ poll(cb, msec, Dispatcher::Close); }
    void readable(DispatchObjCB cb = NULL, ulong msec = DSP_PREVIOUS)
	{ poll(cb, msec, Dispatcher::Read); }
    void writeable(DispatchObjCB cb = NULL, ulong msec = DSP_PREVIOUS)
	{ poll(cb, msec, Dispatcher::Write); }
    void rwable(DispatchObjCB cb = NULL, ulong msec = DSP_PREVIOUS)
	{ poll(cb, msec, Dispatcher::ReadWrite); }
};

class DispatchClientSocket: public DispatchIOSocket {
public:
    DispatchClientSocket(Dispatcher &d, int type = SOCK_STREAM,
	ulong msec = DSP_NEVER): DispatchIOSocket(d, type, msec) {}
    DispatchClientSocket(DispatchObj &parent, int type = SOCK_STREAM,
	ulong msec = DSP_NEVER): DispatchIOSocket(parent, type, msec) {}
    DispatchClientSocket(Dispatcher &d, const Socket &sock,
	ulong msec = DSP_NEVER): DispatchIOSocket(d, sock, msec) {}
    DispatchClientSocket(DispatchObj &parent, const Socket &sock,
	ulong msec = DSP_NEVER): DispatchIOSocket(parent, sock, msec) {}

    void connect(const Sockaddr &addr, ulong msec = 40000, DispatchObjCB cb =
	NULL);

protected:
    virtual void onConnect(void) = 0;

private:
    DSP_DECLARE(DispatchClientSocket, connected);
};

class DispatchServerSocket: public DispatchIOSocket {
public:
    DispatchServerSocket(Dispatcher &d, const Socket &sock,
	ulong msec = DSP_NEVER): DispatchIOSocket(d, sock, msec) {}

    virtual void start(void) = 0;
};

class DispatchListenSocket: public DispatchSocket {
public:
    DispatchListenSocket(Dispatcher &d, int type = SOCK_STREAM):
	DispatchSocket(d, type) {}
    DispatchListenSocket(Dispatcher &d, const Sockaddr &addr,
	int type = SOCK_STREAM, bool reuse = true, int queue = SOCK_BACKLOG,
	DispatchObjCB cb = connection);

    const Sockaddr address(void) { return addr; }
    bool listen(const Sockaddr &addr, bool reuse = true, int queue =
	SOCK_BACKLOG, DispatchObjCB cb = NULL);
    void relisten() { poll(NULL, DSP_PREVIOUS, Dispatcher::Accept); }

protected:
    virtual void onAccept(Socket &sock) = 0;

    Sockaddr addr;

 private:
    DSP_DECLARE(DispatchListenSocket, connection);
};

template<class D, class S>
class SimpleDispatchListenSocket: public DispatchListenSocket {
public:
    SimpleDispatchListenSocket(D &dspr, int type = SOCK_STREAM,
	bool detached = true): DispatchListenSocket(dspr, type) {
	if (detached)
	    detach();
    }

    bool listen(const tchar *host = NULL, bool enable = true,
	int backlog = SOCK_BACKLOG) {
	tstring s(dspr.config().get(T("host"), host, S::section()));

	if (!dspr.config().get(T("enable"), enable, S::section()))
	    return true;
	backlog = dspr.config().get(T("backlog"), backlog, S::section());
	if (DispatchListenSocket::listen(Sockaddr(s.c_str()), true, backlog)) {
	    dlog << Log::Info << T("mod=") << S::section() <<
		T(" cmd=listen addr=") << s << endlog;
	    return true;
	}
	return false;
    }

protected:
    virtual void onAccept(Socket &sock) {
	S *s = new S(static_cast<D &>(dspr), sock);

	if (s == NULL) {
	    sock.close();
	} else {
	    s->detach();
	    start(*s);
	}
    }

    virtual void start(S &ssock) { ssock.start(); }
};

inline void DispatchObjList::pop(DispatchObj *obj) {
    if (front == obj) {
	if ((front = obj->next) == NULL)
	    back = NULL;
    } else {
	for (DispatchObj *p = front; p; p = p->next) {
	    if (p->next == obj) {
		if ((p->next = obj->next) == NULL)
		    back = p;
		break;
	    }
	}
    }
}

inline DispatchObj *DispatchObjList::pop_front(void) {
    DispatchObj *obj = front;
    
    if ((front = obj->next) == NULL)
	back = NULL;
    return obj;
}

inline void DispatchObjList::push_back(DispatchObj *obj) {
    obj->next = NULL;
    if (back)
	back = back->next = obj;
    else
	back = front = obj;
}

inline void DispatchObjList::push_front(DispatchObj *obj) {
    obj->next = front;
    front = obj;
    if (!back)
	back = obj;
}

inline void DispatchObjList::push_front(DispatchObjList &lst) {
    if (lst.back) {
	lst.back->next = front;
	front = lst.front;
	lst.front = lst.back = NULL;
    }
}

#endif // Dispatch_h
