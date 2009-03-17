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

#ifndef Dispatch_h
#define Dispatch_h

#include <map>
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

#if defined(_WIN32) && !defined(_WIN32_WCE)
/*
 * select() is faster on Windows for normal fd set sizes
#define DSP_WIN32_ASYNC
const int DSP_TimerID = 1;
 */
#endif

#ifdef __APPLE__	// some OSX revs won't wake on a 0 byte UDP write
#define DSP_WAKE_READ
#define DSP_WAKE_SIZE 1
#else
#define DSP_WAKE_SIZE 0
#endif

#ifdef __linux__
#define DSP_EPOLL
#endif

class DispatchObjList: nocopy {
public:
    DispatchObjList(): front(NULL), back(NULL) {}

    bool operator !(void) const { return front == NULL; }
    operator bool(void) const { return front != NULL; }
    bool empty(void) const { return front == NULL; }
    const DispatchObj *peek(void) const { return front; }

    DispatchObj *pop_front(void);
    void pop(DispatchObj *obj);
    void push_back(DispatchObj *obj);
    void push_front(DispatchObj *obj);
    void push_front(DispatchObjList &lst);

private:
    DispatchObj *front, *back;
};

class Dispatcher: public ThreadGroup {
public:
    enum Msg {
	Read, Write, ReadWrite, Accept, Connect, Close, Timeout, Resume, Nomsg
    };

    Dispatcher(const Config &config);
    virtual ~Dispatcher() { stop(); }

    const Config &config(void) const { return cfg; }
    bool start(uint maxthreads = 100, uint stacksz = 0, bool autoterm = true);
    void stop(void);

protected:
    virtual int onStart(void);

    const Config &cfg;

private:
    typedef hash_map<int, DispatchSocket *> socketmap;
    typedef multimap<msec_t, DispatchTimer *> timermap;

    friend class DispatchObj;
    void addReady(DispatchObj &obj, bool hipri, Msg reason);
    void cancelReady(DispatchObj &obj);
    void removeReady(DispatchObj &obj);
    void deleteObj(DispatchObj &obj);
    void ready(DispatchObj &obj, bool hipri = false);

    friend class DispatchTimer;
    void addTimer(DispatchTimer &dt, ulong tm);
    void cancelTimer(DispatchTimer &dt);
    void removeTimer(DispatchTimer &dt);
    bool timer(DispatchTimer &dt, msec_t to);

    friend class DispatchSocket;
    void cancelSocket(DispatchSocket &ds);
    void eraseSocket(DispatchSocket &ds);
    void selectSocket(DispatchSocket &ds, Msg msg, ulong timeout);

    bool exec(volatile DispatchObj *&aobj, thread_t tid);
    int run(void);
    void wake(uint tasks);
    static int worker(void *parm);

    msec_t due;
    volatile int shutdown;
    volatile ulong threads;
    uint maxthreads;
    long stacksz;
    Lock lock;
    socketmap smap;

    timermap timers;
    Lifo lifo;
    DispatchObjList flist, rlist;
    TLS<volatile DispatchObj *> activeobj;
#ifdef DSP_WIN32_ASYNC
    volatile ulong interval;
    HWND wnd;
    static uint socketmsg;

    void wakeup(msec_t now, msec_t when) {
	interval = when - now;
	do {
	    when = interval;
	    SetTimer(hWnd, DSP_TimerID, interval, NULL);
	} while (interval != when);
    }
#else
    int epollfd;
    SocketSet rset, wset;
    volatile bool polling;
    Sockaddr waddr;
    Socket wsock;

    void wakeup(msec_t, msec_t) {
	if (polling) {
	    polling = false;
	    wsock.write("", DSP_WAKE_SIZE, waddr);
	}
    }
#endif
};

#define DSP_DECLARE(cls, func) \
    static void func(DispatchObj *obj) { (static_cast<cls *>(obj))->func(); } \
    void func(void)

class DispatchObj: public nocopy {
private:
    class Group: nocopy {
	friend class DispatchObj;
	friend class Dispatcher;
	Group(): active(0), refcount(1) {}

	Group &addref() { refcount.addref(); return *this; }

	thread_t active;
	Refcount refcount;
	DispatchObjList glist;
    };

public:
    DispatchObj(Dispatcher &d, DispatchObjCB cb = NULL):
	dspr(d), dcb(cb), flags(0), msg(Dispatcher::Nomsg),
	group(new Group), next(NULL) {}
    DispatchObj(DispatchObj &parent, DispatchObjCB cb = NULL):
	dspr(parent.dspr), dcb(cb), flags(0), msg(Dispatcher::Nomsg),
	group(&parent.group->addref()), next(NULL) {}
    virtual ~DispatchObj() { dspr.deleteObj(*this); }

    Dispatcher::Msg reason(void) const { return msg; }
    Dispatcher &dispatcher(void) const { return dspr; }

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

    Dispatcher &dspr;
    DispatchObjCB dcb;
    uint flags;
    Dispatcher::Msg msg;

private:
    Group *group;
    DispatchObj *next;

    friend class Dispatcher;
    friend class DispatchObjList;
};

// handle objects with timeouts
#define DSP_FOREVER	static_cast<ulong>(-1)
#define DSP_PREVIOUS	static_cast<ulong>(-2)

class DispatchTimer: public DispatchObj {
public:
    DispatchTimer(Dispatcher &d, ulong msec = DSP_FOREVER):
	DispatchObj(d), to(msec), due(0) {}
    DispatchTimer(Dispatcher &d, ulong msec, DispatchObjCB cb):
	DispatchObj(d), due(0) { timeout(cb, msec); }
    DispatchTimer(DispatchObj &parent, ulong msec = DSP_FOREVER):
	DispatchObj(parent), to(msec), due(0) {}
    DispatchTimer(DispatchObj &parent, ulong msec, DispatchObjCB cb):
	DispatchObj(parent), due(0) { timeout(cb, msec); }
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

protected:
    ulong to;

private:
    msec_t due;

    friend class Dispatcher;
};

// handle socket events
class DispatchSocket: public DispatchTimer, public Socket {
public:
    DispatchSocket(Dispatcher &d, int type = SOCK_STREAM,
    	ulong msec = DSP_FOREVER);
    DispatchSocket(Dispatcher &d, const Socket &sock, ulong msec = DSP_FOREVER);
    DispatchSocket(DispatchObj &parent, int type = SOCK_STREAM,
    	ulong msec = DSP_FOREVER);
    DispatchSocket(DispatchObj &parent, const Socket &sock,
	ulong msec = DSP_FOREVER);
    virtual ~DispatchSocket() { DispatchSocket::cancel(); }

    bool close(void) { cancel(); return Socket::close(); }
    virtual void cancel(void) { dspr.cancelSocket(*this); }

protected:
    void select(DispatchObjCB cb, ulong msec, Dispatcher::Msg msg) {
	callback(cb);
	if (msec != DSP_PREVIOUS)
	    to = msec;
	dspr.selectSocket(*this, msg, to);
    }

    bool block, mapped;

    friend class Dispatcher;
};

class DispatchIOSocket: public DispatchSocket {
public:
    DispatchIOSocket(Dispatcher &d, int type = SOCK_STREAM,
    	ulong msec = DSP_FOREVER): DispatchSocket(d, type, msec) {}
    DispatchIOSocket(DispatchObj &parent, int type = SOCK_STREAM,
    	ulong msec = DSP_FOREVER): DispatchSocket(parent, type, msec) {}
    DispatchIOSocket(Dispatcher &d, const Socket &sock, ulong msec =
	DSP_FOREVER): DispatchSocket(d, sock) {}
    DispatchIOSocket(DispatchObj &parent, const Socket &sock, ulong msec =
	DSP_FOREVER): DispatchSocket(parent, sock) {}

    void closeable(DispatchObjCB cb = NULL,
	ulong msec = 15000) { select(cb, msec, Dispatcher::Close); }
    void readable(DispatchObjCB cb = NULL,
	ulong msec = DSP_PREVIOUS) { select(cb, msec, Dispatcher::Read); }
    void writeable(DispatchObjCB cb = NULL,
	ulong msec = DSP_PREVIOUS) { select(cb, msec, Dispatcher::Write); }
    void rwable(DispatchObjCB cb = NULL,
	ulong msec = DSP_PREVIOUS) { select(cb, msec, Dispatcher::ReadWrite); }
};

class DispatchClientSocket: public DispatchIOSocket {
public:
    DispatchClientSocket(Dispatcher &d, int type = SOCK_STREAM,
	ulong msec = DSP_FOREVER): DispatchIOSocket(d, type, msec) {}
    DispatchClientSocket(DispatchObj &parent, int type = SOCK_STREAM,
	ulong msec = DSP_FOREVER): DispatchIOSocket(parent, type, msec) {}
    DispatchClientSocket(Dispatcher &d, const Socket &sock,
	ulong msec = DSP_FOREVER): DispatchIOSocket(d, sock, msec) {}
    DispatchClientSocket(DispatchObj &parent, const Socket &sock,
	ulong msec = DSP_FOREVER): DispatchIOSocket(parent, sock, msec) {}

    void connect(const Sockaddr &addr, ulong msec = 40000);

protected:
    virtual void onConnect(void) = 0;

private:
    DSP_DECLARE(DispatchClientSocket, connected);
};

class DispatchServerSocket: public DispatchIOSocket {
public:
    DispatchServerSocket(Dispatcher &d, const Socket &sock,
	ulong msec = DSP_FOREVER): DispatchIOSocket(d, sock, msec) {}

    virtual void start(void) = 0;
};

class DispatchListenSocket: public DispatchSocket {
public:
    DispatchListenSocket(Dispatcher &d, int type = SOCK_STREAM):
	DispatchSocket(d, type) { dcb = connection; }
    DispatchListenSocket(Dispatcher &d, const Sockaddr &addr,
	int type = SOCK_STREAM, bool reuse = true, int queue = LISTEN_BACKLOG);

    const Sockaddr address(void) { return sa; }
    bool listen(const Sockaddr &addr, bool reuse = true, int queue =
	LISTEN_BACKLOG);
    void relisten() { select(connection, DSP_FOREVER, Dispatcher::Accept); }

protected:
    Sockaddr sa;

    virtual bool onAccept(Socket &sock) = 0;

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

    bool listen(const char *host = NULL, bool enable = true,
	int backlog = LISTEN_BACKLOG) {
	string s(dspr.config().get("host", host, S::section()));

	if (!dspr.config().get("enable", enable, S::section()))
	    return true;
	backlog = dspr.config().get("backlog", backlog, S::section());
	if (DispatchListenSocket::listen(Sockaddr(s.c_str()), true, backlog)) {
	    dlog << Log::Info << "mod=" << S::section() <<
		" cmd=listen addr=" << s << endlog;
	    return true;
	}
	return false;
    }

protected:
    virtual bool onAccept(Socket &sock) {
	S *s = new S(static_cast<D &>(dspr), sock);

	if (s == NULL) {
	    sock.close();
	} else {
	    s->detach();
	    start(*s);
	}
	return true;
    }

    virtual void start(S &ssock) { ssock.start(); }
};


inline void DispatchObjList::push_back(DispatchObj *obj) {
    obj->next = NULL;
    if (back)
	back->next = obj;
    else
	front = obj;
    back = obj;
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

inline void DispatchObjList::pop(DispatchObj *obj) {
    if (front == obj) {
	front = obj->next;
	if (!front)
	    back = NULL;
    } else {
	for (DispatchObj *p = front; p; p = p->next) {
	    if (p->next == obj) {
		p->next = obj->next;
		if (!p->next)
		    back = p;
		break;
	    }
	}
    }
}

inline DispatchObj *DispatchObjList::pop_front(void) {
    DispatchObj *obj = front;

    front = obj->next;
    if (!front)
	back = NULL;
    return obj;
}

#endif // Dispatch_h

