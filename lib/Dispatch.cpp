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

#include "stdapi.h"
#include <signal.h>
#include <time.h>
#include "Dispatch.h"

static const ulong MAX_SELECT_TIMER = 5 * 1000;
static const uint MAX_WAKE_THREAD = 8;
static const int MAX_WAIT_TIME = 4 * 60 * 1000;
static const int MIN_IDLE_TIMER = 2 * 1000;
static const msec_t DSP_NEVER = static_cast<msec_t>(-1);

static const uint DSP_Socket = 0x0001;
static const uint DSP_Detached = 0x0002;
static const uint DSP_Scheduled = 0x0008;
static const uint DSP_Ready = 0x0010;
static const uint DSP_ReadyGroup = 0x0020;
static const uint DSP_Active = 0x0040;
static const uint DSP_Freed = 0x0080;

static const uint DSP_Acceptable = 0x0100;
static const uint DSP_Readable = 0x0200;
static const uint DSP_Writeable = 0x0400;
static const uint DSP_Closeable = 0x0800;
static const uint DSP_IO = DSP_Acceptable | DSP_Readable | DSP_Writeable |
    DSP_Closeable;

static const uint DSP_SelectAccept = 0x1000;
static const uint DSP_SelectRead = 0x2000;
static const uint DSP_SelectWrite = 0x4000;
static const uint DSP_SelectClose = 0x8000;
static const uint DSP_SelectAll = DSP_SelectAccept | DSP_SelectRead |
    DSP_SelectWrite | DSP_SelectClose;

static const uint DSP_ReadyAll = DSP_Ready | DSP_ReadyGroup;

#ifdef DSP_WIN32_ASYNC
#pragma comment(lib, "user32.lib")

static const tchar *DispatchClass = T("DSP_CLASS");

uint Dispatcher::socketmsg;

#elif defined(DSP_EPOLL)

#include <sys/epoll.h>
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif
#ifndef EPOLLONESHOT
#define EPOLLONESHOT (1 << 30)
#endif

#endif

Dispatcher::Dispatcher(const Config &config): cfg(config), due(DSP_NEVER),
    shutdown(-1), threads(0), lifo(lock),
#ifdef DSP_WIN32_ASYNC
    wnd(0), interval(DSP_FOREVER)
#else
    epollfd(-1), wsock(SOCK_DGRAM)
#endif
    {
#ifdef DSP_WIN32_ASYNC
    if (!socketmsg) {
	WNDCLASS wc;

	socketmsg = RegisterWindowMessage(T("Dispatch_Socket"));
	memset(&wc, 0, sizeof (wc));
	wc.lpfnWndProc = DefWindowProc;
	wc.cbWndExtra = 0;
	wc.hInstance = GetModuleHandle(NULL);
	wc.lpszClassName = DispatchClass; 
	RegisterClass(&wc);
    }
#else
    polling = false;
#ifdef DSP_EPOLL
    do {
	epollfd = epoll_create(10000);
    } while (epollfd == -1 && interrupted(sockerrno()));
#endif
#endif
    if (Processor::count() > 1)
	lock.spin(40);
}

bool Dispatcher::exec(volatile DispatchObj *&aobj, thread_t tid) {
    DispatchObj *obj;
    DispatchObj::Group *group;

    for (;;) {
	if (!rlist)
	    return false;
	obj = rlist.pop_front();
	group = obj->group;
	if (group->active) {
	    obj->flags = (obj->flags & ~DSP_Ready) | DSP_ReadyGroup;
	    group->glist.push_back(obj);
	} else {
	    break;
	}
    }
    group->active = tid;
    do {
	aobj = obj;
	obj->flags = (obj->flags & ~DSP_ReadyAll) | DSP_Active;
	for (;;) {
	    lock.unlock();
#ifdef DSP_WIN32_ASYNC
	    if (obj->flags & DSP_Socket && obj->msg != Dispatcher::Timeout &&
		obj->msg != Dispatcher::Nomsg) {
		DispatchSocket *ds = (DispatchSocket *)obj;

		if (ds->block) {
		    ds->flags &= ~DSP_SelectAll;
		    WSAAsyncSelect(ds->fd(), wnd, socketmsg, 0);
		    ds->blocking(true);
		}
	    }
#endif
	    if (obj->flags & DSP_Freed) {
		delete obj;
		aobj = NULL;
		lock.lock();
	    } else {
		obj->dcb(obj);
		if (aobj && (obj->flags & DSP_Freed) &&
		    !(obj->flags & DSP_Socket)) {
		    delete obj;
		    aobj = NULL;
		}
		lock.lock();
		if (aobj) {
		    if (obj->flags & DSP_Freed) {
			obj->flags &= ~DSP_Active;
			flist.push_back(obj);
			aobj = NULL;
		    } else if (obj->flags & DSP_Ready) {
			obj->flags &= ~DSP_Ready;
			continue;
		    }
		}
	    }
	    break;
	}
	if (aobj)
	    obj->flags &= ~DSP_Active;
	if (group->glist)
	    obj = group->glist.pop_front();
	else
	    break;
    } while (obj);
    group->active = 0;
    if (group->refcount.is_zero())
	delete group;
    return rlist;
}

int Dispatcher::run() {
    volatile DispatchObj *aobj = NULL;
    Lifo::Waiting waiting(lifo);
    thread_t tid = THREAD_SELF();

    priority(-1);
    activeobj.set(&aobj);
    lock.lock();
    while (!shutdown) {
	if (!exec(aobj, tid) && !lifo.wait(waiting, MAX_WAIT_TIME) && threads > 1)
	    break;
    }
    threads--;
    lock.unlock();
    return 0;
}

int Dispatcher::worker(void *parm) {
    return (reinterpret_cast<Dispatcher *>(parm))->run();
}

#ifdef DSP_WIN32_ASYNC

int Dispatcher::onStart() {
    Thread *t;
    DispatchSocket *ds = NULL;
    DispatchTimer *dt = NULL;
    timermap::iterator tit;
    msec_t now;
    MSG msg;
    uint count = 0;

    if ((wnd = CreateWindow(DispatchClass, T("Dispatch Window"), 0, 0, 0,
	CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, GetModuleHandle(NULL), 0)) == NULL) {
	shutdown = 1;
	return -1;
    }
    shutdown = 0;
    while (!shutdown) {
	GetMessage(&msg, wnd, 0, 0);
	if (shutdown)
	    break;
	count = 0;
	if (msg.message == socketmsg) {
	    socketmap::const_iterator it;
	    uint evt = WSAGETSELECTEVENT(msg.lParam);

	    lock.lock();
	    if ((it = smap.find(msg.wParam)) != smap.end()) {
		ds = (DispatchSocket *)(*it).second;
		removeTimer(*ds);
		if (ds->flags & DSP_Scheduled) {
		    // uint err = WSAGETSELECTERROR(msg.lParam);
		    ds->flags = (ds->flags & ~DSP_Scheduled) | DSP_Ready;
		    if (evt & FD_READ)
			ds->msg = Read;
		    else if (evt & FD_ACCEPT)
			ds->msg = Accept;
		    if (evt & (FD_CONNECT | FD_WRITE)) {
			if (ds->msg == Nomsg)
			    ds->msg = Write;
		    	else
			    ds->flags |= DSP_Writeable;
		    }
		    if (evt & FD_CLOSE) {
			if (ds->msg == Nomsg)
			    ds->msg = Close;
		    	else
			    ds->flags |= DSP_Closeble;
		    }
		    if (!(ds->flags & DSP_Active)) {
			if (ds->msg == Accept)
			    rlist.push_front(ds);
			else
			    rlist.push_back(ds);
			count++;
		    }
		} else {
		    if (evt & FD_READ)
			ds->flags |= DSP_Readable;
		    else if (evt & FD_ACCEPT)
			ds->flags |= DSP_Acceptable;
		    if (evt & (FD_CONNECT | FD_WRITE))
			ds->flags |= DSP_Writeable;
		    if (evt & FD_CLOSE)
			ds->flags |= DSP_Closeable;
		}
	    }
	} else if (msg.message == WM_TIMER) {
	    now = mticks();
	    lock.lock();
	    while ((tit = timers.begin()) != timers.end()) {
		dt = (*tit).second;
		if (now < dt->due)
		    break;
		timers.erase(tit);
		dt->flags = (dt->flags & ~DSP_Scheduled) | DSP_Ready;
		dt->msg = Timeout;
		if (!(dt->flags & DSP_Active)) {
		    rlist.push_back(dt);
		    count++;
		}
	    }
	    if (tit == timers.end()) {
		if (interval < MIN_IDLE_TIMER) {
		    due = DSP_NEVER;
		    interval = DSP_FOREVER;
		    KillTimer(wnd, DSP_TimerID);
		}
	    } else if (dt->due - now < interval || interval < MIN_IDLE_TIMER) {
		due = dt->due;
		interval = dt->due - now;
		SetTimer(hwnd, DSP_TimerID, interval, NULL);
	    } else {
		due = now + interval;
	    }
	} else {
	    DefWindowProc(wnd, msg.message, msg.wParam, msg.lParam);
	    continue;
	}
	if (count)
	    wake(count);
	lock.unlock();
    }
    lock.lock();
    KillTimer(wnd, DSP_TimerID);
    DestroyWindow(wnd);
    wnd = 0;
    lifo.broadcast();
    lock.unlock();
    while ((t = wait(30000)) != NULL)
	delete t;
    return 0;
}

#else

int Dispatcher::onStart() {
    Thread *t;
    DispatchSocket *ds = NULL;
    DispatchTimer *dt = NULL;
    msec_t now;
    socketmap::const_iterator sit;
    timermap::iterator tit;
    char buf[16];
    uint count = 0;

#ifdef DSP_EPOLL
    epoll_event event[64];
    int nevents = 0;
#endif
    SocketSet irset, iwset, orset, owset, oeset;
    uint u;
    ulong msec;
#ifndef _WIN32
    sigset_t sigs;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);
#endif
    Socket isock(SOCK_DGRAM);

    (void)buf;
    waddr.host(T("localhost"));
    if (!isock.bind(waddr) || !isock.sockname(waddr)) {
	shutdown = 1;
	return -1;
    }
    isock.blocking(false);
    wsock.open(waddr.family());
    wsock.blocking(false);
    if (epollfd == -1) {
	rset.set(isock);
#ifdef DSP_EPOLL
    } else {
	ZERO(event);
	event[0].events = EPOLLIN;
	while (epoll_ctl(epollfd, EPOLL_CTL_ADD, isock.fd(), event) == -1 &&
	    interrupted(sockerrno()))
	    ;
#endif
    }
    lock.lock();
    shutdown = 0;
    now = mticks();
    while (!shutdown) {
	if (epollfd == -1) {
	    irset = rset;
	    iwset = wset;
	}
	if ((tit = timers.begin()) == timers.end()) {
	    msec = count ? MAX_SELECT_TIMER : DSP_NEVER;
	    due = count ? (now + MAX_SELECT_TIMER) : DSP_NEVER;
	} else {
	    dt = (*tit).second;
	    msec = dt->due > now ? static_cast<ulong>(dt->due - now) : 0;
	    due = now + msec;
	}
	polling = true;
	lock.unlock();
	if (epollfd == -1) {
	    if (!SocketSet::ioselect(irset, orset, iwset, owset, oeset, msec)) {
		orset.clear();
		owset.clear();
	    }
#ifdef DSP_WAKE_READ
	    if (!orset.empty() && orset[0] == isock)
		recvfrom(isock, buf, sizeof (buf), 0, NULL, NULL);
#endif
#ifdef DSP_EPOLL
	} else {
	    if ((nevents = epoll_wait(epollfd, event,
		sizeof (event) / sizeof (*event), msec)) == -1)
		nevents = 0;
#endif
	}
	polling = false;
	count = 0;
	now = mticks();
	lock.lock();
	rlist.push_front(flist);
	if (shutdown)
	    break;
#ifdef DSP_EPOLL
	for (u = 0; u < (uint)nevents; u++) {
	    ds = (DispatchSocket *)event[u].data.ptr;
	    if (!ds) {
		recvfrom(isock, buf, sizeof (buf), 0, NULL, NULL);
		continue;
	    }
	    if (ds->flags & DSP_Scheduled) {
		if (event[u].events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP))
		    ds->msg = ds->flags & DSP_SelectAccept ? Accept : Read;
		if (event[u].events & EPOLLOUT) {
		    if (ds->msg == Nomsg)
			ds->msg = Write;
		    else
			ds->flags |= DSP_Writeable;
		}
		if (event[u].events & (EPOLLERR | EPOLLHUP)) {
		    if (ds->msg == Nomsg)
			ds->msg = Close;
		    else
			ds->flags |= DSP_Closeable;
		}
		ds->flags = (ds->flags & ~(DSP_Scheduled | DSP_SelectAll)) |
		    DSP_Ready;
		if (!(ds->flags & DSP_Active)) {
		    if (ds->msg == Accept)
			rlist.push_front(ds);
		    else
			rlist.push_back(ds);
		    count++;
		}
	    } else {
		if (event[u].events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP))
		    ds->flags |= DSP_Readable;
		if (event[u].events & EPOLLOUT)
		    ds->flags |= DSP_Writeable;
		if (event[u].events & (EPOLLERR | EPOLLHUP))
		    ds->flags |= DSP_Closeable;
	    }
	    removeTimer(*ds);
	}
#endif
	for (u = 0; u < orset.size(); u++) {
	    if (orset[u] == isock)
		continue;
	    rset.unset(orset[u]);
	    if ((sit = smap.find(orset[u])) == smap.end())
		continue;
	    ds = (*sit).second;
	    if (ds->flags & DSP_SelectWrite)
		wset.unset(orset[u]);
	    if (ds->flags & DSP_Scheduled) {
		ds->msg = ds->flags & DSP_SelectAccept ? Accept : Read;
		ds->flags = (ds->flags & ~(DSP_Scheduled | DSP_SelectAll)) |
		    DSP_Ready;
		if (!(ds->flags & DSP_Active)) {
		    if (ds->msg == Accept)
			rlist.push_front(ds);
		    else
			rlist.push_back(ds);
		    count++;
		}
	    } else {
		ds->flags |= ds->flags & DSP_SelectAccept ? DSP_Acceptable :
		    DSP_Readable;
		ds->flags &= ~DSP_SelectAll;
	    }
	    removeTimer(*ds);
	}
	for (u = 0; u < owset.size(); u++) {
	    wset.unset(owset[u]);
	    if ((sit = smap.find(owset[u])) == smap.end())
		continue;
	    ds = (*sit).second;
	    if (ds->flags & DSP_SelectRead)
		rset.unset(owset[u]);
	    if (ds->flags & DSP_Scheduled) {
		ds->msg = Write;
		ds->flags = (ds->flags & ~(DSP_Scheduled | DSP_SelectAll)) |
		    DSP_Ready;
		if (!(ds->flags & DSP_Active)) {
		    rlist.push_back(ds);
		    count++;
		}
	    } else {
		ds->flags |= DSP_Writeable;
		ds->flags &= ~DSP_SelectAll;
	    }
	    removeTimer(*ds);
	}
	for (u = 0; u < oeset.size(); u++) {
	    if (ds->flags & DSP_SelectRead)
		rset.unset(oeset[u]);
	    if (ds->flags & DSP_SelectWrite)
		wset.unset(oeset[u]);
	    if ((sit = smap.find(oeset[u])) == smap.end())
		continue;
	    ds = (*sit).second;
	    if (ds->flags & DSP_Scheduled) {
		ds->msg = Close;
		ds->flags = (ds->flags & ~(DSP_Scheduled | DSP_SelectAll)) |
		    DSP_Ready;
		if (!(ds->flags & DSP_Active)) {
		    rlist.push_back(ds);
		    count++;
		}
	    } else {
		ds->flags |= DSP_Closeable;
		ds->flags &= ~DSP_SelectAll;
	    }
	    removeTimer(*ds);
	}
	while ((tit = timers.begin()) != timers.end()) {
	    dt = (*tit).second;
	    if (now < dt->due)
		break;
	    timers.erase(tit);
	    dt->due = DSP_NEVER;
	    dt->flags = (dt->flags & ~DSP_Scheduled) | DSP_Ready;
	    dt->msg = Timeout;
	    if (!(dt->flags & DSP_Active)) {
		rlist.push_back(dt);
		count++;
	    }
	}
	if (count)
	    wake(count);
    }
    lifo.broadcast();
    lock.unlock();
    while ((t = wait(30000)) != NULL)
	delete t;
    rlist.push_front(flist);
    while (rlist) {
	DispatchObj *obj = rlist.pop_front();
	DispatchObj::Group *group = obj->group;

	if (group->glist)
	    obj = group->glist.pop_front();
	if (obj->flags & DSP_Freed) {
	    delete obj;
	} else {
	    obj->cancel();
	    obj->terminate();
	}
    }
    while ((tit = timers.begin()) != timers.end()) {
	(*tit).second->cancel();
	(*tit).second->terminate();
    }
    return 0;
}

#endif

bool Dispatcher::start(uint mthreads, uint stack, bool autoterm) {
    bool ret;

    maxthreads = mthreads;
    stacksz = stack ? stack : 256 * 1024;
    shutdown = -1;
    ret = ThreadGroup::start(maxthreads ? 32 * 1024 : stacksz, autoterm);
    while (ret && shutdown == -1)
	msleep(20);
    return ret;
}

void Dispatcher::stop() {
    msec_t now = mticks();

    if (shutdown)
    	return;
    shutdown = 1;
    lock.lock();
    wakeup(now, now);
    lock.unlock();
    waitForMain();
}

void Dispatcher::wake(uint tasks) {
    if (maxthreads == 0) {
	volatile DispatchObj *aobj;

	activeobj.set(&aobj);
	while (!shutdown && exec(aobj, THREAD_ID()))
	    ;
    } else {
	uint cnt = tasks < MAX_WAKE_THREAD ? tasks : MAX_WAKE_THREAD;
	uint lsz = lifo.size();
	bool relock = false;

	while (rlist && cnt && lsz--) {
	    lifo.set();
	    if ((relock = !relock) == false) {
		lock.unlock();
		lock.lock();
	    }
	    cnt--;
	}
	while (rlist && cnt-- && threads < maxthreads && !shutdown) {
	    Thread *t;

	    threads++;
	    lock.unlock();
	    t = new Thread;
	    t->start(worker, this, stacksz);
	    while ((t = wait(0)) != NULL)
		delete t;
	    lock.lock();
	}
    }
}

bool Dispatcher::timer(DispatchTimer &dt, msec_t tmt) {
    if (dt.due != DSP_NEVER)
	removeTimer(dt);
    dt.due = tmt;
    if (tmt != DSP_NEVER) {
	pair<msec_t, DispatchTimer *> p(tmt, &dt);

	timers.insert(p);
	if (tmt + 1 < due) {
	    due = tmt;
	    return true;
	}
    }
    return false;
}

void Dispatcher::addTimer(DispatchTimer &dt, ulong tm) {
    msec_t now = tm ? mticks() : 0;
    bool wake;

    lock.lock();
    if (tm) {
	wake = timer(dt, tm == DSP_FOREVER ? DSP_NEVER : now + tm);
    } else {
	removeTimer(dt);
	ready(dt);
	wake = false;
    }
    lock.unlock();
    if (wake)
	wakeup(now, dt.due);
}

void Dispatcher::cancelTimer(DispatchTimer &dt) {
    if (dt.due != DSP_NEVER) {
	lock.lock();
	removeReady(dt);
	removeTimer(dt);
	lock.unlock();
    }
}

void Dispatcher::removeTimer(DispatchTimer &dt) {
    dt.flags &= ~DSP_Scheduled;
    if (dt.due == DSP_NEVER)
    	return;
    for (timermap::iterator it = timers.find(dt.due); it != timers.end(); ++it) {
	DispatchTimer *p = (*it).second;

	if (p == &dt) {
	    timers.erase(it);
	    break;
	} else if (p->due != dt.due) {
	    break;
	}
    }
    dt.due = DSP_NEVER;
}

void Dispatcher::cancelSocket(DispatchSocket &ds) {
    socket_t fd;
    Locker lkr(lock);

    if (ds.flags & DSP_ReadyAll)
	removeReady(ds);
    else
	removeTimer(ds);
    if (ds.mapped && (fd = ds.fd()) != -1) {
	ds.mapped = false;
#ifdef DSP_WIN32_ASYNC
	smap.erase(fd);
	if (ds.flags & DSP_SelectAll) {
	    ds.flags &= ~DSP_SelectAll;
	    lkr.unlock();
	    WSAAsyncSelect(fd, wnd, socketmsg, 0);
	}
#else
	if (epollfd == -1) {
	    smap.erase(fd);
	    if (ds.flags & (DSP_SelectRead | DSP_SelectAccept))
		rset.unset(fd);
	    if (ds.flags & DSP_SelectWrite)
		wset.unset(fd);
	    ds.flags &= ~DSP_SelectAll;
#ifdef DSP_EPOLL
	} else {
	    ds.flags &= ~DSP_SelectAll;
	    lkr.unlock();
	    while (epoll_ctl(epollfd, EPOLL_CTL_DEL, fd, 0) == -1 &&
		interrupted(sockerrno()))
		;
#endif
	}
#endif
    }
}

void Dispatcher::eraseSocket(DispatchSocket &ds) {
    Locker lkr(lock);

    if (shutdown)
	delete &ds;
    else
	flist.push_back(&ds);
}

void Dispatcher::selectSocket(DispatchSocket &ds, Msg m, ulong tm) {
    uint ioflags;
    msec_t now = mticks();
    static uint ioarray[] = {
	DSP_Readable | DSP_Closeable, DSP_Writeable | DSP_Closeable,
	DSP_Readable | DSP_Writeable | DSP_Closeable, DSP_Acceptable,
	DSP_Writeable | DSP_Closeable, DSP_Closeable, 0, 0, 0
    };
    static uint sarray[] = {
	DSP_SelectRead, DSP_SelectWrite, DSP_SelectRead | DSP_SelectWrite,
	DSP_SelectAccept, DSP_SelectWrite, DSP_SelectClose, 0, 0, 0
    };
#ifdef DSP_EPOLL
    int op = EPOLL_CTL_MOD;
    epoll_event event;
    static const long sockevents[] = {
	EPOLLIN | EPOLLPRI | EPOLLRDHUP, EPOLLOUT,
	EPOLLIN | EPOLLPRI | EPOLLRDHUP | EPOLLOUT, EPOLLIN, EPOLLOUT, 0, 0, 0
    };

    ZERO(event);
    event.data.ptr = &ds;
    event.events = sockevents[m] | EPOLLERR | EPOLLHUP | EPOLLONESHOT;
#endif

    Locker lkr(lock);

    ioflags = ds.flags & DSP_IO;
    if (ioarray[m] & ioflags) {
	if ((ioflags & DSP_Writeable) &&
	    (m == Write || m == ReadWrite || m == Connect)) {
	    ds.flags &= ~DSP_Writeable;
	    ds.msg = Dispatcher::Write;
	} else if ((ioflags & DSP_Readable) && (m == Read || m == ReadWrite)) {
	    ds.flags &= ~DSP_Readable;
	    ds.msg = Dispatcher::Read;
	} else if ((ioflags & DSP_Acceptable) && m == Accept) {
	    ds.flags &= ~DSP_Acceptable;
	    ds.msg = Dispatcher::Accept;
	} else if (ioflags & DSP_Closeable) {
	    ds.flags &= ~DSP_Closeable;
	    ds.msg = Dispatcher::Close;
	}
	ready(ds, m == Accept);
	return;
    }

    msec_t tmt = tm == DSP_FOREVER ? DSP_NEVER : now + tm;
    bool wake = timer(ds, tmt);

    ds.flags |= DSP_Scheduled;
    ds.msg = Nomsg;
    if (sarray[m] != (ds.flags & DSP_SelectAll)) {
	ds.flags &= ~(DSP_SelectAll | DSP_IO);
	ds.flags |= sarray[m];
    	if (!ds.mapped) {
#ifdef DSP_EPOLL
	    op = EPOLL_CTL_ADD;
	    if (epollfd == -1)
#endif
		smap[ds.fd()] = &ds;
	    ds.mapped = true;
	}
#ifdef DSP_WIN32_ASYNC
	static const long sockevents[] = {
	    FD_READ | FD_CLOSE, FD_WRITE | FD_CLOSE,
	    FD_READ | FD_WRITE | FD_CLOSE, FD_ACCEPT, FD_CONNECT | FD_CLOSE,
	    FD_CLOSE
	};

	lkr.unlock();
	if (WSAAsyncSelect(ds.fd(), wnd, socketmsg, sockevents[(int)m])) {
	    lkr.lock();
	    removeTimer(ds);
	    ready(ds);
	}
#else
	if (epollfd == -1) {
	    if (m == Read || m == ReadWrite || m == Accept || m == Close)
		rset.set(ds.fd());
	    if (m == Write || m == ReadWrite || m == Connect)
		wset.set(ds.fd());
	    if (polling) {
		tmt = now;
		wake = true;
	    }
#ifdef DSP_EPOLL
	} else {
	    lkr.unlock();
	    while (epoll_ctl(epollfd, op, ds.fd(), &event) == -1 &&
		interrupted(sockerrno()))
		;
#endif
	}
#endif
    }
    lkr.unlock();
    if (wake)
	wakeup(now, tmt);
}

void Dispatcher::addReady(DispatchObj &obj, bool hipri, Msg reason) {
    Locker lkr(lock);

    obj.msg = reason;
    obj.flags |= DSP_Ready;
    if (obj.flags & DSP_Active)
	return;
    if (obj.group && obj.group->active && THREAD_ISSELF(obj.group->active)) {
	obj.group->glist.push_front(&obj);
	return;
    }
    if (hipri)
	rlist.push_front(&obj);
    else
	rlist.push_back(&obj);
    if (!lifo.empty())
	lifo.set();
}

void Dispatcher::ready(DispatchObj &obj, bool hipri) {
    obj.flags = (obj.flags | DSP_Ready) & ~DSP_Scheduled;
    if (obj.flags & DSP_Active)
	return;
    if (obj.group && obj.group->active && THREAD_ISSELF(obj.group->active)) {
	obj.group->glist.push_front(&obj);
	return;
    }
    if (hipri)
	rlist.push_front(&obj);
    else
	rlist.push_back(&obj);
    if (!lifo.empty())
	lifo.set();
}

void Dispatcher::deleteObj(DispatchObj &obj) {
    cancelReady(obj);
    if (obj.flags & DSP_Active)
	*activeobj.data() = NULL;
    if (obj.group->refcount.release() && !obj.group->active)
	delete obj.group;
}


void Dispatcher::cancelReady(DispatchObj &obj) {
    if (obj.flags & DSP_ReadyAll) {
	lock.lock();
	removeReady(obj);
	lock.unlock();
    }
}

void Dispatcher::removeReady(DispatchObj &obj) {
    if (obj.flags & DSP_Ready) {
	obj.flags &= ~DSP_Ready;
	rlist.pop(&obj);
    } else if (obj.flags & DSP_ReadyGroup) {
	obj.flags &= ~DSP_ReadyAll;
	obj.group->glist.pop(&obj);
    }
}

void DispatchObj::detach(void) { flags |= DSP_Detached; }

void DispatchObj::erase(void) {
    if (flags & (DSP_Active | DSP_SelectAll)) {
	cancel();
	flags |= DSP_Freed;
	if (!(flags & DSP_Active))
	    dspr.eraseSocket((DispatchSocket &)*this);
    } else {
	delete this;
    }
}

void DispatchObj::terminate(void) {
    if (flags & DSP_Detached)
	erase();
}

DispatchSocket::DispatchSocket(Dispatcher &d, int type, ulong msec):
    DispatchTimer(d, msec), Socket(type), block(false), mapped(false) {
    flags |= DSP_Socket;
}

DispatchSocket::DispatchSocket(Dispatcher &d, const Socket &s, ulong msec):
    DispatchTimer(d, msec), Socket(s), block(false), mapped(false) {
    flags |= DSP_Socket;
}

DispatchSocket::DispatchSocket(DispatchObj &parent, int type, ulong msec):
    DispatchTimer(parent, msec), Socket(type), block(false), mapped(false) {
    flags |= DSP_Socket;
}

DispatchSocket::DispatchSocket(DispatchObj &parent, const Socket &s, ulong msec):
    DispatchTimer(parent, msec), Socket(s), block(false), mapped(false) {
    flags |= DSP_Socket;
}

void DispatchClientSocket::connect(const Sockaddr &addr, ulong msec) {
    bind(Sockaddr(addr.family()));
#ifndef DSP_WIN32_ASYNC
    blocking(false);
#endif
    if (Socket::connect(addr)) {
	msg = Dispatcher::Write;
	ready(connected);
    } else if (!blocked()) {
	msg = Dispatcher::Close;
	ready(connected);
    } else {
	select(connected, msec, Dispatcher::Connect);
    }
}

void DispatchClientSocket::connected() {
    onConnect();
}

DispatchListenSocket::DispatchListenSocket(Dispatcher &d, const Sockaddr &addr,
    int type, bool reuse, int queue): DispatchSocket(d, type) {
    listen(addr, reuse, queue);
}

bool DispatchListenSocket::listen(const Sockaddr &addr, bool reuse, int queue) {
    sa = addr;
    if (!Socket::listen(addr, reuse, queue))
	return false;
    blocking(false);
    msleep(1);
    select(connection, DSP_FOREVER, Dispatcher::Accept);
    return true;
}

void DispatchListenSocket::connection() {
    Socket s;
    bool reselect = true;

    if (msg != Dispatcher::Close && accept(s)) {
#ifdef __linux__
    	s.blocking(false);
#endif
	s.movehigh();
	reselect = onAccept(s);
    }
    if (reselect)
	select(connection, DSP_PREVIOUS, Dispatcher::Accept);
}

