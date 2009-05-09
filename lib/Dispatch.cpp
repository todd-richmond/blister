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
static const int MAX_EVENTS = 64;

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

#elif defined(DSP_KQUEUE)

#include <sys/queue.h>
#endif

Dispatcher::Dispatcher(const Config &config): cfg(config), due(DSP_NEVER_DUE),
    lifo(lock), shutdown(-1), threads(0),
#ifdef DSP_WIN32_ASYNC
     interval(DSP_NEVER), wnd(0)
#else
    evtfd(-1), polling(false), wsock(SOCK_DGRAM)
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
	    group->active = tid;
	    break;
	}
    }
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

    activeobj.set(&aobj);
    priority(-1);
    lock.lock();
    while (!shutdown) {
	if (!exec(aobj, tid)) {
	    if (shutdown || (!lifo.wait(waiting, MAX_WAIT_TIME) && threads > 1))
		break;
	}
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
    uint count = 0;
    DispatchSocket *ds = NULL;
    DispatchTimer *dt = NULL;
    timermap::iterator tit;
    MSG msg;
    msec_t now;

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
		ds = (DispatchSocket *)it->second;
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
			    ds->flags |= DSP_Closeable;
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
		removeTimer(*ds);
	    }
	} else if (msg.message == WM_TIMER) {
	    now = milliticks();
	    lock.lock();
	    while ((tit = timers.begin()) != timers.end()) {
		dt = tit->second;
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
		    due = DSP_NEVER_DUE;
		    interval = DSP_NEVER;
		    KillTimer(wnd, DSP_TimerID);
		}
	    } else if (dt->due - now < interval || interval < MIN_IDLE_TIMER) {
		due = dt->due;
		interval = (ulong)(dt->due - now);
		SetTimer(wnd, DSP_TimerID, interval, NULL);
	    } else {
		due = now + interval;
	    }
	} else {
	    DefWindowProc(wnd, msg.message, msg.wParam, msg.lParam);
	    continue;
	}
	rlist.push_front(flist);
	if (count)
	    wake(count);
	lock.unlock();
    }
    lock.lock();
    KillTimer(wnd, DSP_TimerID);
    cleanup();
    DestroyWindow(wnd);
    wnd = 0;
    lock.unlock();
    return 0;
}

#else

int Dispatcher::onStart() {
    char buf[16];
    uint count = 0;
    DispatchSocket *ds = NULL;
    DispatchTimer *dt = NULL;
    SocketSet irset, iwset, orset, owset, oeset;
    ulong msec;
    msec_t now;
    socketmap::const_iterator sit;
    timermap::iterator tit;
    uint u;

#ifdef DSP_EPOLL
    epoll_event evts[MAX_EVENTS];

    do {
	evtfd = epoll_create(10000);
    } while (evtfd == -1 && interrupted(errno));
#elif defined(DSP_KQUEUE)
    struct kevent evts[MAX_EVENTS];
    timespec ts;

    evtfd = kqueue();
    EV_SET(&evts[0], -1, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(evtfd, &evts[0], 1, &evts[0], 1, NULL) != 1 || evts[0].ident !=
	(uintptr_t)-1 || evts[0].flags != EV_ERROR) {
	close(evtfd);
	evtfd = -1;
    }
#endif
#ifndef _WIN32
    sigset_t sigs;

    sigemptyset(&sigs);
    sigaddset(&sigs, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);
#endif
    Socket isock(SOCK_DGRAM);
    int nevts = 0;

    (void)buf;
    waddr.host(T("localhost"));
    if (!isock.bind(waddr) || !isock.sockname(waddr)) {
	shutdown = 1;
	return -1;
    }
    isock.blocking(false);
    wsock.open(waddr.family());
    wsock.blocking(false);
    if (evtfd == -1) {
	rset.set(isock);
#ifdef DSP_EPOLL
    } else {
	ZERO(evts);
	evts[0].events = EPOLLIN;
	while (epoll_ctl(evtfd, EPOLL_CTL_ADD, isock.fd(), evts) == -1 &&
	    interrupted(sockerrno()))
	    ;
#elif defined(DSP_KQUEUE)
	ZERO(evts);
	EV_SET(&evts[0], isock.fd(), EVFILT_READ, EV_ADD, 0, 0, NULL);
	while (kevent(evtfd, evts, 1, evts, 1, NULL) == -1 &&
	    interrupted(errno))
	    ;
#endif
    }
    lock.lock();
    shutdown = 0;
    now = milliticks();
    while (!shutdown) {
	if (evtfd == -1) {
	    irset = rset;
	    iwset = wset;
	}
	if ((tit = timers.begin()) == timers.end()) {
	    msec = count ? MAX_SELECT_TIMER : DSP_NEVER_DUE;
	    due = count ? (now + MAX_SELECT_TIMER) : DSP_NEVER_DUE;
	} else {
	    dt = tit->second;
	    msec = dt->due > now ? (ulong)(dt->due - now) : 0;
	    due = now + msec;
	}
	polling = true;
	lock.unlock();
	if (evtfd == -1) {
	    if (!SocketSet::ioselect(irset, orset, iwset, owset, oeset, msec)) {
		orset.clear();
		owset.clear();
	    }
#ifdef DSP_WAKE_READ
	    if (!orset.empty() && orset[0] == isock)
		recvfrom(isock, buf, sizeof (buf), 0, NULL, NULL);
#endif
	} else {
#ifdef DSP_EPOLL
	    if ((nevts = epoll_wait(evtfd, evts, MAX_EVENTS, msec)) == -1)
		nevts = 0;
#elif defined(DSP_KQUEUE)
	    ts.tv_sec = msec / 1000;
	    ts.tv_nsec = (msec % 1000) * 1000;
	    if ((nevts = kevent(evtfd, NULL, 0, evts, MAX_EVENTS, &ts)) == -1)
		nevts = 0;
#endif
	}
	polling = false;
	count = 0;
	now = milliticks();
	lock.lock();
	if (shutdown)
	    break;
	rlist.push_front(flist);
	for (u = 0; u < (uint)nevts; u++) {
#ifdef DSP_EPOLL
	    ds = (DispatchSocket *)evts[u].data.ptr;
	    if (!ds) {
		recvfrom(isock, buf, sizeof (buf), 0, NULL, NULL);
		continue;
	    }
	    if (ds->flags & DSP_Scheduled) {
		if (evts[u].events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP))
		    ds->msg = ds->flags & DSP_SelectAccept ? Accept : Read;
		if (evts[u].events & EPOLLOUT) {
		    if (ds->msg == Nomsg)
			ds->msg = Write;
		    else
			ds->flags |= DSP_Writeable;
		}
		if (evts[u].events & (EPOLLERR | EPOLLHUP)) {
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
		if (evts[u].events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP))
		    ds->flags |= DSP_Readable;
		if (evts[u].events & EPOLLOUT)
		    ds->flags |= DSP_Writeable;
		if (evts[u].events & (EPOLLERR | EPOLLHUP))
		    ds->flags |= DSP_Closeable;
	    }
#elif defined(DSP_KQUEUE)
	    ds = (DispatchSocket *)evts[u].udata;
	    if (!ds) {
		recvfrom(isock, buf, sizeof (buf), 0, NULL, NULL);
		continue;
	    }
	    if (ds->flags & DSP_Scheduled) {
    if (evts[u].flags & EV_ERROR && evts[u].data == ENOENT)
		if (evts[u].flags & EV_ERROR && evts[u].data == ENOENT)
		    continue;
		if (evts[u].filter == EVFILT_READ) {
		    if (ds->msg == Nomsg)
			ds->msg = ds->flags & DSP_SelectAccept ? Accept : Read;
		    else
			ds->flags |= DSP_Readable;
		} else if (evts[u].filter == EVFILT_WRITE) {
		    if (ds->msg == Nomsg)
			ds->msg = Write;
		    else
			ds->flags |= DSP_Writeable;
		}
		if (evts[u].flags & EV_ERROR) {
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
		if (evts[u].flags & EV_ERROR) {
		    if (evts[u].data == ENOENT)
			continue;
		    ds->flags |= DSP_Closeable;
		}
		if (evts[u].filter == EVFILT_READ)
		    ds->flags |= DSP_Readable;
		else if (evts[u].filter == EVFILT_WRITE)
		    ds->flags |= DSP_Writeable;
	    }
#endif
	    removeTimer(*ds);
	}
	for (u = 0; u < orset.size(); u++) {
	    if (orset[u] == isock)
		continue;
	    rset.unset(orset[u]);
	    if ((sit = smap.find(orset[u])) == smap.end())
		continue;
	    ds = sit->second;
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
	    ds = sit->second;
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
	    ds = sit->second;
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
	    dt = tit->second;
	    if (now < dt->due)
		break;
	    timers.erase(tit);
	    dt->due = DSP_NEVER_DUE;
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
    cleanup();
    lock.unlock();
    if (evtfd != -1)
	close(evtfd);
    return 0;
}

#endif

void Dispatcher::cleanup(void) {
    timermap::iterator tit;
    Thread *t;

    do {
	lifo.broadcast();
	lock.unlock();
	if ((t = wait(30000)) != NULL)
	    delete t;
	lock.lock();
    } while (t);
    rlist.push_front(flist);
    while (rlist) {
	DispatchObj *obj = rlist.pop_front();
	DispatchObj::Group *group = obj->group;

	if (group->glist)
	    obj = group->glist.pop_front();
	lock.unlock();
	if (obj->flags & DSP_Freed) {
	    delete obj;
	} else {
	    obj->cancel();
	    obj->terminate();
	}
	lock.lock();
    }
    while ((tit = timers.begin()) != timers.end()) {
	DispatchTimer *dt = tit->second;

	lock.unlock();
	dt->cancel();
	dt->terminate();
	lock.lock();
    }
}

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
    msec_t now = milliticks();

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
	    t = new Thread();
	    t->start(worker, this, stacksz, false, false, this);
	    while ((t = wait(0)) != NULL)
		delete t;
	    lock.lock();
	}
    }
}

bool Dispatcher::timer(DispatchTimer &dt, msec_t tmt) {
    if (dt.due != DSP_NEVER_DUE)
	removeTimer(dt);
    dt.due = tmt;
    if (tmt != DSP_NEVER_DUE) {
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
    msec_t now = tm ? milliticks() : 0;
    bool notify;

    lock.lock();
    if (tm) {
	notify = timer(dt, tm == DSP_NEVER ? DSP_NEVER_DUE : now + tm);
    } else {
	removeTimer(dt);
	ready(dt);
	if (!threads)
	    wake(1);
	notify = false;
    }
    lock.unlock();
    if (notify)
	wakeup(now, dt.due);
}

void Dispatcher::cancelTimer(DispatchTimer &dt) {
    if (dt.due != DSP_NEVER_DUE) {
	lock.lock();
	removeReady(dt);
	removeTimer(dt);
	lock.unlock();
    }
}

void Dispatcher::removeTimer(DispatchTimer &dt) {
    dt.flags &= ~DSP_Scheduled;
    if (dt.due == DSP_NEVER_DUE)
    	return;
    for (timermap::iterator it = timers.find(dt.due); it != timers.end(); ++it) {
	DispatchTimer *p = it->second;

	if (p == &dt) {
	    timers.erase(it);
	    break;
	} else if (p->due != dt.due) {
	    break;
	}
    }
    dt.due = DSP_NEVER_DUE;
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
	if (evtfd == -1) {
	    smap.erase(fd);
	    if (ds.flags & (DSP_SelectRead | DSP_SelectAccept))
		rset.unset(fd);
	    if (ds.flags & DSP_SelectWrite)
		wset.unset(fd);
	    ds.flags &= ~DSP_SelectAll;
	} else {
#ifdef DSP_EPOLL
	    ds.flags &= ~DSP_SelectAll;
	    lkr.unlock();
	    while (epoll_ctl(evtfd, EPOLL_CTL_DEL, fd, 0) == -1 &&
		interrupted(errno))
		;
#elif defined(DSP_KQUEUE)
	    struct kevent evt;

	    EV_SET(&evt, fd, ds.flags & DSP_SelectWrite ? EVFILT_WRITE :
		EVFILT_READ, EV_DELETE | EV_RECEIPT, 0, 0, &ds);
	    ds.flags &= ~DSP_SelectAll;
	    lkr.unlock();
	    while (kevent(evtfd, &evt, 1, NULL, 0, NULL) == -1 &&
		interrupted(errno))
		;
#endif
	}
#endif
    }
}

void Dispatcher::selectSocket(DispatchSocket &ds, ulong tm, Msg m) {
    uint ioflags;
    msec_t now = milliticks();
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
    epoll_event evt;
    static const long sockevts[] = {
	EPOLLIN | EPOLLPRI | EPOLLRDHUP, EPOLLOUT,
	EPOLLIN | EPOLLPRI | EPOLLRDHUP | EPOLLOUT, EPOLLIN, EPOLLOUT, 0, 0, 0
    };

    ZERO(evt);
    evt.data.ptr = &ds;
    evt.events = sockevts[m] | EPOLLERR | EPOLLHUP | EPOLLONESHOT;
#elif defined(DSP_KQUEUE)
    struct kevent evt;

    EV_SET(&evt, ds.fd(), EVFILT_READ, EV_ADD | EV_EOF | EV_ERROR | EV_ONESHOT |
	EV_RECEIPT, 0, 0, &ds);
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

    msec_t tmt = tm == DSP_NEVER ? DSP_NEVER_DUE : now + tm;
    bool wake = timer(ds, tmt);

    ds.flags |= DSP_Scheduled;
    ds.msg = Nomsg;
    if (sarray[m] != (ds.flags & DSP_SelectAll)) {
	ds.flags &= ~(DSP_SelectAll | DSP_IO);
	ds.flags |= sarray[m];
    	if (!ds.mapped) {
#ifdef DSP_EPOLL
	    op = EPOLL_CTL_ADD;
	    if (evtfd == -1)
#endif
		smap[ds.fd()] = &ds;
	    ds.mapped = true;
	}
#ifdef DSP_WIN32_ASYNC
	static const long sockevts[] = {
	    FD_READ | FD_CLOSE, FD_WRITE | FD_CLOSE,
	    FD_READ | FD_WRITE | FD_CLOSE, FD_ACCEPT, FD_CONNECT | FD_CLOSE,
	    FD_CLOSE
	};

	lkr.unlock();
	if (WSAAsyncSelect(ds.fd(), wnd, socketmsg, sockevts[(int)m])) {
	    lkr.lock();
	    removeTimer(ds);
	    ready(ds);
	}
#else
	if (evtfd == -1) {
	    if (m == Read || m == ReadWrite || m == Accept || m == Close)
		rset.set(ds.fd());
	    if (m == Write || m == ReadWrite || m == Connect)
		wset.set(ds.fd());
	    if (polling) {
		tmt = now;
		wake = true;
	    }
	} else {
#ifdef DSP_EPOLL
	    lkr.unlock();
	    while (epoll_ctl(evtfd, op, ds.fd(), &evt) == -1 &&
		interrupted(errno))
		;
#elif defined(DSP_KQUEUE)
	    if (m == Read || m == ReadWrite || m == Accept || m == Close) {
		while (kevent(evtfd, &evt, 1, NULL, 0, NULL) == -1 &&
		    interrupted(errno))
		    ;
	    }
	    if (m == Write || m == ReadWrite || m == Connect) {
		evt.filter = EVFILT_WRITE;
		while (kevent(evtfd, &evt, 1, NULL, 0, NULL) == -1 &&
		    interrupted(errno))
		    ;
	    }
	}
#endif
#endif
    }
    lkr.unlock();
    if (wake)
	wakeup(now, tmt);
}

void Dispatcher::deleteObj(DispatchObj &obj) {
    cancelReady(obj);
    if (obj.flags & DSP_Active)
	*activeobj.data() = NULL;
    if (obj.group->refcount.release() && !obj.group->active)
	delete obj.group;
}

void Dispatcher::addReady(DispatchObj &obj, bool hipri, Msg reason) {
    Locker lkr(lock);

    obj.msg = reason;
    ready(obj, hipri);
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
    else if (!threads)
	wake(1);
}

void DispatchObj::detach(void) { flags |= DSP_Detached; }

void DispatchObj::erase(void) {
    if (flags & (DSP_Active | DSP_SelectAll)) {
	cancel();
	flags |= DSP_Freed;
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

void DispatchClientSocket::connect(const Sockaddr &addr, ulong msec,
    DispatchObjCB cb) {
    if (!cb)
	cb = connected;
    bind(Sockaddr(addr.family()));
#ifndef DSP_WIN32_ASYNC
    blocking(false);
#endif
    if (Socket::connect(addr)) {
	msg = Dispatcher::Write;
	ready(cb);
    } else if (!blocked()) {
	msg = Dispatcher::Close;
	ready(cb);
    } else {
	select(cb, msec, Dispatcher::Connect);
    }
}

void DispatchClientSocket::connected() {
    onConnect();
}

DispatchListenSocket::DispatchListenSocket(Dispatcher &d, const Sockaddr &addr,
    int type, bool reuse, int queue, DispatchObjCB cb): DispatchSocket(d,
    type) {
    listen(addr, reuse, queue, cb);
}

bool DispatchListenSocket::listen(const Sockaddr &addr, bool reuse, int queue,
    DispatchObjCB cb) {
    if (!cb)
	cb = connection;
    sa = addr;
    if (!Socket::listen(addr, reuse, queue))
	return false;
    blocking(false);
    msleep(1);
    select(cb, DSP_NEVER, Dispatcher::Accept);
    return true;
}

void DispatchListenSocket::connection() {
    Socket s;
    bool again = true;

    if (msg != Dispatcher::Close && accept(s)) {
#ifdef __linux__
    	s.blocking(false);
#endif
	s.movehigh();
	again = onAccept(s);
    }
    if (again)
	relisten();
}

