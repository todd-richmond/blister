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
static const int MIN_EVENTS = 32;
static const int MAX_EVENTS = 128;

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

#elif defined(__linux__)

#define DSP_EPOLL

#include <sys/epoll.h>
#ifndef EPOLLRDHUP
#define EPOLLRDHUP 0x2000
#endif
#ifndef EPOLLONESHOT
#define EPOLLONESHOT (1 << 30)
#endif

typedef epoll_event event_t;

#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)

#define DSP_KQUEUE

#include <sys/event.h>
#include <sys/queue.h>
#ifndef NOTE_EOF
#define NOTE_EOF 0
#endif

typedef struct kevent event_t;

#elif defined(__sun__)

#define DSP_DEVPOLL

#include <sys/devpoll.h>
#include <sys/queue.h>

typedef struct pollfd event_t;

#else

#define DSP_POLL

#endif

Dispatcher::Dispatcher(const Config &config): cfg(config), due(DSP_NEVER_DUE),
    shutdown(-1), threads(0),
#ifdef DSP_WIN32_ASYNC
     interval(DSP_NEVER), wnd(0)
#else
    evtfd(-1), isock(SOCK_STREAM), polling(false), wsock(SOCK_STREAM)
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
    if (!group->refcount.referenced())
	delete group;
    return rlist;
}

int Dispatcher::run() {
    volatile DispatchObj *aobj = NULL;
    uint thrds;
    thread_t tid = THREAD_SELF();
    Lifo::Waiting waiting(lifo);

    activeobj.set(&aobj);
    priority(-1);
    lock.lock();
    while (!shutdown) {
	if (!exec(aobj, tid)) {
	    if (shutdown)
		break;
	    thrds = threads;
	    lock.unlock();
	    if (!lifo.wait(waiting, thrds == 1 ? INFINITE : MAX_WAIT_TIME)) {
		lock.lock();
		break;
	    }
	    lock.lock();
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
    MSG msg;
    msec_t now;
    timermap::iterator tit;

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
		    ds->flags = (ds->flags & ~DSP_Scheduled) | DSP_Ready;
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
	wake(count, true);
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
    Socket asock(SOCK_STREAM);
    Sockaddr addr(T("localhost"));
    uint count = 0;
    DispatchSocket *ds = NULL;
    DispatchTimer *dt = NULL;
    SocketSet irset, iwset, orset, owset, oeset;
    uint msec;
    msec_t now;
    socketmap::const_iterator sit;
    timermap::iterator tit;
    uint u;

#ifndef _WIN32
    sigset_t sigs;
#if defined(DSP_DEVPOLL) || defined(DSP_EPOLL) || defined(DSP_KQUEUE)
    event_t evts[MAX_EVENTS];
    int nevts = 0;

    ZERO(evts);
#endif
    sigemptyset(&sigs);
    sigaddset(&sigs, SIGPIPE);
    pthread_sigmask(SIG_BLOCK, &sigs, NULL);
#ifdef DSP_DEVPOLL
    do {
	evtfd = open("/dev/poll", O_RDWR);
    } while (evtfd == -1 && interrupted(errno));
#elif defined(DSP_EPOLL)
    do {
	evtfd = epoll_create(10000);
    } while (evtfd == -1 && interrupted(errno));
#elif defined(DSP_KQUEUE)
    timespec ts;

    evtfd = kqueue();
    EV_SET(&evts[0], -1, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(evtfd, &evts[0], 1, &evts[0], 1, NULL) != 1 || evts[0].ident !=
	(uintptr_t)-1 || evts[0].flags != EV_ERROR) {
	close(evtfd);
	evtfd = -1;
    }
#endif
    if (evtfd != -1)
	fcntl(evtfd, F_SETFD, 1);
#endif
    asock.listen(addr);
    asock.sockname(addr);
    asock.blocking(false);
    wsock.connect(addr, 100);
    if (!asock.accept(isock)) {
	shutdown = 1;
	return -1;
    }
    asock.close();
    isock.blocking(false);
    wsock.blocking(false);
    if (evtfd == -1) {
	rset.set(isock);
    } else {
#ifdef DSP_DEVPOLL
	evts[0].fd = isock.fd();
	evts[0].events = POLLIN;

	while (pwrite(evtfd, &evts[0], sizeof (evts[0]), 0) == -1 &&
	    interrupted(errno))
	    ;
#elif defined(DSP_EPOLL)
	evts[0].events = EPOLLIN;
	while (epoll_ctl(evtfd, EPOLL_CTL_ADD, isock.fd(), evts) == -1 &&
	    interrupted(errno))
	    ;
#elif defined(DSP_KQUEUE)
	EV_SET(&evts[0], isock.fd(), EVFILT_READ, EV_ADD, 0, 0, NULL);
	while (kevent(evtfd, evts, 1, NULL, 0, NULL) == -1 &&
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
	    msec = count ? MAX_SELECT_TIMER : SOCK_INFINITE;
	    due = count ? (now + MAX_SELECT_TIMER) : DSP_NEVER_DUE;
	} else {
	    dt = tit->second;
	    msec = dt->due > now ? (uint)(dt->due - now) : 0;
	    due = now + msec;
	}
	polling = true;
	lock.unlock();
	if (evtfd == -1) {
	    if (!SocketSet::iopoll(irset, orset, iwset, owset, oeset, msec)) {
		orset.clear();
		owset.clear();
	    }
	} else {
#ifdef DSP_DEVPOLL
	    dvpoll dvp = { evts, MAX_EVENTS, msec };

	    if ((nevts = ioctl(evtfd, DP_POLL, &dvp)) == -1)
		nevts = 0;
#elif defined(DSP_EPOLL)
	    if ((nevts = epoll_wait(evtfd, evts, MAX_EVENTS, msec)) == -1)
		nevts = 0;
#elif defined(DSP_KQUEUE)
	    ts.tv_sec = msec / 1000;
	    ts.tv_nsec = (msec % 1000) * 1000;
	    if ((nevts = kevent(evtfd, NULL, 0, evts, MAX_EVENTS, msec ==
		SOCK_INFINITE ? NULL : &ts)) == -1)
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
#if defined(DSP_DEVPOLL) || defined(DSP_EPOLL) || defined(DSP_KQUEUE)
	count += handleEvents(&evts[0], nevts);
#endif
	for (u = 0; u < orset.size(); u++) {
	    if (orset[u] == isock) {
		reset();
		continue;
	    }
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
	wake(count, true);
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
	lock.unlock();
	lifo.broadcast();
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

#if defined(DSP_DEVPOLL) || defined(DSP_EPOLL) || defined(DSP_KQUEUE)
uint Dispatcher::handleEvents(void *evts, int nevts) {
    uint count = 0;

    for (uint u = 0; u < (uint)nevts; u++) {
	DispatchSocket *ds;
	event_t *evt = (event_t *)evts + u;
#ifdef DSP_DEVPOLL
	socketmap::const_iterator sit;

	if (evt->fd == isock) {
	    reset();
	    continue;
	} else if ((sit = smap.find(evt->fd)) == smap.end()) {
	    continue;
	}
	ds = sit->second;
	if (ds->flags & DSP_Scheduled) {
	    if (evt->revents & POLLIN)
		ds->msg = ds->flags & DSP_SelectAccept ? Accept : Read;
	    if (evt->events & POLLOUT) {
		if (ds->msg == Nomsg)
		    ds->msg = Write;
		else
		    ds->flags |= DSP_Writeable;
	    }
	    if (evt->revents & (POLLERR | POLLHUP)) {
		if (ds->msg == Nomsg)
		    ds->msg = Close;
		else
		    ds->flags |= DSP_Closeable;
	    }
	    ds->flags = (ds->flags & ~DSP_Scheduled) | DSP_Ready;
	    if (!(ds->flags & DSP_Active)) {
		if (ds->msg == Accept)
		    rlist.push_front(ds);
		else
		    rlist.push_back(ds);
		count++;
	    }
	} else {
	    if (evt->events & POLLIN)
		ds->flags |= DSP_Readable;
	    if (evt->events & POLLOUT)
		ds->flags |= DSP_Writeable;
	    if (evt->events & (POLLERR | POLLHUP))
		ds->flags |= DSP_Closeable;
	}
#elif defined(DSP_EPOLL)
	ds = (DispatchSocket *)evt->data.ptr;
	if (!ds) {
	    reset();
	    continue;
	}
	if (ds->flags & DSP_Scheduled) {
	    if (evt->events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP))
		ds->msg = ds->flags & DSP_SelectAccept ? Accept : Read;
	    if (evt->events & EPOLLOUT) {
		if (ds->msg == Nomsg)
		    ds->msg = Write;
		else
		    ds->flags |= DSP_Writeable;
	    }
	    if (evt->events & (EPOLLERR | EPOLLHUP)) {
		if (ds->msg == Nomsg)
		    ds->msg = Close;
		else
		    ds->flags |= DSP_Closeable;
	    }
	    ds->flags = (ds->flags & ~DSP_Scheduled) | DSP_Ready;
	    if (!(ds->flags & DSP_Active)) {
		if (ds->msg == Accept)
		    rlist.push_front(ds);
		else
		    rlist.push_back(ds);
		count++;
	    }
	} else {
	    if (evt->events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP))
		ds->flags |= DSP_Readable;
	    if (evt->events & EPOLLOUT)
		ds->flags |= DSP_Writeable;
	    if (evt->events & (EPOLLERR | EPOLLHUP))
		ds->flags |= DSP_Closeable;
	}
#elif defined(DSP_KQUEUE)
	ds = (DispatchSocket *)evt->udata;
	if (!ds) {
	    reset();
	    continue;
	}
	if (ds->flags & DSP_Scheduled) {
	    if (evt->flags & EV_ERROR) {
		if (evt->data == EBADF || evt->data == EINVAL ||
		    evt->data == ENOENT)
		    continue;
		ds->err(evt->data);
		if (ds->msg == Nomsg)
		    ds->msg = Close;
		else
		    ds->flags |= DSP_Closeable;
	    } else if (evt->flags & EV_EOF) {
		if (ds->msg == Nomsg)
		    ds->msg = Close;
		else
		    ds->flags |= DSP_Closeable;
	    } else if (evt->filter == EVFILT_READ) {
		if (ds->msg == Nomsg)
		    ds->msg = ds->flags & DSP_SelectAccept ? Accept : Read;
		else
		    ds->flags |= DSP_Readable;
	    } else if (evt->filter == EVFILT_WRITE) {
		if (ds->msg == Nomsg)
		    ds->msg = Write;
		else
		    ds->flags |= DSP_Writeable;
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
	    if (evt->flags & EV_ERROR) {
		if (evt->data == EBADF || evt->data == EINVAL ||
		    evt->data == ENOENT)
		    continue;
		ds->err(evt->data);
		ds->flags |= DSP_Closeable;
	    } else if (evt->flags & EV_ERROR) {
		ds->flags |= DSP_Closeable;
	    } else if (evt->filter == EVFILT_READ) {
		ds->flags |= DSP_Readable;
	    } else if (evt->filter == EVFILT_WRITE) {
		ds->flags |= DSP_Writeable;
	    }
	}
#endif
	removeTimer(*ds);
    }
    return count;
}
#endif

bool Dispatcher::start(uint mthreads, uint stack, bool suspend, bool autoterm) {
    maxthreads = mthreads;
    stacksz = stack ? stack : 256 * 1024;
    shutdown = -1;
    if (!ThreadGroup::start(mthreads ? 8 * 1024 : stacksz, suspend, autoterm))
	return false;
    while (shutdown == -1)
	msleep(20);
    return !shutdown;
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

void Dispatcher::wake(uint tasks, bool master) {
    if (maxthreads == 0) {
	if (master) {
	    volatile DispatchObj *aobj;

	    activeobj.set(&aobj);
	    while (!shutdown && exec(aobj, THREAD_ID()))
		;
	}
    } else {
	if (tasks > MAX_WAKE_THREAD)
	    tasks = MAX_WAKE_THREAD;
	while (tasks && rlist) {
	    lock.unlock();
	    if (lifo.set()) {
		Thread *t;

		lock.lock();
		if (threads >= maxthreads)
		    break;
		threads++;
		lock.unlock();
		t = new Thread();
		t->start(worker, this, stacksz, this);
		while ((t = wait(0)) != NULL)
		    delete t;
	    }
	    tasks--;
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
    SpinLocker lkr(lock);

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
	} else if (ds.flags & DSP_SelectAll) {
#ifdef DSP_DEVPOLL
	    lkr.unlock();

	    event_t evt = { ds.fd(), POLLREMOVE, 0 };

	    ds.flags &= ~DSP_SelectAll;
	    while (pwrite(evtfd, &evt, sizeof (evt), 0) == -1 &&
		interrupted(errno))
		;
#elif defined(DSP_EPOLL)
	    ds.flags &= ~DSP_SelectAll;
	    lkr.unlock();
	    while (epoll_ctl(evtfd, EPOLL_CTL_DEL, fd, 0) == -1 &&
		interrupted(errno))
		;
#elif defined(DSP_KQUEUE)
	    lkr.unlock();

	    event_t evts[MIN_EVENTS];
	    int nevts = 0;
	    timespec ts = { 0, 0 };

	    if (ds.flags & (DSP_SelectRead | DSP_SelectAccept))
		EV_SET(&evts[nevts++], fd, EVFILT_READ, EV_DELETE, 0, 0, &ds);
	    if (ds.flags & DSP_SelectWrite)
		EV_SET(&evts[nevts++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, &ds);
	    ds.flags &= ~DSP_SelectAll;
	    while ((nevts = kevent(evtfd, evts, nevts, evts, MIN_EVENTS, &ts))
		== -1 && interrupted(errno))
		;
	    if (nevts > 0) {
		lkr.lock();
		nevts = handleEvents(&evts[0], nevts);
		if (nevts > 1)
		    wake(nevts - 1, false);
	    }
#endif
	}
#endif
    }
}

void Dispatcher::pollSocket(DispatchSocket &ds, ulong tm, Msg m) {
    uint flags;
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

#ifdef DSP_DEVPOLL
    static const long sockevts[] = {
	POLLIN, POLLOUT, POLLIN | POLLOUT, POLLIN, POLLOUT, 0, 0, 0
    };
    event_t evt = { ds.fd(), sockevts[m] | POLLERR | POLLHUP, 0 };
#elif defined(DSP_EPOLL)
    event_t evt;
    int op = EPOLL_CTL_MOD;
    static const long sockevts[] = {
	EPOLLIN | EPOLLPRI | EPOLLRDHUP, EPOLLOUT,
	EPOLLIN | EPOLLPRI | EPOLLRDHUP | EPOLLOUT, EPOLLIN, EPOLLOUT, 0, 0, 0
    };

    ZERO(evt);
    evt.data.ptr = &ds;
    evt.events = sockevts[m] | EPOLLERR | EPOLLHUP;
#elif defined(DSP_KQUEUE)
    event_t evts[MIN_EVENTS];
    int nevts = 0;
    timespec ts = { 0, 0 };
#endif
    SpinLocker lkr(lock);

    flags = ds.flags & DSP_IO;
    if (ioarray[m] & flags) {
	if ((flags & DSP_Writeable) &&
	    (m == Write || m == ReadWrite || m == Connect)) {
	    ds.flags &= ~DSP_Writeable;
	    ds.msg = Dispatcher::Write;
	} else if ((flags & DSP_Readable) && (m == Read || m == ReadWrite)) {
	    ds.flags &= ~DSP_Readable;
	    ds.msg = Dispatcher::Read;
	} else if ((flags & DSP_Acceptable) && m == Accept) {
	    ds.flags &= ~DSP_Acceptable;
	    ds.msg = Dispatcher::Accept;
	} else if (flags & DSP_Closeable) {
	    ds.flags &= ~DSP_Closeable;
	    ds.msg = Dispatcher::Close;
	}
	ready(ds, m == Accept);
	return;
    }

    msec_t tmt = tm == DSP_NEVER ? DSP_NEVER_DUE : now + tm;
    bool resched = timer(ds, tmt);

    ds.flags |= DSP_Scheduled;
    ds.msg = Nomsg;
    if (sarray[m] != (ds.flags & DSP_SelectAll)) {
    	if (!ds.mapped) {
#ifdef DSP_EPOLL
	    op = EPOLL_CTL_ADD;
	    if (evtfd == -1)
#elif defined(DSP_KQUEUE)
	    if (evtfd == -1)
#endif
		smap[ds.fd()] = &ds;
	    ds.mapped = true;
	}
	flags = ds.flags;
	ds.flags &= ~(DSP_SelectAll | DSP_IO);
	ds.flags |= sarray[m];
#ifdef DSP_WIN32_ASYNC
	static const long sockevts[] = {
	    FD_READ | FD_CLOSE, FD_WRITE | FD_CLOSE,
	    FD_READ | FD_WRITE | FD_CLOSE, FD_ACCEPT,
	    FD_CONNECT | FD_WRITE | FD_CLOSE, FD_CLOSE
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
		resched = true;
	    }
	} else {
	    lkr.unlock();
#ifdef DSP_DEVPOLL
	    /*
	    if (m == Read || m == ReadWrite || m == Accept || m == Close)
		evt.events = POLLIN;
	    if (m == Write || m == ReadWrite || m == Connect)
		evt.events |= POLLOUT;
	    */
	    while (pwrite(evtfd, &evt, sizeof (evt), 0) == -1 &&
		interrupted(errno))
		;
#elif defined(DSP_EPOLL)
	    while (epoll_ctl(evtfd, op, ds.fd(), &evt) == -1 &&
		interrupted(errno))
		;
#elif defined(DSP_KQUEUE)
	    if (m == Read || m == ReadWrite || m == Accept || m == Close) {
		EV_SET(&evts[nevts++], ds.fd(), EVFILT_READ, EV_ADD |
		    EV_ONESHOT, NOTE_EOF, 0, &ds);
		if (flags & DSP_SelectWrite && m != ReadWrite) {
		    EV_SET(&evts[nevts++], ds.fd(), EVFILT_WRITE, EV_DELETE, 0,
			0, &ds);
		}
	    }
	    if (m == Write || m == ReadWrite || m == Connect) {
		EV_SET(&evts[nevts++], ds.fd(), EVFILT_WRITE, EV_ADD |
		    EV_ONESHOT, NOTE_EOF, 0, &ds);
		if (flags & DSP_SelectRead && m != ReadWrite) {
		    EV_SET(&evts[nevts++], ds.fd(), EVFILT_READ, EV_DISABLE, 0,
			0, &ds);
		}
	    }
	    while ((nevts = kevent(evtfd, evts, nevts, evts, MIN_EVENTS, &ts))
		== -1 && interrupted(errno))
		;
	    if (nevts > 0) {
		lkr.lock();
		nevts = handleEvents(&evts[0], nevts);
		if (nevts > 1)
		    wake(nevts - 1, false);
	    }
#endif
	}
#endif
    }
    lkr.unlock();
    if (resched)
	wakeup(now, tmt);
}

void Dispatcher::deleteObj(DispatchObj &obj) {
    cancelReady(obj);
    if (obj.flags & DSP_Active)
	*activeobj.get() = NULL;
    if (!obj.group->refcount.release() && !obj.group->active)
	delete obj.group;
}

void Dispatcher::addReady(DispatchObj &obj, bool hipri, Msg reason) {
    FastSpinLocker lkr(lock);

    obj.msg = reason;
    ready(obj, hipri);
}

void Dispatcher::cancelReady(DispatchObj &obj) {
    if (obj.flags & DSP_ReadyAll) {
	FastSpinLocker lkr(lock);

	removeReady(obj);
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
    if (!(obj.flags & DSP_Active))
	wake(1, false);
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
    DispatchTimer(d, msec), Socket(type), mapped(false) {
    flags |= DSP_Socket;
}

DispatchSocket::DispatchSocket(Dispatcher &d, const Socket &s, ulong msec):
    DispatchTimer(d, msec), Socket(s), mapped(false) {
    flags |= DSP_Socket;
}

DispatchSocket::DispatchSocket(DispatchObj &parent, int type, ulong msec):
    DispatchTimer(parent, msec), Socket(type), mapped(false) {
    flags |= DSP_Socket;
}

DispatchSocket::DispatchSocket(DispatchObj &parent, const Socket &s, ulong msec):
    DispatchTimer(parent, msec), Socket(s), mapped(false) {
    flags |= DSP_Socket;
}

void DispatchClientSocket::connect(const Sockaddr &sa, ulong msec, DispatchObjCB
    cb) {
    if (!cb)
	cb = connected;
    if (open(sa.family()) && blocking(false) && Socket::connect(sa)) {
	msg = Dispatcher::Write;
	ready(cb);
    } else if (!blocked()) {
	msg = Dispatcher::Close;
	ready(cb);
    } else {
	poll(cb, msec, Dispatcher::Connect);
    }
}

void DispatchClientSocket::connected() {
    onConnect();
}

bool DispatchListenSocket::listen(const Sockaddr &sa, bool reuse, int queue,
    DispatchObjCB cb) {
    if (!cb)
	cb = connection;
    this->sa = sa;
    if (!Socket::listen(sa, reuse, queue))
	return false;
    blocking(false);
    msleep(1);
    poll(cb, DSP_NEVER, Dispatcher::Accept);
    return true;
}

DispatchListenSocket::DispatchListenSocket(Dispatcher &d, const Sockaddr &sa,
    int type, bool reuse, int queue, DispatchObjCB cb): DispatchSocket(d, type)
    {
    listen(sa, reuse, queue, cb);
}

void DispatchListenSocket::connection() {
    Socket s;

    if (msg != Dispatcher::Close && accept(s)) {
	relisten();
#ifdef __linux__
    	s.blocking(false);
#endif
	s.movehigh();
	onAccept(s);
    } else {
	relisten();
    }
}

