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

#include "stdapi.h"
#include <signal.h>
#include <time.h>
#include "Dispatch.h"

#ifdef _WIN32
#define CLOEXEC(fd)
#else
#define CLOEXEC(fd) (void)fcntl((fd), F_SETFD, FD_CLOEXEC)
#endif
#define RETRY(call) while ((int)(call) == -1 && interrupted(errno))

static const uint MAX_WAIT_TIME = 1 * 60 * 1000;
static const uint MAX_IDLE_TIMER = 10 * 1000;
static const uint MIN_IDLE_TIMER = 1 * 1000;
static const uint MAX_EVENTS = 128;

static const uint DSP_Socket = 0x0001;
static const uint DSP_Detached = 0x0002;
static const uint DSP_Connecting = 0x0004;
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
#include <sys/eventfd.h>
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

static const uint MIN_EVENTS = 32;

#elif defined(__sun__)

#define DSP_DEVPOLL

#include <sys/devpoll.h>
#include <sys/queue.h>

typedef struct pollfd event_t;

#else

#define DSP_POLL

#endif

Dispatcher::Dispatcher(const Config &config): cfg(config), due(DSP_NEVER_DUE),
    maxthreads(0), running(0), shutdown(true), stacksz(0), workers(0),
#ifdef DSP_WIN32_ASYNC
     interval(DSP_NEVER), wnd(0)
#else
    evtfd(-1), wfd(-1), isock(SOCK_STREAM), polling(false), wsock(SOCK_STREAM)
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

bool Dispatcher::exec() {
    while (rlist && !shutdown) {
	DispatchObj::Group *group;
	DispatchObj *obj = rlist.pop_front();

	if (!obj) {
	    continue;
	} else if (obj->flags & DSP_Freed) {
	    lock.unlock();
	    delete obj;
	    lock.lock();
	    continue;
	} else if ((group = obj->group)->active) {
	    obj->flags = (obj->flags & ~DSP_Ready) | DSP_ReadyGroup;
	    group->glist.push_back(*obj);
	    continue;
	} else {
	    group->active = true;
	}
	obj->flags = (obj->flags & ~DSP_Ready) | DSP_Active;
	running++;
	lock.unlock();
	obj->dcb(obj);
	if (obj->flags & DSP_Freed && !(obj->flags & DSP_Socket)) {
	    obj->flags &= ~DSP_Active;
	    delete obj;
	    obj = NULL;
	}
	lock.lock();
	running--;
	if (obj)
	    obj->flags &= ~DSP_Active;
	group->active = false;
	if (group->glist) {
	    if (obj && obj->flags & DSP_Ready) {
		obj->flags = (obj->flags & ~DSP_Ready) | DSP_ReadyGroup;
		group->glist.push_back(*obj);
	    }
	    obj = group->glist.pop_front();
	    obj->flags = (obj->flags & ~DSP_ReadyGroup) | DSP_Ready;
	    rlist.push_back(*obj);
	} else if (obj && obj->flags & DSP_Ready) {
	    rlist.push_back(*obj);
	}
    }
    return !shutdown;
}

int Dispatcher::run() {
    Lifo::Waiting waiting;

    lock.lock();
    while (exec()) {
	bool b = workers == lifo.size() + 1;

	lock.unlock();
	b = lifo.wait(waiting, b ? INFINITE : MAX_WAIT_TIME);
	lock.lock();
	if (!b)
	    break;
    }
    workers--;
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

    if ((wnd = CreateWindow(DispatchClass, T("Dispatch Window"), 0, 0, 0,
	CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, GetModuleHandle(NULL), 0)) == NULL) {
	shutdown = true;
	return -1;
    }
    due = DSP_NEVER_DUE;
    lifo.open();
    running = 0;
    shutdown = false;
    workers = 0;
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
		ds = static_cast<DispatchSocket *>(it->second);
		if (ds->flags & DSP_Scheduled) {
		    // uint err = WSAGETSELECTERROR(msg.lParam);
		    if (evt & FD_READ)
			ds->msg = DispatchRead;
		    else if (evt & FD_ACCEPT)
			ds->msg = DispatchAccept;
		    if (evt & (FD_CONNECT | FD_WRITE)) {
			if (ds->msg == DispatchNone)
			    ds->msg = DispatchWrite;
		    	else
			    ds->flags |= DSP_Writeable;
		    }
		    if (evt & FD_CLOSE) {
			if (ds->msg == DispatchNone)
			    ds->msg = DispatchClose;
		    	else
			    ds->flags |= DSP_Closeable;
		    }
		    if (ready(*ds, ds->msg == DispatchAccept))
			count++;
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
	    now = mticks();
	    lock.lock();
	    while ((dt = timers.get(now)) != NULL) {
		dt->msg = DispatchTimeout;
		if (ready(*dt, false))
		    count++;
	    }
	    dt = timers.peek();
	    if (dt == NULL && timers.half() < now + MIN_IDLE_TIMER) {
		timers.reorder(now + MAX_IDLE_TIMER);
		dt = timers.peek();
	    }
	    if (dt == NULL) {
		if (timers.empty()) {
		    due = DSP_NEVER_DUE;
		    interval = DSP_NEVER;
		    KillTimer(wnd, DSP_TimerID);
		} else {
		    due = now + MAX_IDLE_TIMER;
		    interval = MAX_IDLE_TIMER;
		    SetTimer(wnd, DSP_TimerID, interval, NULL);
		}
	    } else if (dt->due < now + interval || interval < MIN_IDLE_TIMER) {
		due = dt->due > now ? dt->due : now;
		interval = (ulong)(dt->due - now);
		SetTimer(wnd, DSP_TimerID, interval, NULL);
	    } else {
		due = now + interval;
	    }
	} else {
	    DefWindowProc(wnd, msg.message, msg.wParam, msg.lParam);
	    continue;
	}
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
    msec_t now;
    uint u = 0;

#ifdef DSP_POLL
    evtfd = wfd = -1;
#else
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
    evtfd = open("/dev/poll", O_RDWR);
#elif defined(DSP_EPOLL)
    evtfd = epoll_create(1024);
#elif defined(DSP_KQUEUE)
    timespec ts;

    evtfd = kqueue();
    // ensure kqueue functions properly 
    EV_SET(&evts[0], -1, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(evtfd, &evts[0], 1, &evts[0], 1, NULL) != 1 || evts[0].ident !=
	(uintptr_t)-1 || !(evts[0].flags & EV_ERROR)) {
	close(evtfd);
	evtfd = -1;
    }
#endif
#endif
#if defined(DSP_EPOLL) || defined(DSP_KQUEUE)
#define CLOSE_EVTFD(fd)
    if (evtfd == -1) {
#else
#define CLOSE_EVTFD(fd)	close(fd)
#endif
	Socket asock(SOCK_STREAM);
	Sockaddr addr(T("127.0.0.1"));

	if (!asock.listen(addr) || !asock.sockname(addr) ||
	    !asock.blocking(false)) {
	    CLOSE_EVTFD(evtfd);
	    return -1;
	}
	(void)wsock.connect(addr, 0);
	while (!asock.accept(isock)) {
	    if (++u == 50) {
		CLOSE_EVTFD(evtfd);
		return -1;
	    }
	    msleep(100);
	}
	asock.close();
	isock.blocking(false);
	isock.cloexec();
	wsock.blocking(false);
	wsock.cloexec();
#if defined(DSP_EPOLL) || defined(DSP_KQUEUE)
    }
#endif
    if (evtfd == -1) {
	CLOEXEC(isock.fd());
	CLOEXEC(wsock.fd());
	rset.set(isock);
    } else {
	CLOEXEC(evtfd);
#ifdef DSP_DEVPOLL
	evts[0].fd = isock.fd();
	evts[0].events = POLLIN;

	RETRY(pwrite(evtfd, &evts[0], sizeof (evts[0]), 0));
#elif defined(DSP_EPOLL)
	wfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
	evts[0].events = EPOLLIN;
	RETRY(epoll_ctl(evtfd, EPOLL_CTL_ADD, wfd, evts));
#endif
    }
    lock.lock();
    due = DSP_NEVER_DUE;
    lifo.open();
    running = 0;
    shutdown = false;
    workers = 0;
    now = mticks();
    while (!shutdown) {
	uint count = 0;
	DispatchTimer *dt = NULL;
	SocketSet irset, iwset, orset, owset, oeset;
	uint msec;
	socketmap::const_iterator sit;

	if (evtfd == -1) {
	    irset = rset;
	    iwset = wset;
	}
	dt = timers.peek();
	if (dt == NULL && timers.half() < now + MIN_IDLE_TIMER) {
	    timers.reorder(now + MAX_IDLE_TIMER);
	    dt = timers.peek();
	}
	if (dt == NULL) {
	    if (timers.empty()) {
		msec = SOCK_INFINITE;
		due = DSP_NEVER_DUE;
	    } else {
		msec = MAX_IDLE_TIMER;
		due = now + MAX_IDLE_TIMER;
	    }
	} else {
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
	    ts.tv_nsec = (msec % 1000) * 1000000;
	    if ((nevts = kevent(evtfd, NULL, 0, evts, MAX_EVENTS, msec ==
		SOCK_INFINITE ? NULL : &ts)) == -1)
		nevts = 0;
#endif
	}
	polling = false;
	count = 0;
	now = mticks();
	lock.lock();
	if (shutdown)
	    break;
	if (evtfd == -1) {
	    DispatchSocket *ds = NULL;
	    socket_t fd;

	    for (u = 0; u < orset.size(); u++) {
		fd = orset[u];
		if ((sit = smap.find(fd)) == smap.end()) {
		    if (fd == isock)
			reset();
		    continue;
		}
		rset.unset(fd);
		ds = sit->second;
		if (ds->flags & DSP_SelectWrite)
		    wset.unset(fd);
		ds->flags &= ~DSP_SelectAll;
		if (ds->flags & DSP_Scheduled) {
		    ds->msg = (ds->flags & DSP_SelectAccept) ? DispatchAccept :
			DispatchRead;
		    if (ready(*ds, ds->msg == DispatchAccept))
			count++;
		} else {
		    ds->flags |= (ds->flags & DSP_SelectAccept) ?
			DSP_Acceptable : DSP_Readable;
		}
		removeTimer(*ds);
	    }
	    for (u = 0; u < owset.size(); u++) {
		fd = owset[u];
		wset.unset(fd);
		if ((sit = smap.find(fd)) == smap.end())
		    continue;
		ds = sit->second;
		if (ds->flags & DSP_SelectRead)
		    rset.unset(fd);
		ds->flags &= ~DSP_SelectAll;
		if (ds->flags & DSP_Scheduled) {
		    ds->msg = DispatchWrite;
		    if (ready(*ds))
			count++;
		} else {
		    ds->flags |= DSP_Writeable;
		}
		removeTimer(*ds);
	    }
	    for (u = 0; u < oeset.size(); u++) {
		fd = oeset[u];
		if ((sit = smap.find(fd)) == smap.end())
		    continue;
		ds = sit->second;
		if (ds->flags & DSP_SelectRead)
		    rset.unset(fd);
		if (ds->flags & DSP_SelectWrite)
		    wset.unset(fd);
		ds->flags &= ~DSP_SelectAll;
		if (ds->flags & DSP_Scheduled) {
		    ds->msg = DispatchClose;
		    if (ready(*ds))
			count++;
		} else {
		    ds->flags |= DSP_Closeable;
		}
		removeTimer(*ds);
	    }
	} else {
#if defined(DSP_DEVPOLL) || defined(DSP_EPOLL) || defined(DSP_KQUEUE)
	    count += handleEvents(evts, (uint)nevts);
#endif
	}
	while ((dt = timers.get(now)) != NULL) {
	    dt->msg = DispatchTimeout;
	    if (ready(*dt, false))
		count++;
	}
	wake(count, true);
    }
    cleanup();
    lock.unlock();
    if (wfd != -1)
	close(wfd);
    if (evtfd != -1)
	close(evtfd);
    return 0;
}

#endif

void Dispatcher::cleanup(void) {
    lock.unlock();
    for (;;) {
	Thread *t;

	lifo.broadcast();
	if ((t = wait(30000)) == NULL)
	    break;
	delete t;
    };
    lock.lock();
    while (rlist) {
	DispatchObj *obj = rlist.pop_front();

	if (!obj)
	    break;
	if (obj->group->glist)
	    rlist.push_front(obj->group->glist);
	if (obj->flags & DSP_ReadyGroup)
	    obj->flags = (obj->flags & ~DSP_ReadyGroup) | DSP_Ready;
	lock.unlock();
	if (obj->flags & DSP_Freed)
	    delete obj;
	else
	    obj->terminate();
	lock.lock();
    }
    lock.unlock();
    while (flist)
	delete flist.pop_front();
    lock.lock();

    DispatchTimer *dt;

    while ((dt = timers.get()) != NULL) {
	lock.unlock();
	dt->terminate();
	lock.lock();
    }
    lock.unlock();
    while (flist)
	delete flist.pop_front();
    lock.lock();
    lifo.close();
}

#if defined(DSP_DEVPOLL) || defined(DSP_EPOLL) || defined(DSP_KQUEUE)
uint Dispatcher::handleEvents(const void *evts, uint nevts) {
    uint count = 0;

    for (uint u = 0; u < nevts; u++) {
	DispatchSocket *ds;
	const event_t *evt = (const event_t *)evts + u;

#ifdef DSP_DEVPOLL
#define DSP_EVENT_ERR(evt)	evt->revents & (POLLERR | POLLHUP)
#define DSP_EVENT_READ(evt)	evt->revents & POLLIN
#define DSP_EVENT_WRITE(evt)	evt->revents & POLLOUT

	socketmap::const_iterator sit;

	if (evt->fd == isock)
	    ds = NULL;
	else if ((sit = smap.find(evt->fd)) == smap.end())
	    continue;
	else
	    ds = sit->second;

#elif defined(DSP_EPOLL)
#define DSP_EVENT_ERR(evt)	evt->events & (EPOLLERR | EPOLLHUP)
#define DSP_EVENT_READ(evt)	evt->events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP)
#define DSP_EVENT_WRITE(evt)	evt->events & EPOLLOUT

	ds = static_cast<DispatchSocket *>(evt->data.ptr);

#elif defined(DSP_KQUEUE)
#define DSP_EVENT_ERR(evt)	evt->flags & (EV_EOF | EV_ERROR)
#define DSP_EVENT_READ(evt)	evt->filter == EVFILT_READ && evt->data > 0
#define DSP_EVENT_WRITE(evt)	evt->filter == EVFILT_WRITE && evt->data > 0

	ds = static_cast<DispatchSocket *>(evt->udata);
#endif
	if (!ds) {
	    reset();
	    continue;
	} else if (ds->flags & DSP_Freed) {
	    continue;
	}
	if (DSP_EVENT_READ(evt)) {
	    if (ds->msg == DispatchNone && (ds->flags & DSP_Scheduled))
		ds->msg = (ds->flags & DSP_SelectAccept) ? DispatchAccept :
		    DispatchRead;
	    else
		ds->flags |= DSP_Readable;
	}
	if (DSP_EVENT_WRITE(evt)) {
	    if (ds->flags & DSP_Connecting)
		ds->msg = DispatchConnect;
	    else if (ds->msg == DispatchNone && (ds->flags & DSP_Scheduled))
		ds->msg = DispatchWrite;
	    else
		ds->flags |= DSP_Writeable;
	}
	if (DSP_EVENT_ERR(evt)) {
	    if (ds->msg == DispatchNone && (ds->flags & DSP_Scheduled))
		ds->msg = DispatchClose;
	    else
		ds->flags |= DSP_Closeable;
	}
	if ((ds->flags & DSP_Scheduled) && ready(*ds, ds->msg ==
	    DispatchAccept))
	    count++;
	removeTimer(*ds);
    }
    if (flist) {
	if (!count)
	    count = 1;
	rlist.push_back(flist);
    }
    return count;
}
#endif

#ifndef DSP_WIN32_ASYNC
void Dispatcher::reset(void) {
    char buf[16];

    lock.unlock();
#ifdef DSP_EPOLL
    RETRY(read(wfd, buf, sizeof (buf)));
#else
    RETRY(wsock.read(buf, sizeof (buf)));
#endif
    lock.lock();
}
#endif

bool Dispatcher::start(uint mthreads, uint stack) {
    maxthreads = mthreads;
    stacksz = stack ? stack : 128 * 1024;
    if (ThreadGroup::start(mthreads ? 8 * 1024 : stacksz, false, false)) {
	while (shutdown && getMainThread().getState() == Running) {
	    msleep(20);
	    lock.lock();
	    lock.unlock();
	}
    }
    return !shutdown;
}

void Dispatcher::stop() {
    if (shutdown)
    	return;
    lock.lock();
    shutdown = true;
    wakeup(0);
    lock.unlock();
    waitForMain();
}

void Dispatcher::wake(uint tasks, bool main) {
    if (maxthreads == 0) {
	if (main)
	    exec();
	return;
    }
    while (tasks && rlist && !shutdown) {
	uint wake = workers - running - lifo.size();

	wake = wake >= rlist.size() ? 0 : rlist.size() - wake;
	if (wake && wake < tasks)
	    tasks = wake;
	if (lifo && (tasks / 2 + 1) >= lifo.size()) {
	    lock.unlock();
	    wake = lifo.broadcast();
	    tasks = wake >= tasks ? 0 : tasks - wake;
	} else {
	    bool b = workers == 0;

	    lock.unlock();
	    if (b || lifo.set()) {
		lock.lock();
		if (workers >= maxthreads || shutdown)
		    break;
		workers++;
		lock.unlock();

		Thread *t = new Thread();

		t->start(worker, this, stacksz, this);
		while ((t = wait(0)) != NULL)
		    delete t;
	    } else if (tasks > 1) {
		THREAD_PAUSE();
	    }
	    tasks--;
	}
	lock.lock();
    }
}

void Dispatcher::wakeup(ulong msec) {
#ifdef DSP_WIN32_ASYNC
    interval = msec;
    do {
	SetTimer(wnd, DSP_TimerID, msec, NULL);
    } while (interval > msec);
#else
    (void)msec;
    if (polling) {
	polling = false;
	if (wsock.open()) {
	    wsock.write("", 1);
	} else {
#ifdef DSP_EPOLL
	    eventfd_t inc = 1;

	    RETRY(eventfd_write(wfd, inc));
#elif defined(DSP_KQUEUE)
	    event_t evt;
	    timespec ts;

	    ts.tv_sec = msec / 1000;
	    ts.tv_nsec = (msec % 1000) * 1000000;
	    EV_SET(&evt, 0, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, 0, NULL);
	    RETRY(kevent(evtfd, &evt, 1, NULL, 0, &ts));
#endif
	}
    }
#endif
}

void Dispatcher::cancelTimer(DispatchTimer &dt, bool del) {
    FastSpinLocker lkr(lock);

    if (dt.flags & DSP_ReadyAll) {
	removeReady(dt);
    } else if (del) {
	timers.erase(dt);
    } else {
	removeTimer(dt);
	dt.flags &= ~DSP_Scheduled;
    }
}

void Dispatcher::setTimer(DispatchTimer &dt, ulong tm) {
    msec_t now = tm ? mticks() : 0;
    msec_t tmt = tm == DSP_NEVER ? DSP_NEVER_DUE : now + tm;

    lock.lock();
    if (tm) {
	timers.set(dt, tmt);
	if (tmt < due) {
	    due = tmt;
	    lock.unlock();
	    wakeup((ulong)(due - now));
	    return;
	}
    } else {
	removeTimer(dt);
	ready(dt);
    }
    lock.unlock();
}

void Dispatcher::cancelSocket(DispatchSocket &ds, bool close, bool del) {
    if (ds.flags & DSP_Freed)
	return;

    socket_t fd = ds.fd();
    SpinLocker lkr(lock);

    if (ds.flags & DSP_ReadyAll) {
	removeReady(ds);
    } else {
	removeTimer(ds);
	ds.flags &= ~DSP_Scheduled;
    }
    if (del)
	ds.flags |= DSP_Freed;
    if (ds.mapped && fd != INVALID_SOCKET) {
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
	} else if (ds.flags & DSP_SelectAll && !close) {
#ifdef DSP_DEVPOLL
	    ds.flags &= ~DSP_SelectAll;
	    lkr.unlock();

	    event_t evt = { fd, POLLREMOVE, 0 };

	    RETRY(pwrite(evtfd, &evt, sizeof (evt), 0));
#elif defined(DSP_EPOLL)
	    ds.flags &= ~DSP_SelectAll;
	    lkr.unlock();
	    RETRY(epoll_ctl(evtfd, EPOLL_CTL_DEL, fd, 0));
#elif defined(DSP_KQUEUE)
	    event_t chgs[2], evts[MIN_EVENTS];
	    uint nevts = 0;
	    static timespec ts = { 0, 0 };

	    if (ds.flags & (DSP_SelectRead | DSP_SelectAccept))
		EV_SET(&chgs[nevts++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	    if (ds.flags & DSP_SelectWrite)
		EV_SET(&chgs[nevts++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	    ds.flags &= ~DSP_SelectAll;
	    lkr.unlock();
	    RETRY(nevts = (uint)kevent(evtfd, chgs, (int)nevts, evts, MIN_EVENTS, &ts));
	    if (nevts > 0) {
		lkr.lock();
		nevts = handleEvents(evts, nevts);
		if (nevts > 1)
		    wake(nevts, false);
	    }
#endif
	}
#endif
    }
    if (close) {
	lkr.unlock();
	ds.closesocket();
	if (del) {
	    lkr.lock();
	    flist.push_back(ds);
	}
    }
}

void Dispatcher::pollSocket(DispatchSocket &ds, ulong tm, DispatchMsg m) {
    uint flags;
    msec_t now = mticks();
    bool resched = false;
    msec_t tmt = tm == DSP_NEVER ? DSP_NEVER_DUE : now + tm;
    static uint ioarray[] = {
	DSP_Readable | DSP_Closeable, DSP_Writeable | DSP_Closeable,
	DSP_Readable | DSP_Writeable | DSP_Closeable, DSP_Acceptable,
	DSP_Writeable | DSP_Closeable, DSP_Closeable, 0, 0
    };
    static uint sarray[] = {
	DSP_SelectRead, DSP_SelectWrite, DSP_SelectRead | DSP_SelectWrite,
	DSP_SelectAccept, DSP_Connecting | DSP_SelectWrite, DSP_SelectClose, 0,
	0
    };

#ifdef DSP_WIN32_ASYNC
    static const long sockevts[] = {
	FD_READ | FD_CLOSE, FD_WRITE | FD_CLOSE, FD_READ | FD_WRITE | FD_CLOSE,
	FD_ACCEPT, FD_CONNECT | FD_WRITE | FD_CLOSE, FD_CLOSE, 0, 0
    };
#elif defined(DSP_DEVPOLL)
    static const long sockevts[] = {
	POLLIN, POLLOUT, POLLIN | POLLOUT, POLLIN, POLLOUT, 0, 0, 0
    };
#elif defined(DSP_EPOLL)
    int op = EPOLL_CTL_MOD;
    static const long sockevts[] = {
	EPOLLIN | EPOLLPRI | EPOLLRDHUP, EPOLLOUT,
	EPOLLIN | EPOLLPRI | EPOLLRDHUP | EPOLLOUT, EPOLLIN, EPOLLOUT, 0, 0, 0
    };
#endif
    SpinLocker lkr(lock);

    flags = ds.flags & DSP_IO;
    if (ioarray[m] & flags) {
	if ((flags & DSP_Writeable) &&
	    (m == DispatchWrite || m == DispatchReadWrite || m ==
	    DispatchConnect)) {
	    ds.flags &= ~DSP_Writeable;
	    ds.msg = m == DispatchConnect ? DispatchConnect : DispatchWrite;
	} else if ((flags & DSP_Readable) && (m == DispatchRead || m ==
	    DispatchReadWrite)) {
	    ds.flags &= ~DSP_Readable;
	    ds.msg = DispatchRead;
	} else if (flags & DSP_Acceptable) {
	    ds.flags &= ~DSP_Acceptable;
	    ds.msg = DispatchAccept;
	} else if (flags & DSP_Closeable) {
	    ds.flags &= ~DSP_Closeable;
	    ds.msg = DispatchClose;
	}
	ready(ds, m == DispatchAccept);
	return;
    }
    timers.set(ds, tmt);
    if (tmt < due) {
	due = tmt;
	resched = true;
    }
    ds.flags |= DSP_Scheduled;
    ds.msg = DispatchNone;
    if (sarray[m] == (ds.flags & DSP_SelectAll)) {
	if (resched) {
	    lkr.unlock();
	    wakeup((ulong)(due - now));
	}
	return;
    }
    if (!ds.mapped) {
#ifdef DSP_EPOLL
	op = EPOLL_CTL_ADD;
#endif
#if defined(DSP_EPOLL) || defined(DSP_KQUEUE)
	if (evtfd == -1)
#endif
	    smap[ds.fd()] = &ds;
	ds.mapped = true;
    }
#ifdef DSP_KQUEUE
    flags = ds.flags;
#endif
    ds.flags &= ~(DSP_SelectAll | DSP_IO);
    ds.flags |= sarray[m];
#ifdef DSP_WIN32_ASYNC
    lkr.unlock();
    if (WSAAsyncSelect(ds.fd(), wnd, socketmsg, sockevts[(int)m])) {
	lkr.lock();
	ds.msg = DispatchClose;
	ready(ds);
	removeTimer(ds);
    }
#else
    if (evtfd == -1) {
	if (m == DispatchRead || m == DispatchReadWrite || m ==
	    DispatchAccept || m == DispatchClose)
	    rset.set(ds.fd());
	if (m == DispatchWrite || m == DispatchReadWrite || m ==
	    DispatchConnect)
	    wset.set(ds.fd());
	if (polling)
	    resched = true;
    } else {
	lkr.unlock();
#ifdef DSP_DEVPOLL
	event_t evt = { ds.fd(), sockevts[m] | POLLERR | POLLHUP, 0 };

	RETRY(pwrite(evtfd, &evt, sizeof (evt), 0));
#elif defined(DSP_EPOLL)
	event_t evt;

	evt.data.ptr = &ds;
	evt.events = sockevts[m] | EPOLLERR | EPOLLHUP;
	RETRY(epoll_ctl(evtfd, op, ds.fd(), &evt));
#elif defined(DSP_KQUEUE)
	event_t chgs[4], evts[MIN_EVENTS];
	uint nevts = 0;
	static timespec ts = { 0, 0 };

	if (m == DispatchRead || m == DispatchReadWrite || m ==
	    DispatchAccept || m == DispatchClose) {
	    EV_SET(&chgs[nevts++], ds.fd(), EVFILT_READ, EV_ADD,
		NOTE_EOF, 0, &ds);
	    if ((flags & DSP_SelectWrite) && m != DispatchReadWrite) {
		EV_SET(&chgs[nevts++], ds.fd(), EVFILT_WRITE, EV_DISABLE, 0, 0,
		    &ds);
	    }
	}
	if (m == DispatchWrite || m == DispatchReadWrite || m ==
	    DispatchConnect) {
	    EV_SET(&chgs[nevts++], ds.fd(), EVFILT_WRITE, EV_ADD,
		NOTE_EOF, 0, &ds);
	    if ((flags & DSP_SelectRead) && m != DispatchReadWrite) {
		EV_SET(&chgs[nevts++], ds.fd(), EVFILT_READ, EV_DISABLE, 0, 0,
		    &ds);
	    }
	}
	RETRY(nevts = (uint)kevent(evtfd, chgs, (int)nevts, evts, MIN_EVENTS, &ts));
	if (nevts > 0) {
	    lkr.lock();
	    nevts = handleEvents(evts, nevts);
	    if (nevts > 1)
		wake(nevts, false);
	}
#endif
    }
#endif
    if (resched) {
	lkr.unlock();
	wakeup((ulong)(due - now));
    }
}

void Dispatcher::addReady(DispatchObj &obj, bool hipri, DispatchMsg reason) {
    lock.lock();
    obj.msg = reason;
    ready(obj, hipri);
    lock.unlock();
}

void Dispatcher::cancelReady(DispatchObj &obj) {
    FastSpinLocker lkr(lock);

    if (obj.flags & DSP_ReadyAll)
	removeReady(obj);
}

void Dispatcher::removeReady(DispatchObj &obj) {
    if (obj.flags & DSP_Ready) {
	obj.flags &= ~DSP_Ready;
	rlist.pop(obj);
    } else if (obj.flags & DSP_ReadyGroup) {
	obj.flags &= ~DSP_ReadyGroup;
	obj.group->glist.pop(obj);
    }
}

bool Dispatcher::ready(DispatchObj &obj, bool hipri) {
    if (obj.flags & DSP_Active) {
	obj.flags = (obj.flags & ~DSP_Scheduled) | DSP_Ready;
	return false;
    } else if (obj.group->active) {
	obj.flags = (obj.flags & ~DSP_Scheduled) | DSP_ReadyGroup;
	if (hipri)
	    obj.group->glist.push_front(obj);
	else
	    obj.group->glist.push_back(obj);
	return false;
    } else {
	obj.flags = (obj.flags & ~DSP_Scheduled) | DSP_Ready;
	if (hipri)
	    rlist.push_front(obj);
	else
	    rlist.push_back(obj);
	if (!workers)
	    wake(1, false);
	return true;
    }
}

void DispatchObj::detach(void) { flags |= DSP_Detached; }

void DispatchObj::erase(void) {
    if (flags & (DSP_Active | DSP_ReadyAll | DSP_Scheduled | DSP_SelectAll)) {
	cancel();
	flags |= DSP_Freed;
    } else {
	delete this;
    }
}

void DispatchObj::terminate(void) {
    if (flags & DSP_Detached)
	erase();
    else
	cancel();
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

DispatchSocket::DispatchSocket(DispatchObj &parent, const Socket &s, ulong
    msec): DispatchTimer(parent, msec), Socket(s), mapped(false) {
    flags |= DSP_Socket;
}

void DispatchClientSocket::connect(const Sockaddr &sa, ulong msec, DispatchObjCB
    cb) {
    if (!cb)
	cb = connected;
    if (open(sa.family()) && blocking(false) && Socket::connect(sa))
	ready(cb, false, DispatchConnect);
    else if (!blocked())
	ready(cb, false, DispatchClose);
    else
	poll(cb, msec, DispatchConnect);
}

void DispatchClientSocket::connected() {
    msg = DispatchConnect;
    onConnect();
}

bool DispatchListenSocket::listen(const Sockaddr &sa, bool reuse, int queue,
    DispatchObjCB cb) {
    if (!cb)
	cb = connection;
    addr = sa;
    if (!Socket::listen(addr, reuse, queue))
	return false;
    blocking(false);
    CLOEXEC(fd());
    msleep(1);
    poll(cb, DSP_NEVER, DispatchAccept);
    return true;
}

DispatchListenSocket::DispatchListenSocket(Dispatcher &d, const Sockaddr &sa,
    int type, bool reuse, int queue, DispatchObjCB cb): DispatchSocket(d, type)
    {
    listen(sa, reuse, queue, cb);
}

void DispatchListenSocket::connection() {
    Socket s;
    bool b = accept(s);
 
    relisten();
    if (b) {
#ifdef __linux__
	s.blocking(false);
#endif
	s.movehigh();
	onAccept(s);
    }
}
