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

#include "stdapi.h"
#include <signal.h>
#include <time.h>
#include "Dispatch.h"

#ifdef _WIN32	// -V::1020
#define CLOEXEC(fd)
#else
#define CLOEXEC(fd) (void)fcntl((fd), F_SETFD, FD_CLOEXEC)
#endif
#define RETRY(call) while (UNLIKELY((int)(call) == -1) && interrupted(errno))

static constexpr uint MAX_WAIT_TIME = 1 * 60 * 1000;
static constexpr uint MAX_IDLE_TIMER = 10 * 1000;
static constexpr uint MIN_IDLE_TIMER = 1 * 1000;

static constexpr uint_fast32_t DSP_IO = DSP_Acceptable | DSP_Readable |
    DSP_Writeable | DSP_Closeable;
static constexpr uint_fast32_t DSP_ReadyAll = DSP_Ready | DSP_ReadyGroup;
static constexpr uint_fast32_t DSP_SelectAll = DSP_SelectAccept |
    DSP_SelectRead | DSP_SelectWrite | DSP_SelectClose;

#ifdef DSP_WIN32_ASYNC
#pragma comment(lib, "user32.lib")

static const tchar *DispatchClass = T("DSP_CLASS");
static uint Dispatcher::socketmsg;

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

#elif defined(BSD_BASE)

#define DSP_KQUEUE

#include <sys/event.h>
#include <sys/queue.h>
#ifndef NOTE_EOF
#define NOTE_EOF 0
#endif

typedef struct kevent event_t;

static constexpr uint MIN_EVENTS = 32;

#elif defined(__sun__)

#define DSP_DEVPOLL

#include <sys/devpoll.h>
#include <sys/queue.h>

typedef struct pollfd event_t;

#else

#define DSP_POLL

#endif

#if defined(DSP_DEVPOLL) || defined(DSP_EPOLL) || defined(DSP_KQUEUE)
static constexpr uint MAX_EVENTS = 128;
#endif

Dispatcher::Dispatcher(const Config &config): cfg(config),
    due(DispatchTimer::DSP_NEVER_DUE), maxthreads(0), running(0),
    shutdown(true), stacksz(0), workers(0),
#ifdef DSP_WIN32_ASYNC
    interval(DispatchTimer::DSP_NEVER), wnd(0)
#else
    evtfd(-1), wfd(-1), polling(false), rsock(SOCK_STREAM), wsock(SOCK_STREAM)
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

WARN_DISABLE(26430)
bool Dispatcher::exec() {
    while (rlist && !shutdown) {
	DispatchObj::Group *group;
	DispatchObj *obj = rlist.pop_front();

	if (UNLIKELY(!obj)) {
	    continue;
	} else if (UNLIKELY(obj->flags & DSP_Freed)) {
	    olock.unlock();
	    delete obj;
	    olock.lock();
	    continue;
	} else if (UNLIKELY((group = obj->group)->active)) {
	    obj->flags = (obj->flags & ~DSP_Ready) | DSP_ReadyGroup;
	    group->glist.push_back(*obj);
	    continue;
	}
	group->active = true;
	obj->flags = (obj->flags & ~DSP_Ready) | DSP_Active;
	++running;
	olock.unlock();
	obj->dcb(obj);
	--running;
	olock.lock();
	obj->flags &= ~DSP_Active;
	group->active = false;
	if (UNLIKELY(group->glist)) {
	    if (obj->flags & DSP_Ready) {
		obj->flags = (obj->flags & ~DSP_Ready) | DSP_ReadyGroup;
		group->glist.push_back(*obj);
	    }
	    obj = group->glist.pop_front();
	    obj->flags = (obj->flags & ~DSP_ReadyGroup) | DSP_Ready;
	    rlist.push_back(*obj);
	} else if (obj->flags & DSP_Ready) {
	    rlist.push_back(*obj);
	} else if (UNLIKELY(obj->flags & (DSP_Freed | DSP_Socket)) ==
	    DSP_Freed) {
	    olock.unlock();
	    delete obj;
	    olock.lock();
	}
    }
    return !shutdown;
}

int Dispatcher::run() {
    Lifo::Waiting waiting;

    priority(-1);
    olock.lock();
    while (exec()) {
	bool b = workers == lifo.size() + 1;

	olock.unlock();
	b = lifo.wait(waiting, b ? INFINITE : MAX_WAIT_TIME);
	olock.lock();
	if (!b)
	    break;
    }
    workers--;
    olock.unlock();
    return 0;
}

int Dispatcher::worker(void *param) {
    return (static_cast<Dispatcher *>(param))->run();
}

#ifdef DSP_WIN32_ASYNC

int Dispatcher::onStart() {
    MSG msg;

    if ((wnd = CreateWindow(DispatchClass, T("Dispatch Window"), 0, 0, 0,
	CW_USEDEFAULT, CW_USEDEFAULT, 0, 0, GetModuleHandle(NULL), 0)) == NULL) {
	shutdown = true;
	return -1;
    }
    due = DispatchTimer::DSP_NEVER_DUE;
    lifo.open();
    running = 0;
    shutdown = false;
    workers = 0;
    while (!shutdown) {
	GetMessage(&msg, wnd, 0, 0);
	if (shutdown)
	    break;
	if (msg.message == socketmsg) {
	    socketmap::const_iterator it;
	    uint evt = WSAGETSELECTEVENT(msg.lParam);

	    slock.lock();
	    if ((it = smap.find(msg.wParam)) != smap.end()) {
		DispatchSocket *ds = it->second;

		slock.unlock();
		olock.lock();
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
		    ready(*ds, ds->msg == DispatchAccept);
		} else {
		    if (evt & FD_READ)
			ds->flags |= DSP_Readable;
		    else if (evt & FD_ACCEPT)
			ds->flags |= DSP_Acceptable;
		    if (evt & (FD_CONNECT | FD_WRITE))
			ds->flags |= DSP_Writeable;
		    if (evt & FD_CLOSE)
			ds->flags |= DSP_Closeable;
		    olock.unlock();
		}
		tlock.lock();
		removeTimer(*ds);
		tlock.unlock();
	    } else {
		slock.unlock();
	    }
	} else if (msg.message == WM_TIMER) {
	    DispatchTimer *dt;
	    msec_t now;

	    now = mticks();
	    tlock.lock();
	    handleTimers(now);
	    dt = timers.peek();
	    if (dt == NULL && timers.half() < now + MIN_IDLE_TIMER) {
		timers.reorder(now + MAX_IDLE_TIMER);
		dt = timers.peek();
	    }
	    if (dt == NULL) {
		if (timers.empty()) {
		    due = DispatchTimer::DSP_NEVER_DUE;
		    interval = DispatchTimer::DSP_NEVER;
		    tlock.unlock();
		    KillTimer(wnd, DSP_TimerID);
		} else {
		    due = now + MAX_IDLE_TIMER;
		    interval = MAX_IDLE_TIMER;
		    tlock.unlock();
		    SetTimer(wnd, DSP_TimerID, interval, NULL);
		}
	    } else if (dt->due < now + interval || interval < MIN_IDLE_TIMER) {
		due = dt->due > now ? dt->due : now;
		interval = (ulong)(dt->due - now);
		tlock.unlock();
		SetTimer(wnd, DSP_TimerID, interval, NULL);
	    } else {
		due = now + interval;
		tlock.unlock();
	    }
	} else {
	    DefWindowProc(wnd, msg.message, msg.wParam, msg.lParam);
	    continue;
	}
	olock.lock();
	if (!maxthreads)
	    exec();
	olock.unlock();
    }
    KillTimer(wnd, DSP_TimerID);
    cleanup();
    DestroyWindow(wnd);
    wnd = 0;
    return 0;
}

#else

int Dispatcher::onStart() {
    msec_t now;
    SocketSet irset, iwset, orset, owset, oeset;
    socketmap::const_iterator sit;
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
    evtfd = kqueue();
    // ensure kqueue functions properly
    EV_SET(&evts[0], -1, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, NULL);
    if (kevent(evtfd, &evts[0], 1, &evts[0], 1, NULL) != 1 || evts[0].ident !=
	(uintptr_t)-1 || !(evts[0].flags & EV_ERROR)) {
	close(evtfd);
	evtfd = -1;
    } else {
	EV_SET(&evts[0], 1, EVFILT_USER, EV_ADD | EV_CLEAR, NOTE_TRIGGER, 0,
	    NULL);
	RETRY(kevent(evtfd, &evts[0], 1, NULL, 0, NULL));
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
	while (!asock.accept(rsock)) {
	    if (++u == 50) {
		CLOSE_EVTFD(evtfd);
		return -1;
	    }
	    msleep(100);
	}
	asock.close();
	rsock.blocking(false);
	rsock.cloexec();
	rset.set(rsock);
	wsock.blocking(false);
	wsock.cloexec();
#if defined(DSP_EPOLL) || defined(DSP_KQUEUE)
    }
#endif
    if (evtfd != -1) {			// cppcheck-suppress duplicateCondition
	CLOEXEC(evtfd);
#ifdef DSP_DEVPOLL
	evts[0].fd = rsock.fd();
	evts[0].events = POLLIN;

	RETRY(pwrite(evtfd, &evts[0], sizeof (evts[0]), 0));
#elif defined(DSP_EPOLL)
	wfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE);
	evts[0].events = EPOLLIN;
	RETRY(epoll_ctl(evtfd, EPOLL_CTL_ADD, wfd, evts));
#endif
    }
    lifo.open();
    running = 0;
    shutdown = false;
    workers = 0;
    now = mticks();
    due = DispatchTimer::DSP_NEVER_DUE;
    while (!shutdown) {
	DispatchTimer *dt;
	uint msec;

	tlock.lock();
	dt = timers.peek();
	if (dt == NULL && timers.half() < now + MIN_IDLE_TIMER) {
	    timers.reorder(now + MAX_IDLE_TIMER);
	    dt = timers.peek();
	}
	if (dt == NULL) {
	    if (timers.empty()) {
		msec = SOCK_INFINITE;
		due = DispatchTimer::DSP_NEVER_DUE;
	    } else {
		msec = MAX_IDLE_TIMER;
		due = now + MAX_IDLE_TIMER;
	    }
	} else {
	    msec = dt->due > now ? (uint)(dt->due - now) : 0;
	    due = now + msec;
	}
	tlock.unlock();
	if (evtfd == -1) {
	    slock.lock();
	    irset = rset;
	    iwset = wset;
	    slock.unlock();
	}
	polling = true;
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
	    if ((nevts = epoll_wait(evtfd, evts, MAX_EVENTS, (int)msec)) == -1)
		nevts = 0;
#elif defined(DSP_KQUEUE)
	    timespec ts = {
		(long)(msec / 1000), (long)((msec % 1000) * 1000000)
	    };

	    if ((nevts = kevent(evtfd, NULL, 0, evts, MAX_EVENTS, msec ==
		SOCK_INFINITE ? NULL : &ts)) == -1)
		nevts = 0;
#endif
	}
	if (shutdown)
	    break;
	polling = false;
	if (evtfd == -1) {
	    DispatchSocket *ds = NULL;
	    socket_t fd;

	    for (u = 0; u < orset.size(); u++) {
		fd = orset[u];
		slock.lock();
		if ((sit = smap.find(fd)) == smap.end()) {
		    slock.unlock();
		    if (fd == rsock)
			reset();
		    continue;
		}
		rset.unset(fd);
		ds = sit->second;
		slock.unlock();
		olock.lock();
		if (ds->flags & DSP_SelectWrite) {
		    olock.unlock();
		    slock.lock();
		    wset.unset(fd);
		    slock.unlock();
		    olock.lock();
		}
		ds->flags &= ~DSP_SelectAll;
		if (ds->flags & DSP_Scheduled) {
		    ds->msg = (ds->flags & DSP_SelectAccept) ? DispatchAccept :
			DispatchRead;
		    ready(*ds, ds->msg == DispatchAccept);
		} else {
		    ds->flags |= (ds->flags & DSP_SelectAccept) ?
			DSP_Acceptable : DSP_Readable;
		    olock.unlock();
		}
		tlock.lock();
		removeTimer(*ds);
		tlock.unlock();
	    }
	    for (u = 0; u < owset.size(); u++) {
		fd = owset[u];
		slock.lock();
		wset.unset(fd);
		if ((sit = smap.find(fd)) == smap.end()) {
		    slock.unlock();
		    continue;
		}
		ds = sit->second;
		slock.unlock();
		olock.lock();
		if (ds->flags & DSP_SelectRead) {
		    olock.unlock();
		    slock.lock();
		    rset.unset(fd);
		    slock.unlock();
		    olock.lock();
		}
		ds->flags &= ~DSP_SelectAll;
		if (ds->flags & DSP_Scheduled) {
		    ds->msg = DispatchWrite;
		    ready(*ds);
		} else {
		    ds->flags |= DSP_Writeable;
		    olock.unlock();
		}
		tlock.lock();
		removeTimer(*ds);
		tlock.unlock();
	    }
	    for (u = 0; u < oeset.size(); u++) {
		fd = oeset[u];
		slock.lock();
		if ((sit = smap.find(fd)) == smap.end()) {
		    slock.unlock();
		    continue;
		}
		ds = sit->second;
		slock.unlock();
		olock.lock();
		if (ds->flags & (DSP_SelectRead | DSP_SelectWrite)) {
		    bool r = ds->flags & DSP_SelectRead;
		    bool w = ds->flags & DSP_SelectWrite;

		    olock.unlock();
		    slock.lock();
		    if (r)
			rset.unset(fd);
		    if (w)
			wset.unset(fd);
		    slock.unlock();
		    olock.lock();
		}
		ds->flags &= ~DSP_SelectAll;
		if (ds->flags & DSP_Scheduled) {
		    ds->msg = DispatchClose;
		    ready(*ds);
		} else {
		    ds->flags |= DSP_Closeable;
		    olock.unlock();
		}
		tlock.lock();
		removeTimer(*ds);
		tlock.unlock();
	    }
#if defined(DSP_DEVPOLL) || defined(DSP_EPOLL) || defined(DSP_KQUEUE)
	} else {
	    olock.lock();
	    handleEvents(evts, (uint)nevts);
	    olock.unlock();
#endif
	}
	now = mticks();
	tlock.lock();
	handleTimers(now);
	tlock.unlock();
	olock.lock();
	rlist.push_front(flist);
	if (!maxthreads)
	    exec();
	olock.unlock();
    }
    cleanup();
    if (wfd != -1)
	close(wfd);
    if (evtfd != -1)
	close(evtfd);
    return 0;
}

#endif

void Dispatcher::cleanup(void) {
    DispatchTimer *dt;

    for (;;) {
	Thread *t;

	lifo.broadcast();
	if ((t = wait()) == NULL)
	    break;
	delete t;
    }
    lifo.close();
    while (rlist) {
	DispatchObj *obj = rlist.pop_front();

	if (!obj)
	    break;
	if (obj->group->glist)
	    rlist.push_front(obj->group->glist);
	if (obj->flags & DSP_ReadyGroup)
	    obj->flags = (obj->flags & ~DSP_ReadyGroup) | DSP_Ready;
	if (obj->flags & DSP_Freed)
	    delete obj;
	else
	    obj->terminate();
    }
    while (flist)
	delete flist.pop_front();
    while ((dt = timers.get()) != NULL)
	dt->terminate();
    while (flist)
	delete flist.pop_front();
}

#if defined(DSP_DEVPOLL) || defined(DSP_EPOLL) || defined(DSP_KQUEUE)
void Dispatcher::handleEvents(const void *evts, uint nevts) {
    for (uint u = 0; u < nevts; u++) {
	DispatchSocket *ds;
	const event_t *evt = (const event_t *)evts + u;

#ifdef DSP_DEVPOLL
#define DSP_EVENT_ERR(evt)	evt->revents & (POLLERR | POLLHUP)
#define DSP_EVENT_READ(evt)	evt->revents & POLLIN
#define DSP_EVENT_WRITE(evt)	evt->revents & POLLOUT
#define DSP_ONESHOT(ds, flag)	ds->flags &= ~(flag);

	if (UNLIKELY(evt->fd == rsock)) {
	    ds = NULL;
	} else {
	    socketmap::const_iterator sit;

	    olock.unlock();
	    slock.lock();
	    if (UNLIKELY((sit = smap.find(evt->fd)) == smap.end())) {
		slock.unlock();
		continue;
	    } else {
		ds = sit->second;
		slock.unlock();
	    }
	    olock.lock();
	}

#elif defined(DSP_EPOLL)
#define DSP_EVENT_ERR(evt)	evt->events & (EPOLLERR | EPOLLHUP)
#define DSP_EVENT_READ(evt)	evt->events & (EPOLLIN | EPOLLPRI | EPOLLRDHUP)
#define DSP_EVENT_WRITE(evt)	evt->events & EPOLLOUT
#define DSP_ONESHOT(ds, flag)	ds->flags &= ~(flag);

	ds = static_cast<DispatchSocket *>(evt->data.ptr);

#elif defined(DSP_KQUEUE)
#define DSP_EVENT_ERR(evt)	evt->flags & (EV_EOF | EV_ERROR)
#define DSP_EVENT_READ(evt)	evt->filter == EVFILT_READ && evt->data > 0
#define DSP_EVENT_WRITE(evt)	evt->filter == EVFILT_WRITE && evt->data > 0
#define DSP_ONESHOT(ds, flag)

	ds = static_cast<DispatchSocket *>(evt->udata);
#endif
	if (!ds) {
	    olock.unlock();
	    reset();
	    olock.lock();
	    continue;
	} else if (UNLIKELY(ds->flags & DSP_Freed)) {
	    continue;
	}
	if (DSP_EVENT_READ(evt)) {
	    if (ds->msg == DispatchNone && (ds->flags & DSP_Scheduled))
		ds->msg = (ds->flags & DSP_SelectAccept) ? DispatchAccept :
		    DispatchRead;
	    else
		ds->flags |= DSP_Readable;
	    DSP_ONESHOT(ds, DSP_SelectAccept | DSP_SelectRead);
	}
	if (DSP_EVENT_WRITE(evt)) {
	    if (ds->flags & DSP_Connecting)
		ds->msg = DispatchConnect;
	    else if (ds->msg == DispatchNone && (ds->flags & DSP_Scheduled))
		ds->msg = DispatchWrite;
	    else
		ds->flags |= DSP_Writeable;
	    DSP_ONESHOT(ds, DSP_SelectWrite);
	}
	if (DSP_EVENT_ERR(evt)) {
	    if (ds->msg == DispatchConnect || (ds->msg == DispatchNone &&
		ds->flags & DSP_Scheduled))
		ds->msg = DispatchClose;
	    else
		ds->flags |= DSP_Closeable;
	    DSP_ONESHOT(ds, DSP_SelectClose);
	}
	if (ds->flags & DSP_Scheduled)
	    ready(*ds, ds->msg == DispatchAccept);
	else
	    olock.unlock();
	tlock.lock();
	removeTimer(*ds);
	tlock.unlock();
	olock.lock();
    }
}
#endif

void Dispatcher::handleTimers(msec_t now) {
    DispatchTimer *dt;

    while ((dt = timers.get(now)) != NULL) {
	tlock.unlock();
	olock.lock();
	dt->msg = DispatchTimeout;
	ready(*dt, false);
	tlock.lock();
    }
}

#ifndef DSP_WIN32_ASYNC
void Dispatcher::reset(void) {
    if (evtfd == -1) {
	char buf[16];

	RETRY(rsock.read(buf, sizeof (buf)));
    }
#ifdef DSP_EPOLL
    else {
	eventfd_t buf;

	RETRY(eventfd_read(wfd, &buf));
    }
#endif
}
#endif

bool Dispatcher::start(uint mthreads, uint stack) {
    maxthreads = mthreads;
    stacksz = stack ? stack : 128 * 1024;
    if (ThreadGroup::start(mthreads ? 8 * 1024 : stacksz, false, false)) {
	olock.lock();
	while (shutdown && getMainThread().getState() == Running) {
	    olock.unlock();
	    msleep(20);
	    olock.lock();
	}
	olock.unlock();
    }
    return !shutdown;
}

void Dispatcher::onStop() {
    if (shutdown)
	return;
    shutdown = true;
    tlock.lock();
    wakeup(0);
    waitForMain();
}

// enter locked, leave unlocked
void Dispatcher::wakeup(ulong msec) {
#ifdef DSP_WIN32_ASYNC
    interval = msec;
    tlock.unlock();
    do {
	SetTimer(wnd, DSP_TimerID, msec, NULL);
    } while (interval > msec);
#else
    (void)msec;
    if (polling) {
	polling = false;
	tlock.unlock();
	if (wsock.open()) {
	    wsock.write("", 1);
	} else {
#ifdef DSP_EPOLL
	    RETRY(eventfd_write(wfd, 1));
#elif defined(DSP_KQUEUE)
	    event_t evt;
	    static timespec ts = { 0, 0 };

	    if (msec)
		EV_SET(&evt, 0, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0, msec,
		    NULL);
	    else
		EV_SET(&evt, 1, EVFILT_USER, EV_ENABLE | EV_ONESHOT,
		    NOTE_TRIGGER, 0, NULL);
	    RETRY(kevent(evtfd, &evt, 1, NULL, 0, &ts));
#endif
	}
    } else {
	tlock.unlock();
    }
#endif
}

void Dispatcher::cancelTimer(DispatchTimer &dt, bool del) {
    olock.lock();
    if (dt.flags & DSP_ReadyAll) {
	removeReady(dt);
	olock.unlock();
	return;
    }
    dt.flags &= ~DSP_Scheduled;
    olock.unlock();
    tlock.lock();
    if (del)
	timers.erase(dt);
    else
	removeTimer(dt);
    tlock.unlock();
}

void Dispatcher::setTimer(DispatchTimer &dt, ulong tm) {
    if (tm) {
	msec_t now = 0;
	msec_t tmt = tm == DispatchTimer::DSP_NEVER ?
	    DispatchTimer::DSP_NEVER_DUE : (now = mticks()) + tm;

	tlock.lock();
	timers.set(dt, tmt);
	if (tmt < due) {
	    due = tmt;
	    wakeup((ulong)(due - now));
	} else {
	    tlock.unlock();
	}
    } else {
	olock.lock();
	if (UNLIKELY(dt.flags & DSP_Scheduled)) {
	    olock.unlock();
	    tlock.lock();
	    removeTimer(dt);
	    tlock.unlock();
	    olock.lock();
	}
	ready(dt);
    }
}

void Dispatcher::cancelSocket(DispatchSocket &ds, bool close, bool del) {
    socket_t fd;

    olock.lock();
    if (ds.flags & DSP_Freed) {
	olock.unlock();
	return;
    }
    fd = ds.fd();
    if (ds.flags & DSP_ReadyAll) {
	removeReady(ds);
    } else {
	ds.flags &= ~DSP_Scheduled;
	olock.unlock();
	tlock.lock();
	removeTimer(ds);
	tlock.unlock();
	olock.lock();
    }
    if (del)
	ds.flags |= DSP_Freed;
    if (ds.mapped && fd != INVALID_SOCKET) {
	ds.mapped = false;
#ifdef DSP_WIN32_ASYNC
	olock.unlock();
	slock.lock();
	smap.erase(fd);
	slock.unlock();
	olock.lock();
	if (ds.flags & DSP_SelectAll) {
	    ds.flags &= ~DSP_SelectAll;
	    olock.unlock();
	    WSAAsyncSelect(fd, wnd, socketmsg, 0);
	    olock.lock();
	}
#else
	if (evtfd == -1) {
	    bool erase = true;

	    if (ds.flags & (DSP_SelectRead | DSP_SelectAccept)) {
		olock.unlock();
		slock.lock();
		smap.erase(fd);
		rset.unset(fd);
		slock.unlock();
		erase = false;
		olock.lock();
	    }
	    if (ds.flags & DSP_SelectWrite) {
		olock.unlock();
		slock.lock();
		if (erase) {
		    smap.erase(fd);
		    erase = false;
		}
		wset.unset(fd);
		slock.unlock();
		olock.lock();
	    }
	    if (erase) {
		olock.unlock();
		slock.lock();
		smap.erase(fd);
		slock.unlock();
		olock.lock();
	    }
	    ds.flags &= ~DSP_SelectAll;
	} else if (ds.flags & DSP_SelectAll && !close) {
#ifdef DSP_DEVPOLL
	    ds.flags &= ~DSP_SelectAll;
	    olock.unlock();

	    event_t evt = { fd, POLLREMOVE, 0 };

	    RETRY(pwrite(evtfd, &evt, sizeof (evt), 0));
	    olock.lock();
#elif defined(DSP_EPOLL)
	    ds.flags &= ~DSP_SelectAll;
	    olock.unlock();
	    RETRY(epoll_ctl(evtfd, EPOLL_CTL_DEL, fd, 0));
	    olock.lock();
#elif defined(DSP_KQUEUE)
	    event_t chgs[2], evts[MIN_EVENTS];
	    uint nevts = 0;
	    static timespec ts = { 0, 0 };

	    if (ds.flags & (DSP_SelectRead | DSP_SelectAccept))
		EV_SET(&chgs[nevts++], fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
	    if (ds.flags & DSP_SelectWrite)
		EV_SET(&chgs[nevts++], fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
	    ds.flags &= ~DSP_SelectAll;
	    olock.unlock();
	    RETRY(nevts = (uint)kevent(evtfd, chgs, (int)nevts, evts,
		MIN_EVENTS, &ts));
	    olock.lock();
	    handleEvents(evts, nevts);
#endif
	}
#endif
    }
    if (del) {
	flist.push_back(ds);
	olock.unlock();
    } else if (close) {
	olock.unlock();
	ds.Socket::close();
    } else {
	olock.unlock();
    }
}

void Dispatcher::pollSocket(DispatchSocket &ds, ulong timeout, DispatchMsg m) {
    uint_fast32_t flags;
    msec_t now = mticks();
    bool resched = false;
    msec_t tmt = timeout == DispatchTimer::DSP_NEVER ?
	DispatchTimer::DSP_NEVER_DUE : now + timeout;
    static const uint_fast32_t ioarray[] = {
	DSP_Readable | DSP_Closeable, DSP_Writeable | DSP_Closeable,
	DSP_Readable | DSP_Writeable | DSP_Closeable, DSP_Acceptable,
	DSP_Writeable | DSP_Closeable, DSP_Closeable, 0, 0
    };
    static const uint_fast32_t sarray[] = {
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
    static const uint sockevts[] = {
	EPOLLIN | EPOLLPRI | EPOLLRDHUP, EPOLLOUT,
	EPOLLIN | EPOLLPRI | EPOLLRDHUP | EPOLLOUT, EPOLLIN, EPOLLOUT, 0, 0, 0
    };
#endif
    olock.lock();
    flags = ds.flags & DSP_IO;
    if (flags & ioarray[m]) {
	if ((flags & DSP_Writeable) &&
	    (m == DispatchWrite || m == DispatchReadWrite || m ==
	    DispatchConnect)) {
	    ds.flags &= ~DSP_Writeable;
	    ds.msg = m == DispatchConnect ? DispatchConnect : DispatchWrite;
	} else if (LIKELY((flags & DSP_Readable) && (m == DispatchRead || m ==
	    DispatchReadWrite))) {
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
    ds.flags |= DSP_Scheduled;
    ds.msg = DispatchNone;
    if (UNLIKELY(tmt < due)) {
	msec_t prev = due;

	due = tmt;
	if (LIKELY(sarray[m] == (ds.flags & DSP_SelectAll))) {
	    olock.unlock();
	    tlock.lock();
	    timers.set(ds, tmt);
	    wakeup((ulong)(due - now));
	    return;
	}
	olock.unlock();
	resched = true;
    } else {
	bool ret = LIKELY(sarray[m] == (ds.flags & DSP_SelectAll));

	olock.unlock();
	tlock.lock();
	timers.set(ds, tmt);
	tlock.unlock();
	if (ret)
	    return;
    }
    if (UNLIKELY(!ds.mapped)) {
	slock.lock();
#ifdef DSP_EPOLL
	op = EPOLL_CTL_ADD;
#endif
#if defined(DSP_EPOLL) || defined(DSP_KQUEUE)
	if (evtfd == -1)
#endif
	    smap[ds.fd()] = &ds;
	ds.mapped = true;
	slock.unlock();
    }
    olock.lock();
#ifdef DSP_KQUEUE
    flags = ds.flags;
#endif
    ds.flags &= ~(DSP_SelectAll | DSP_IO);
    ds.flags |= sarray[m];
    olock.unlock();
#ifdef DSP_WIN32_ASYNC
    if (UNLIKELY(WSAAsyncSelect(ds.fd(), wnd, socketmsg, sockevts[(int)m]))) {
	olock.lock();
	ds.msg = DispatchClose;
	ready(ds);
	tlock.lock();
	removeTimer(*ds);
	if (resched)
	    wakeup((ulong)(due - now));
	else
	    tlock.unlock();
    } else if (UNLIKELY(resched)) {
	tlock.lock();
	wakeup((ulong)(due - now));
    }
#else
    if (UNLIKELY(resched)) {
	if (polling)
	    polling = false;
	else
	    resched = false;
    }
    if (UNLIKELY(evtfd == -1)) {
	slock.lock();
	if (m == DispatchRead || m == DispatchReadWrite || m ==
	    DispatchAccept || m == DispatchClose)
	    rset.set(ds.fd());
	if (m == DispatchWrite || m == DispatchReadWrite || m ==
	    DispatchConnect)
	    wset.set(ds.fd());
	slock.unlock();
	if (resched)
	    wsock.write("", 1);
    } else {
#ifdef DSP_DEVPOLL
	event_t evt = { ds.fd(), sockevts[m] | POLLERR | POLLHUP, 0 };

	RETRY(pwrite(evtfd, &evt, sizeof (evt), 0));
	if (UNLIKELY(resched))
	    wsock.write("", 1);
#elif defined(DSP_EPOLL)
	event_t evt;

	evt.data.ptr = &ds;
	// | (uint)EPOLLET requires caller to read to completion
	evt.events = sockevts[m] | EPOLLERR | EPOLLHUP | EPOLLONESHOT;
	RETRY(epoll_ctl(evtfd, op, ds.fd(), &evt));
	if (UNLIKELY(resched))
	    RETRY(eventfd_write(wfd, 1));
#elif defined(DSP_KQUEUE)
	event_t chgs[6], evts[MIN_EVENTS];
	uint nevts = 0;
	static timespec ts = { 0, 0 };

	if (LIKELY(m == DispatchRead || m == DispatchReadWrite || m ==
	    DispatchAccept || m == DispatchClose)) {
	    EV_SET(&chgs[nevts++], ds.fd(), EVFILT_READ, EV_ADD | EV_CLEAR,
		NOTE_EOF, 0, &ds);
	    if ((flags & DSP_SelectWrite) && m != DispatchReadWrite) {
		EV_SET(&chgs[nevts++], ds.fd(), EVFILT_WRITE, EV_DISABLE, 0, 0,
		    &ds);
	    }
	}
	if (UNLIKELY(m == DispatchWrite || m == DispatchReadWrite || m ==
	    DispatchConnect)) {
	    EV_SET(&chgs[nevts++], ds.fd(), EVFILT_WRITE, EV_ADD | EV_CLEAR,
		NOTE_EOF, 0, &ds);
	    if ((flags & DSP_SelectRead) && m != DispatchReadWrite) {
		EV_SET(&chgs[nevts++], ds.fd(), EVFILT_READ, EV_DISABLE, 0, 0,
		    &ds);
	    }
	}
	if (UNLIKELY(resched))
	    EV_SET(&chgs[nevts++], 0, EVFILT_TIMER, EV_ADD | EV_ONESHOT, 0,
		(ulong)(due - now), NULL);
	RETRY(nevts = (uint)kevent(evtfd, chgs, (int)nevts, evts, MIN_EVENTS,
	    &ts));
	if (LIKELY(nevts > 0)) {
	    olock.lock();
	    handleEvents(evts, nevts);
	    rlist.push_front(flist);
	    olock.unlock();
	}
#endif
    }
#endif
}

void Dispatcher::addReady(DispatchObj &obj, bool hipri, DispatchMsg reason) {
    olock.lock();
    obj.msg = reason;
    ready(obj, hipri);
}

void Dispatcher::cancelReady(DispatchObj &obj) {
    olock.lock();
    if (obj.flags & DSP_ReadyAll)
	removeReady(obj);
    olock.unlock();
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

// enter locked, leave unlocked
void Dispatcher::ready(DispatchObj &obj, bool hipri) {
    if (UNLIKELY(obj.group->active)) {
	obj.flags = (obj.flags & ~DSP_Scheduled) | DSP_ReadyGroup;
	if (UNLIKELY(hipri))
	    obj.group->glist.push_front(obj);
	else
	    obj.group->glist.push_back(obj);
	olock.unlock();
    } else {
	obj.flags = (obj.flags & ~DSP_Scheduled) | DSP_Ready;
	if (UNLIKELY(obj.flags & DSP_Active)) {
	    olock.unlock();
	    return;
	}
	if (UNLIKELY(hipri))
	    rlist.push_front(obj);
	else
	    rlist.push_back(obj);
	if (workers - running - lifo.size() >= rlist.size()) {
	    olock.unlock();
	    return;
	}
	olock.unlock();
	if (!shutdown && maxthreads && lifo.set() && workers < maxthreads) {
	    Thread *t;

	    workers++;
	    t = new Thread();
	    t->start(worker, this, stacksz, this);
	    while ((t = wait(0)) != NULL)
		delete t;
	}
    }
}

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
    onConnect();
}

bool DispatchListenSocket::listen(const Sockaddr &sa, bool reuse, int queue,
    DispatchObjCB cb, bool start) {
    if (!cb)
	cb = connection;
    addr = sa;
    if (!Socket::listen(addr, reuse, queue))
	return false;
    blocking(false);
    cloexec();
    if (start) {
	msleep(1);
	poll(cb, DispatchTimer::DSP_NEVER, DispatchAccept);
    } else {
	callback(cb);
    }
    return true;
}

DispatchListenSocket::DispatchListenSocket(Dispatcher &d, const Sockaddr &sa,
    int type, bool reuse, int queue, DispatchObjCB cb): DispatchSocket(d, type) {
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
