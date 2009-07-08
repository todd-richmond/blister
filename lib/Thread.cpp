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
#include <errno.h>
#include "Thread.h"

static const thread_t NOID = (thread_t)-1;

ulong ThreadGroup::nextId;
set<ThreadGroup *> ThreadGroup::groups;
Lock ThreadGroup::grouplck;
ThreadGroup ThreadGroup::MainThreadGroup(false);

Thread Thread::MainThread(THREAD_HDL(), &ThreadGroup::MainThreadGroup);

#ifdef _WIN32
ThreadLocalClass<Event> Condvar::tls;
Process Process::self(GetCurrentProcess());
#ifndef _WIN32_WCE
int Process::argc = __argc;
#ifdef _UNICODE
tchar **Process::argv = __wargv;
tchar **Process::envv = _wenviron;
#else
tchar **Process::argv = __argv;
tchar **Process::envv = _environ;
#endif

#else
#include <sys/times.h>
#endif

Mutex::Mutex(const tchar *name) {
    if (name) {
	tstring s(name);

	for (int i = 0; i < s.size(); i++) {
	    if (s[i] == '\\')
		s[i] = '_';
	}
	hdl = CreateMutex(NULL, 0, s.c_str());
    } else {
	hdl = CreateMutex(NULL, 0, NULL);
    }
}

void Condvar::set(uint count) {
    while (head && count--) {
	head->evt.set();
	head = head->next;
    }
    if (!head)
	tail = NULL;
}

bool Condvar::wait(ulong msec, bool hipri) {
    Event &event(*tls);
    waiting elem(*this, event, hipri);

    lock.unlock();
    bool ret = event.wait(msec);
    lock.lock();
    if (!ret) {
	if (head == &elem) {
	    head = head->next;
	    if (!head)
		tail = NULL;
	} else {
	    ret = true;
	    for (waiting *w = head; w && w->next; w = w->next) {
		if (w->next == &elem) {
		    w->next = elem.next;
		    if (tail == &elem)
			tail = w;
		    ret = false;
		    break;
		}
	    }
	}
    }
    return ret;
}
#endif

ThreadGroup::ThreadGroup(bool aterm): cv(lock), autoterm(aterm), state(Init) {
    grouplck.lock();
    id = (thread_t)((ulong)nextId++);
    groups.insert(this);
    grouplck.unlock();
}

ThreadGroup::~ThreadGroup() {
    if (autoterm)
	terminate();
    wait(INFINITE, true);
    grouplck.lock();
    groups.erase(this);
    grouplck.unlock();
}

int ThreadGroup::init(void *data) {
    return ((ThreadGroup *)data)->onStart();
}

// start a group's main thread
bool ThreadGroup::start(uint stacksz, bool aterm) {
    if (master.getState() != Init && master.getState() != Terminated)
	return false;
    autoterm = aterm;
    return master.start(init, this, stacksz, false, autoterm, this);
}

// control all threads in group
// TFR does not work yet if caller is in same group
void ThreadGroup::control(ThreadState ts, ThreadControlRoutine func) {
    set<Thread *>::iterator it;
    
    lock.lock();
    state = ts;
    for (it = threads.begin(); it != threads.end(); it++) {
	if (!THREAD_ISSELF((*it)->id))
	    ((*it)->*func)();
    }
    lock.unlock();
}

Thread *ThreadGroup::wait(ulong to, bool all, bool main) {
    msec_t start = milliticks();
    bool signaled = false;
    set<Thread *>::iterator it;

    lock.lock();
    do {
	// wait for one thread at a time to save having to deal with
	// threads restarting other threads
	bool found = false;

	for (it = threads.begin(); it != threads.end(); it++) {
	    Thread *p = *it;
	    ThreadState tstate = p->getState();
	    
	    if (main && p != &master) {
		continue;
	    } else if (tstate == Terminated) {
		if (!all) {
		    threads.erase(it);
		    lock.unlock();
		    return p;
		}
	    } else if (tstate != Terminated && p->id != NOID &&
		!THREAD_ISSELF(p->id)) {
		found = true;
	    }
	}
	if (signaled && main) {
	    cv.set();			// pass on to someone else
	    lock.unlock();
	    msleep(1);
	    lock.lock();
	    signaled = false;
	    continue;
	}
	if (!found || !to) {
	    lock.unlock();
	    return NULL;
	}
	// Check every 30 seconds in case we missed something
	if (!cv.wait(min(30000UL, to)) && to <= 30000) {
	    lock.unlock();
	    return NULL;
	}
	signaled = true;
	if (to != INFINITE)
	    to -= (ulong)(milliticks() - start);
    } while (true);
}

void ThreadGroup::priority(int pri) {
    set<Thread *>::iterator it;
    Locker lck(lock);

    for (it = threads.begin(); it != threads.end(); it++)
	(*it)->priority(pri);
}

void ThreadGroup::remove(Thread *thread) {
    Locker lck(lock);

    threads.erase(thread);
}

ThreadGroup *ThreadGroup::add(Thread *thread, ThreadGroup *tgroup) {
    ThreadGroup *p;
    
    if (tgroup) {
	p = tgroup;
	p->lock.lock();			// add to specified thread group
    } else {
	set<ThreadGroup *>::iterator i;
	set<Thread *>::iterator ii;
	
	grouplck.lock();
	p = NULL;
	for (i = groups.begin(); i != groups.end(); i++) {
	    p = *i;
	    p->lock.lock();
	    for (ii = p->threads.begin(); ii != p->threads.end(); ii++) {
		if (THREAD_ISSELF((*ii)->id))
		    break;
	    }
	    if (ii == p->threads.end()) {
		p->lock.unlock();
		p = NULL;
	    } else {
		break;
	    }
	}
	grouplck.unlock();
	if (p == NULL) {		    // add to main group
	    p = &MainThreadGroup;
	    p->lock.lock();
	}
    }
    p->threads.insert(thread);
    p->lock.unlock();
    return p;
}

Thread::Thread(thread_t handle, ThreadGroup *tgroup): cv(lck), autoterm(true),
    hdl(handle), id(NOID), group(tgroup), retval(0), state(Init) {
    if (hdl) {
	state = Running;
	group = ThreadGroup::add(this, tgroup);
    }
}

Thread::~Thread() {
    if (hdl && id != NOID) {
	if (autoterm)
	    terminate();
	else
	    wait();
    }
    if (group && state != Init)
	group->remove(this);
}

// set state and notify threadgroup
void Thread::clear(bool self) {
    lck.lock();
    if (id != NOID) {
#ifdef _WIN32
	CloseHandle(hdl);
	if (self)
	    delete Condvar::tls.get();
#else
	pthread_detach(hdl);
#endif
    }
    hdl = 0;
    state = Terminated;
    cv.set();
    lck.unlock();
    group->notify(this);
}

// setup thread and call it's main routine
THREAD_FUNC Thread::threadInit(void *arg) {
    Thread *thread = (Thread *)arg;
    ThreadState istate = thread->state;
    int status;
    
    thread->lck.lock();
    thread->id = THREAD_ID();
    srand((uint)(ulong)thread->id);
    thread->state = Running;
    thread->cv.set();
    thread->lck.unlock();
    if (istate == Suspended)
	thread->suspend();
    status = thread->retval = (thread->main)(thread->data);
    thread->clear();
#ifdef _WIN32
    return status;
#else
    return 0;
#endif
}

// call into ThreadMain with correct class scope
int Thread::init(void *args) {
    return ((Thread *)args)->onStart();
}

// create Thread and start it running in a derived class
bool Thread::start(ThreadRoutine func, void *arg, uint stacksz,
    bool bSuspend, bool aterm, ThreadGroup *tgroup) {
    Locker lkr(lck);

    if (state == Terminated) {
	state = Init;
	group->remove(this);
    } else if (state != Init) {
	return false;
    }
    autoterm = aterm;
    group = tgroup;
    main = func;
    data = arg;
    if (bSuspend)
	state = Suspended;
    else
	state = Running;
    group = ThreadGroup::add(this, group);
#ifdef _WIN32
    hdl = (HANDLE)_beginthreadex(NULL, stacksz, threadInit, this, 0,
    	(uint *)&id);
#else
    pthread_attr_t attr;

    pthread_attr_init(&attr);
    if (stacksz) {
	stacksz += 16 * 1024;
#ifdef __linux__
	stacksz += 100 * 1024;
#endif
	pthread_attr_setstacksize(&attr, stacksz);
    }
    pthread_attr_setscope(&attr, PTHREAD_SCOPE_SYSTEM);
    pthread_create(&hdl, &attr, threadInit, this);
    pthread_attr_destroy(&attr);
#endif
    if (hdl) {
	cv.wait();
	if (bSuspend)
	    msleep(500); // workaround for a race condition
	return true;
    } else {
	group->remove(this);
	state = Terminated;
	return false;
    }
}

// create Thread and have it call ThreadMain()
bool Thread::start(uint stacksz, bool suspend, bool term, ThreadGroup *tgroup) {
    return start(init, this, stacksz, suspend, term, tgroup);
}

bool Thread::stop(void) {
    Locker lkr(lck);

    if (state != Terminated) {
	onStop();
	if (state == Suspended)
	    resume();
    }
    return true;
}

bool Thread::suspend() {
    Locker lkr(lck);

    if (state == Suspended) {
	return true;
    } else if (state == Running) {
	state = Suspended;		    // allow self suspend
	lkr.unlock();
#ifdef _WIN32
	if (SuspendThread(hdl) != -1)
	    return true;
	lkr.lock();
#endif
	state = Running;
    }
    return false;
}

bool Thread::resume(void) {
    bool ret = false;
    Locker lkr(lck);

    if (state == Suspended) {
	state = Running;
#ifdef _WIN32
	ret = ResumeThread(hdl) != -1;
#else
	ret = true;
#endif
	if (!ret)
	    state = Suspended;
    }
    return ret;
}

// terminate thread ungracefully
bool Thread::terminate(void) {
    bool ret = false;
    Locker lkr(lck);

    if (state == Running || state == Suspended) {
#ifdef _WIN32
	ret = TerminateThread(hdl, 1) == 1;
#else
	ret = pthread_cancel(hdl) == 0;
#endif
	if (ret) {
	    retval = -2;
	    lkr.unlock();
	    clear(false);
	}
    } else if (state == Terminated) {
	ret = true;
    }
    return ret;
}

// exit thread cleanly - called by itself
void Thread::end(int status) {
    retval = status;
    clear();
#ifdef _WIN32
    _endthreadex(status);
#else
    pthread_exit(&status);
#endif
}

// wait for thread to exit
bool Thread::wait(ulong timeout) {
    bool ret = false;
    Locker lkr(lck);

    if (state == Init || state == Terminated) {
	ret = true;
    } else {
	if (id == NOID) {
	    lkr.unlock();
#ifdef _WIN32
	    ret = WaitForSingleObject(hdl, timeout) == WAIT_OBJECT_0;
#else
	    // pthreads does not support a timeout
	    if (timeout == INFINITE)
		ret = pthread_join(hdl, NULL) == 0;
#endif
	} else {
	    ret = cv.wait(timeout);
	}
    }
    if (ret && group) {
	group->remove(this);
	group = NULL;
    }
    return ret;
}

bool Thread::priority(thread_t hdl, int pri) {
#ifdef _WIN32
    if (pri < -5)
	return SetThreadPriority(hdl, THREAD_PRIORITY_IDLE) != 0;
    else if (pri < -1)
	return SetThreadPriority(hdl, THREAD_PRIORITY_LOWEST) != 0;
    else if (pri < 0)
	return SetThreadPriority(hdl, THREAD_PRIORITY_BELOW_NORMAL) != 0;
    else if (pri < 1)
	return SetThreadPriority(hdl, THREAD_PRIORITY_NORMAL) != 0;
    else if (pri < 2)
	return SetThreadPriority(hdl, THREAD_PRIORITY_ABOVE_NORMAL) != 0;
    else if (pri < 6)
	return SetThreadPriority(hdl, THREAD_PRIORITY_HIGHEST) != 0;
    else
	return SetThreadPriority(hdl, THREAD_PRIORITY_TIME_CRITICAL) != 0;
#else
    struct sched_param sched;
    int policy;
    int mn, mx;

    if (pthread_getschedparam(hdl, &policy, &sched))
    	return false;
    mn = sched_get_priority_min(policy);
    mx = sched_get_priority_max(policy);
    if (pri < -20)
    	pri = -20;
    else if (pri > 20)
    	pri = 20;
    sched.sched_priority = (int)(mn + (mx * 1.0 - mn) / 41 * (pri + 20));
    return pthread_setschedparam(hdl, policy, &sched) == 0;
#endif
}

uint Processor::count(void) {
    static int cpus;

    if (!cpus) {
	cpus = 1;
#ifdef _WIN32
	SYSTEM_INFO si;

	GetSystemInfo(&si);
	cpus = si.dwNumberOfProcessors;
#else
	cpus = (uint)sysconf(_SC_NPROCESSORS_ONLN);
#endif
    }
    return cpus;
}

void Processor::prefer(uint cpu) {
#if defined(_WIN32) && !defined(_WIN32_WCE)
    typedef DWORD (WINAPI *pSetThreadIdealProcessor)(HANDLE hdl, DWORD cpu);

    HANDLE hdl;
    static pSetThreadIdealProcessor func =
	(pSetThreadIdealProcessor)GetProcAddress(
	GetModuleHandle(T("KERNEL32.DLL")), "SetThreadIdealProcessor");

    if (func && DuplicateHandle(Process::self, Thread::MainThread,
	Process::self, &hdl, DUPLICATE_SAME_ACCESS, FALSE,
	DUPLICATE_SAME_ACCESS)) {
	func(hdl, cpu);
	CloseHandle(hdl);
    }
#endif
}

#ifdef _WIN32
Process::Process(const Process &proc) {
    if (!DuplicateHandle(GetCurrentProcess(), proc.hdl,
	GetCurrentProcess(), &hdl, 0L, TRUE, DUPLICATE_SAME_ACCESS)) {
	hdl = NULL;
    }
}

Process Process::start(tchar *const *args, const int *fds) {
    STARTUPINFO *st = NULL;
    PROCESS_INFORMATION proc;
    tstring cmd;

    ZERO(st);
    ZERO(proc);
#ifndef _WIN32_WCE
    STARTUPINFO sbuf;

    st = &sbuf;
    st->cb = sizeof (*st);
    if (fds) {				// only support 3 fds
	st->dwFlags = STARTF_USESTDHANDLES;
	st->hStdInput = (HANDLE)fds[0];
	if (fds[1] != -1) {
	    st->hStdOutput = (HANDLE)fds[1];
	    if (fds[2] != -1)
		st->hStdError = (HANDLE)fds[2];
	}
    }
#endif
    while (*args)
	cmd += *(args++) + ' ';
    if (!CreateProcess(NULL, (tchar *)cmd.c_str(), NULL, NULL, TRUE, 0, NULL, NULL,
	st, &proc)) {
	errno = EINVAL;
    }
    return Process(proc.hProcess);
}

#endif

