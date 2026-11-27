/*
 * Copyright 2001-2026 Todd Richmond
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
#include <fcntl.h>
#include <signal.h>
#ifndef _WIN32
#include <sys/mman.h>
#include <sys/shm.h>
#endif
#include <sys/stat.h>
#include "Log.h"
#include "MPHTTPServer.h"
#include "Timing.h"

#ifndef MAP_NORESERVE
#define MAP_NORESERVE	0
#endif
#ifndef MAP_POPULATE
#define MAP_POPULATE	0
#endif

static constexpr ulong AcceptDelay = 1000;	// ms before retrying a failed accept
static constexpr ulong ShmKeep = 128UL * 1024;	// larger segments detach

static tchar pidprefix[32];

void MPHTTPSocket::exec(void) {
    mpdspr().request();
    MPHTTPDispatcher::logprefix();
    HTTPTLSServer::exec();
}

void MPHTTPSocket::get(bool) {
    bool close = mpdspr().complete();

    if (!strcmp(path, "/check")) {
	status(200, "text/plain", 0, nullptr, close);
	*this << "OK";
    } else if (!strcmp(path, "/metrics")) {
	sendmetrics(close);
	return;
    } else if (!strcmp(path, "/timing")) {
	status(200, "text/plain", 0, nullptr, close);
	*this << tstringtoastring(dtiming.data());
    } else if (!strcmp(path, "/version")) {
	status(200, "text/plain", 0, nullptr, close);
	*this << tstringtoastring(dspr.config().get(T("version")));
    } else {
	error(404, close);
	return;
    }
    reply();
}

void ShMemHTTPSocket::cleanup(bool force) {
    if (filemem) {
#ifdef _WIN32
	UnmapViewOfFile(filemem);
#else
	munmap(filemem, filesz);
#endif
	filemem = nullptr;
    }
    if (shm && (force || (!shmout && shmsz > ShmKeep))) {
#ifdef _WIN32
	UnmapViewOfFile(shm);
	shmid.clear();
#else
	shmdt(shm);
	shmid = -1;
#endif
	shm = nullptr;
	shmout = false;
	shmsz = 0;
    }
}

void ShMemHTTPSocket::post(void) {
    const char *file = attr("X-File");
    ulong len;
    void *mem;
    const char *name = attr("X-Name");
    const char *op = path + 1;
    const char *val = attr("X-Shm-Id");

    if (!name)
	name = file ? file : "";
    if (file || val) {
	Sockaddr peer;

	// both map local resources into this process
	if (!dspr.config().get(T("post.local"), false, section()) ||
	    !peername(peer) || !peer.localhost()) {
	    error(403);
	    return;
	}
    }
    if (val) {
#ifdef _WIN32
	MEMORY_BASIC_INFORMATION mbi;

	if (shmid != val) {
	    cleanup(true);
	    shmid = val;
	}
	if (!shm) {
	    HANDLE hdl = OpenFileMappingA(FILE_MAP_READ | FILE_MAP_WRITE, FALSE,
		val);

	    if (!hdl || (shm = MapViewOfFile(hdl, FILE_MAP_READ |
		FILE_MAP_WRITE, 0, 0, 0)) == nullptr || !VirtualQuery(shm, &mbi,
		sizeof (mbi))) {
		dlog.note(Log::cmd(op), Log::kv(T("shm"), val),
		    Log::kv(T("err"), GetLastError()),
		    T("unable to map shm data"));
		if (shm)
		    UnmapViewOfFile(shm);
		if (hdl)
		    CloseHandle(hdl);
		shm = nullptr;
		shmid.clear();
		error(400);
		return;
	    }
	    CloseHandle(hdl);
	    shmsz = (ulong)mbi.RegionSize;
	}
#else
	struct shmid_ds ds;
	int id;

	if (from_chars(val, val + strlen(val), id).ec != errc()) {
	    error(400);
	    return;
	} else if (id != shmid) {
	    cleanup(true);
	    shmid = id;
	}
	if (!shm) {
	    if ((shm = shmat(shmid, nullptr, 0)) == (void *)-1 ||
		shmctl(shmid, IPC_STAT, &ds)) {
		dlog.note(Log::cmd(op), Log::kv(T("shmid"), shmid),
		    Log::error(tstrerror(errno)), T("unable to map shm data"));
		if (shm != (void *)-1)
		    shmdt(shm);
		shm = nullptr;
		shmid = -1;
		error(400);
		return;
	    }
	    shmsz = (ulong)ds.shm_segsz;
	}
#endif
	// client sizes must stay inside the segment
	if ((val = attr("X-Shm-Size")) == nullptr || from_chars(val, val +
	    strlen(val), len).ec != errc() || len > shmsz) {
	    error(400);
	    return;
	}
	mem = shm;
    } else if (file) {
#ifdef _WIN32
	HANDLE fh, mh = nullptr;
	LARGE_INTEGER fsz;

	if ((fh = CreateFileA(file, GENERIC_READ, FILE_SHARE_READ |
	    FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
	    FILE_FLAG_SEQUENTIAL_SCAN, nullptr)) == INVALID_HANDLE_VALUE) {
	    error(400);
	    return;
	}
	if (GetFileType(fh) != FILE_TYPE_DISK || !GetFileSizeEx(fh, &fsz) ||
	    fsz.QuadPart <= 0 || (ullong)fsz.QuadPart >= (ulong)-1) {
	    CloseHandle(fh);
	    error(400);
	    return;
	}
	if ((mh = CreateFileMappingA(fh, nullptr, PAGE_READONLY, 0, 0,
	    nullptr)) == nullptr || (mem = MapViewOfFile(mh, FILE_MAP_READ,
	    0, 0, 0)) == nullptr) {
	    dlog.note(Log::cmd(op), Log::kv(T("file"), file), Log::kv(T("err"),
		GetLastError()), T("unable to map file data"));
	    if (mh)
		CloseHandle(mh);
	    CloseHandle(fh);
	    error(400);
	    return;
	}
	CloseHandle(mh);
	CloseHandle(fh);
	filemem = mem;
	len = (ulong)fsz.QuadPart;
	if (len > ShmKeep) {
	    WIN32_MEMORY_RANGE_ENTRY r{mem, len};

	    (void)PrefetchVirtualMemory(GetCurrentProcess(), 1, &r, 0);
	}
#else
	int fd;
	struct stat st;

	// O_NONBLOCK: a FIFO must not block the open
	if ((fd = ::open(file, O_RDONLY | O_CLOEXEC | O_NONBLOCK)) == -1 ||
	    fstat(fd, &st) || (!S_ISREG(st.st_mode) && (errno = EINVAL)) ||
	    (mem = mmap(nullptr, (size_t)st.st_size, PROT_READ, MAP_NORESERVE |
	    MAP_POPULATE | MAP_PRIVATE, fd, 0)) == MAP_FAILED) {
	    dlog.note(Log::cmd(op), Log::kv(T("file"), file),
		Log::error(tstrerror(errno)), T("unable to map file data"));
	    if (fd != -1)
		::close(fd);
	    error(400);
	    return;
	}
	::close(fd);
	filemem = mem;
	filesz = (ulong)st.st_size;
	len = filesz;
	if (len > ShmKeep) {
	    (void)posix_madvise(mem, len, POSIX_MADV_SEQUENTIAL);
	    (void)posix_madvise(mem, len, POSIX_MADV_WILLNEED);
	}
#endif
    } else {
	mem = postdata;
	len = postsz;
    }
    if (!len)
	error(400);
    else if (!onPost(name, mem, len))
	error(404);
}

void ShMemHTTPSocket::replydone(DispatchObjCB cb) {
    cleanup();
    out.reset();
    MPHTTPSocket::replydone(cb);
}

void MPHTTPListenSocket::accepted(void) {
    auto &d = (MPHTTPDispatcher &)dspr;
    Socket s;

    if (UNLIKELY(reason() == DispatchClose)) {
	dloge(Log::mod(HTTPServerSocket::section()), Log::cmd(T("accept")),
	    Log::kv(T("addr"), addr.str()), T("listener poll failed"));
	cancel();
	d.retire();
	return;
    }
    while (!d.complete()) {
	if (UNLIKELY(!accept(s, true, true))) {
	    if (err() == WSAEWOULDBLOCK)
		break;
	    dlogw(Log::mod(HTTPServerSocket::section()), Log::cmd(T("accept")),
		Log::kv(T("addr"), addr.str()), Log::error(errstr()));
	    // the queue is not empty: polling again would fire at once
	    cancel();
	    timeout(accepted, AcceptDelay);
	    to = DSP_NEVER;		// relisten() reuses it as a poll timeout
	    return;
	}
#ifndef __linux__
	s.movehigh();			// some stdio implementations need low fds
#endif
	onAccept(s);
	// one connection at a time: closed() resumes accepting
	if (!d.acceptmany() && d.connections()) {
	    cancel();
	    return;
	}
	s = Socket();
    }
    if (d.complete())
	cancel();
    else
	relisten();
}

const Sockaddr *MPHTTPDispatcher::address(void) const {
    return lsock ? &lsock->address() : nullptr;
}

void MPHTTPDispatcher::closed(void) {
    if (--curcon == 0 && complete())
	quit();
    else if (!many && !complete() && !stopping)
	lsock->relisten();
}

// bound how long open connections may delay the exit
void MPHTTPDispatcher::drain(void) {
    if (!draining.exchange(true))
#ifdef _WIN32
	(void)CreateTimerQueueTimer(&timer, nullptr, drained, this,
	    cfg.get(T("watch.stop"), 60U) * 1000, 0, WT_EXECUTEONLYONCE);
#else
	alarm(cfg.get(T("watch.stop"), 60U));
#endif
}

#ifdef _WIN32
void __stdcall MPHTTPDispatcher::drained(void *d, BOOLEAN) {
    if (MPHTTPDaemon *dmn = ((MPHTTPDispatcher *)d)->daemon)
	dmn->onTimer(0);
}
#endif

bool MPHTTPDispatcher::listen(MPHTTPListenSocket *ls, const tchar *host) {
    const tchar *sect = HTTPServerSocket::section();
    tstring addr(cfg.get(T("host"), host, sect));

    ls->detach();
#ifdef _WIN32
    if (insock != SOCK_INVALID) {
	ls->Socket::operator =(insock);
	(void)ls->blocking(false);
	(void)ls->sockname(ls->addr);
	ls->callback(MPHTTPListenSocket::accepted);
	lsock = ls;
	return true;
    }
#endif
    if (!ls->DispatchListenSocket::listen(addr.c_str(), cfg.get(
	T("socket.reuse"), true, sect), cfg.get(T("socket.backlog"),
	SOCK_BACKLOG, sect), MPHTTPListenSocket::accepted, false)) {
	dloge(Log::mod(sect), Log::cmd(T("listen")), Log::kv(T("addr"), addr),
	    Log::error(ls->errstr()));
	return false;
    }
    dlogi(Log::mod(sect), Log::cmd(T("listen")), Log::kv(T("addr"), addr));
    lsock = ls;
    return true;
}

// workers share a log file: tag each thread's lines once
void MPHTTPDispatcher::logprefix(void) {
    if (pidprefix[0] && !dlog.prefix()[0])
	dlog.prefix(pidprefix);
}

// SIGTERM to self lets ctrl_handler stop the dispatcher off its own threads
void MPHTTPDispatcher::quit(void) {
    if (stopping || quitting.exchange(true))
	return;
#ifdef _WIN32
    // ctrl-C reaches only this worker's hidden console
    (void)GenerateConsoleCtrlEvent(CTRL_C_EVENT, 0);
#elif defined(__linux__) || defined(__FreeBSD__)
    sigval val{};

    // self-sent kill() signals are ignored as our own process group's
    (void)sigqueue(getpid(), SIGTERM, val);
#else
    (void)kill(getpid(), SIGTERM);
#endif
}

void MPHTTPDispatcher::onStop(void) {
    stopping = true;
    Dispatcher::onStop();
}

void MPHTTPDispatcher::refresh(bool recycle) {
    maxreq = recycle ? cfg.get(T("worker.maxrequests"), 10000U) : 0;
    if (complete())
	retire();
}

uint MPHTTPDispatcher::remaining(void) const {
    uint m = maxreq, t = totreq;

    return retired ? 0 : !m ? (uint)-1 : m > t ? m - t : 0;
}

void MPHTTPDispatcher::retire(void) {
    retired = true;
    drain();
    if (!curcon)
	quit();
}

bool MPHTTPDispatcher::start(void) {
    many = cfg.get(T("worker.acceptmany"), true);
    if (!Dispatcher::start(many ? cfg.get(T("worker.threads"), 64U) : 0,
	cfg.get(T("worker.stack"), 0U)))
	return false;
    if (lsock)
	lsock->relisten();
    return true;
}

// the watcher checks the shared socket so any worker may answer
bool MPHTTPDaemon::check(Status, tstring &err) {
    const Sockaddr *sa = dspr.address();

    return !sa || HTTPTLSServer::check(*sa, cfg.get(T("watch.checkwait"),
	60U) * 1000, err);
}

void MPHTTPDaemon::onPause(void) {
    MPHTTPDispatcher::logprefix();
    HTTPServerSocket::pause(true);
    Daemon::onPause();
}

bool MPHTTPDaemon::onRefresh(void) {
    MPHTTPDispatcher::logprefix();
    if (!Daemon::onRefresh())
	return false;
    dspr.refresh(worker());
    return true;
}

#ifdef _WIN32
void MPHTTPDaemon::onSpawn(vector<HANDLE> &handles) {
    if (worker()) {
	if (!handles.empty())
	    dspr.insock = (socket_t)handles[0];
    } else if (dspr.lsock) {
	handles.push_back((HANDLE)dspr.lsock->fd());
    }
}
#endif

void MPHTTPDaemon::onResume(void) {
    MPHTTPDispatcher::logprefix();
    HTTPServerSocket::pause(false);
    Daemon::onResume();
}

int MPHTTPDaemon::onStart(int argc, const tchar * const *argv) {
    int ret;

#ifdef _WIN32
    dspr.daemon = this;		// not in ctor: dspr may be an unbuilt member
#endif
    if ((ret = Daemon::onStart(argc, argv)) != 0)
	return ret;
    if (worker()) {
	*format_to_n(pidprefix, std::size(pidprefix) - 1, T("pid={}"),
	    getpid()).out = '\0';
	MPHTTPDispatcher::logprefix();
    }
    if (!setids())
	return 7;
    dspr.refresh(worker());
    onWorker();
    if (!dspr.start()) {
	dloge(Log::mod(name), Log::cmd(T("start")),
	    Log::error(T("dispatcher failed")));
	return 8;
    }
    running();
    dspr.waitForMain();
    return 0;
}

void MPHTTPDaemon::onStop(bool fast) {
    MPHTTPDispatcher::logprefix();
    dspr.stop();
    Daemon::onStop(fast);
}

// alarm() from drain() has no timer id
void MPHTTPDaemon::onTimer(ulong timer) {
    MPHTTPDispatcher::logprefix();
    dlog.warn(Log::mod(name), Log::cmd(T("timer")), Log::error(timer ?
	T("processing timeout") : T("drain timeout")));
    if (!worker()) {
	onStop(false);
	return;
    }
    update(Stopped);
    _exit(timer ? SIGALRM : 0);
}
