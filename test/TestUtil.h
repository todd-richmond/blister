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

#ifndef TestUtil_h
#define TestUtil_h

#include <fcntl.h>
#include <signal.h>
#ifndef _WIN32
#include <sys/resource.h>
#endif
#include <sys/stat.h>

// file contents, or path itself when no such file exists
inline char *loaddata(const tchar *prog, const tchar *path, uint &sz) {
    char *buf;
    int fd;
    ssize_t len;
    struct stat sbuf;

    if ((fd = open(tchartoachar(path), O_CLOEXEC | O_RDONLY)) == -1) {
	if (access(tchartoachar(path), 0) == 0) {
	    tcerr << prog << T(": unable to open ") << path << endl;
	    return nullptr;
	}
	sz = (uint)(tstrlen(path) * sizeof (tchar));
	buf = new char[sz];
	memcpy(buf, path, sz);
	return buf;
    }
    if (fstat(fd, &sbuf) == -1) {
	close(fd);
	tcerr << prog << T(": unable to stat ") << path << endl;
	return nullptr;
    }
    buf = new char[(size_t)sbuf.st_size];
    len = read(fd, buf, (uint)sbuf.st_size);
    close(fd);
    if (len == -1) {
	delete [] buf;
	tcerr << prog << T(": unable to read ") << path << endl;
	return nullptr;
    }
    sz = (uint)len;
    return buf;
}

// raise the fd limit for many sockets; writes to closed peers return EPIPE
inline void setlimits(void) {
#ifndef _WIN32
    struct rlimit rl;
    struct sigaction sig {};

    if (!getrlimit(RLIMIT_NOFILE, &rl) && rl.rlim_cur != rl.rlim_max) {
	rl.rlim_cur = rl.rlim_max;
	setrlimit(RLIMIT_NOFILE, &rl);
    }
    sig.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig, nullptr);
#endif
}

#endif // TestUtil_h
