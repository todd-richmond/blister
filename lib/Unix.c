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
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <sys/times.h>
#if defined(__APPLE__)
#include <stdatomic.h>
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_port.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include "Thread.h"

static uint32_t ticks_denom_ms;
static uint32_t ticks_denom_us;
static uint32_t ticks_numer;

__attribute__((constructor)) static void ticks_init(void) {
    struct mach_timebase_info mti;

    mach_timebase_info(&mti);
    ticks_numer = mti.numer;
    ticks_denom_ms = mti.denom * 1000000U;
    ticks_denom_us = mti.denom * 1000U;
}
#endif

msec_t mticks(void) {
#ifdef __APPLE__
    return (msec_t)(mach_approximate_time() * ticks_numer / ticks_denom_ms);
#else
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (msec_t)ts.tv_sec * 1000 + (msec_t)ts.tv_nsec / 1000000;
#endif
}

usec_t uticks(void) {
#ifdef __APPLE__
    return (usec_t)(mach_absolute_time() * ticks_numer / ticks_denom_us);
#else
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (usec_t)ts.tv_sec * 1000000 + (usec_t)ts.tv_nsec / 1000;
#endif
}

int lockfile(int fd, short type, short whence, ulong start, ulong len,
    short test) {
    struct flock fl;
    int ret;


    ZERO(fl);
    fl.l_type = type;
    fl.l_whence = whence;
    fl.l_start = (off_t)start;
    fl.l_len = (off_t)len;
    do {
	ret = fcntl(fd, test ? F_SETLK : F_SETLKW, &fl);
    } while (ret == -1 && errno == EINTR && !test);
    return ret;
}

int pidstat(pid_t pid, struct pidstat *psbuf) {
    if (!pid)
	pid = getpid();
    memset(psbuf, 0, sizeof (*psbuf));
#if defined(__APPLE__)
    mach_msg_type_number_t msg_type = TASK_BASIC_INFO_COUNT;
    task_t task = MACH_PORT_NULL;
    struct task_basic_info tinfo;

    if (task_for_pid(current_task(), pid, &task) != KERN_SUCCESS)
	return -1;
    ZERO(tinfo);
    if (!task_info(task, TASK_BASIC_INFO, (task_info_t)&tinfo, &msg_type)) {
	psbuf->pss = psbuf->rss = tinfo.resident_size / 1024;
	psbuf->sz = tinfo.virtual_size / 1024;
	psbuf->stime = (ulong)tinfo.system_time.seconds * 1000 +
	    (ulong)tinfo.system_time.microseconds / 1000;
	psbuf->utime = (ulong)tinfo.user_time.seconds * 1000 +
	    (ulong)tinfo.user_time.microseconds / 1000;
    }
    mach_port_deallocate(mach_task_self(), task);
#elif defined(sun)
    // TODO incomplete
    char buf[PATH_MAX];
    struct stat sbuf;

    snprintf(buf, sizeof (buf), "/proc/%ld/as", (long)pid);
    if (stat(buf, &sbuf) == -1)
	return -1;
    psbuf->sz = sbuf.st_size / 1024;
#elif defined(__linux__)
    char buf[512];
    FILE *f;
    ulong pages, rpages;

    snprintf(buf, sizeof (buf), "/proc/%ld/statm", (long)pid);
    if ((f = fopen(buf, "r")) == NULL)
	return -1;
    if (fscanf(f, "%lu %lu", &pages, &rpages) == 2) {
	long pgkb = sysconf(_SC_PAGESIZE) / 1024;

	psbuf->sz = pages * (ulong)pgkb;
	psbuf->rss = rpages * (ulong)pgkb;
    }
    fclose(f);
    snprintf(buf, sizeof (buf), "/proc/%ld/smaps_rollup", (long)pid);
    if ((f = fopen(buf, "r")) != NULL) {
	while (fgets(buf, (int)sizeof (buf), f) != NULL) {
	    if (!strncmp(buf, "Pss:", (size_t)4)) {
		char *end;
		ulong val = strtoul(buf + 4, &end, 10);

		if (!strncmp(end, " kB", (size_t)3))
		    psbuf->pss = val;
		break;
	    }
	}
	fclose(f);
    }
    if (!psbuf->pss)
	psbuf->pss = psbuf->rss;
    snprintf(buf, sizeof (buf), "/proc/%ld/stat", (long)pid);
    if ((f = fopen(buf, "r")) == NULL)
	return -1;
    if (fgets(buf, (int)sizeof (buf), f) != NULL) {
	const char *p = strrchr(buf, ')');
	char c;
	long d;
	ulong u, stime, utime;

	if (p && sscanf(p + 2,
	    "%c %ld %ld %ld %ld %ld %lu %lu %lu %lu %lu %lu %lu", &c, &d, &d, &d,
	    &d, &d, &u, &u, &u, &u, &u, &utime, &stime) == 13) {
	    long hz = sysconf(_SC_CLK_TCK);

	    psbuf->stime = stime * 1000 / (ulong)hz;
	    psbuf->utime = utime * 1000 / (ulong)hz;
	}
    }
    fclose(f);
#else
    (void)pid;
#endif
    return 0;
}
