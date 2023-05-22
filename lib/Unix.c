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
#include <fcntl.h>
#include <time.h>
#include <sys/times.h>
#if defined(__linux__)
#include <linux/param.h>
#elif defined(__APPLE__)
#include <mach/task.h>
#include <mach/mach_init.h>
#include <mach/mach_time.h>
#include <sys/sysctl.h>
#include "Thread.h"

#ifdef APPLE_NO_CLOCK_GETTIME
int clock_gettime(int id, struct timespec *ts) {
    if (id == CLOCK_MONOTONIC) {
	uint64_t t = mach_absolute_time();
	static struct mach_timebase_info mti;

	if (!mti.denom)
	    mach_timebase_info(&mti);
	t = t * mti.numer / mti.denom;
	ts->tv_sec  = t / (1000 * 1000 * 1000);
	ts->tv_nsec = t % 1000;
	return 0;
    } else if (id == CLOCK_REALTIME) {
	struct timeval now;

	gettimeofday(&now, NULL);
	ts->tv_sec  = now.tv_sec;
	ts->tv_nsec = now.tv_usec * 1000;
	return 0;
    }
    return -1;
}
#endif
#endif

msec_t mticks(void) {
#ifdef CLOCK_MONOTONIC_COARSE
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC_COARSE, &ts);
    return (msec_t)ts.tv_sec * 1000 + (msec_t)(ts.tv_nsec + 500000) / 1000000;
#else
    return (msec_t)((uticks() + 500) / 1000);
#endif
}

usec_t __no_sanitize("thread") uticks(void) {
#if defined(__APPLE__)
    static volatile atomic_t lck;
    static struct mach_timebase_info mti;

    if (!mti.denom) {
        while (atomic_lck(lck))
	    THREAD_YIELD();
	if (!mti.denom) {
	    mach_timebase_info(&mti);
	    mti.denom *= 1000;
	}
	atomic_clr(lck);
    }
    return mach_absolute_time() * mti.numer / mti.denom;
#elif defined(CLOCK_MONOTONIC)
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (usec_t)ts.tv_sec * 1000000 + (usec_t)ts.tv_nsec / 1000;
#else
    usec_t diff, now, save;
    struct timeval tv;
    static volatile usec_t lastusec, lastutick;

    gettimeofday(&tv, NULL);
    now = (usec_t)tv.tv_sec * 1000000 + tv.tv_usec;
    diff = now - lastusec;
    save = lastutick;
    if (lastusec - now < 1000000) {
	return lastutick;
    } else if (diff > 1000000 && save == lastutick) {
	// check for system time change
	struct tms tbuf;
	ulong ticks = times(&tbuf);
	usec_t ticksdiff;
	static ulong lastticks, tps;

	if (!tps) {
	    tps = sysconf(_SC_CLK_TCK);
	    lastticks = ticks;
	}
	ticksdiff = ((usec_t)(ticks - lastticks) * (usec_t)1000000) / tps;
	if (now < lastusec || diff > ticksdiff + 1000)
	    diff = ticksdiff;
	lastticks = ticks;
    }
    if (save == lastutick) {
	lastutick += diff;
	lastusec = now;
    }
    return lastutick;
#endif
}

int lockfile(int fd, short type, short whence, ulong start, ulong len,
    short test) {
    struct flock fl;

    ZERO(fl);
    fl.l_type = type;
    fl.l_whence = whence;
    fl.l_start = (off_t)start;
    fl.l_len = (off_t)len;
    return fcntl(fd, test ? F_SETLK : F_SETLKW, &fl);
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
	    (ulong)tinfo.system_time.microseconds / 1000;;
	psbuf->utime = (ulong)tinfo.user_time.seconds * 1000 +
	    (ulong)tinfo.user_time.microseconds / 1000;;
    }
#elif defined(sun)
    // TODO incomplete
    char buf[PATH_MAX];
    struct stat sbuf;

    sprintf(buf, "/proc/%ld/as", (long)pid);
    if (stat(buf, &sbuf) == -1)
	return -1;
    psbuf->sz = sbuf.st_size / 1024;
#elif defined(__linux__)
    char buf[PATH_MAX + 128], fbuf[4096];
    FILE *f;

    sprintf(buf, "/proc/%ld/smaps", (long)pid);
    if ((f = fopen(buf, "r")) == NULL)
	return -1;
    setvbuf(f, fbuf, _IOFBF, sizeof (fbuf));
    while (fgets(buf, (int)sizeof (buf), f) != NULL) {
	char *end;
	ulong val;

	if (!strncmp(buf, "Pss:", (size_t)4)) {
	    val = strtoul(buf + 4, &end, 10);
	    if (!strncmp(end, " kB", (size_t)3))
		psbuf->pss += val;
	} else if (!strncmp(buf, "Rss:", (size_t)4)) {
	    val = strtoul(buf + 4, &end, 10);
	    if (!strncmp(end, " kB", (size_t)3))
		psbuf->rss += val;
	} else if (!strncmp(buf, "Size:", (size_t)5)) {
	    val = strtoul(buf + 5, &end, 10);
	    if (!strncmp(end, " kB", (size_t)3))
		psbuf->sz += val;
	}
    }
    fclose(f);
    sprintf(buf, "/proc/%ld/stat", (long)pid);
    if ((f = fopen(buf, "r")) == NULL)
	return -1;
    if (fgets(buf, (int)sizeof (buf), f) != NULL) {
	char c;
	long d;
	const char *p = strchr(buf, ')');
	ulong u;
	ulong stime, utime;

	sscanf(p + 2, "%c %ld %ld %ld %ld %ld %lu %lu %lu %lu %lu %lu %lu",
	    &c, &d, &d, &d, &d, &d, &u, &u, &u, &u, &u, &utime, &stime);
	psbuf->stime = stime / HZ * 1000 + (stime % HZ) * (1000L / HZ);
	psbuf->utime = utime / HZ * 1000 + (utime % HZ) * (1000L / HZ);
    }
    fclose(f);
#else
    (void)pid;
#endif
    return 0;
}
