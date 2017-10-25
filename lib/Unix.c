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
#include <fcntl.h>
#include <time.h>
#include <sys/times.h>

#ifdef __APPLE__
#include <mach/mach_time.h>

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

usec_t microticks(void) {
#ifdef CLOCK_BOOTTIME
    struct timespec ts;

    clock_gettime(CLOCK_BOOTTIME, &ts);
    return (usec_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
#elif defined(__APPLE__)
    static struct mach_timebase_info mti;

    if (!mti.denom) {
	mach_timebase_info(&mti);
	mti.denom *= 1000;
    }
    return mach_absolute_time() * mti.numer / mti.denom;
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
	/* check for system time change */
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

msec_t milliticks(void) {
#ifdef CLOCK_BOOTTIME_COARSE
    struct timespec ts;

    clock_gettime(CLOCK_BOOTTIME_COARSE, &ts);
    return (msec_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
#else
    return (msec_t)(microticks() / 1000);
#endif
}

int lockfile(int fd, short type, short whence, ulong start, ulong len,
    short test) {
    struct flock fl;

    ZERO(fl);
    fl.l_type = type;
    fl.l_whence = whence;
    fl.l_start = start;
    fl.l_len = len;
    return fcntl(fd, test ? F_SETLK : F_SETLKW, &fl);
}
