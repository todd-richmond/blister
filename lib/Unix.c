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
#ifdef sun
#include <procfs.h>
#elif defined(__APPLE__)
#include <libproc.h>
#include <mach/mach_time.h>
#endif

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

static int procstats(pid_t pid, struct pidstat *psbuf, int full) {
    (void)full;
    if (!pid)
	pid = getpid();
    memset(psbuf, 0, sizeof (*psbuf));
#if defined(__APPLE__)
    mach_timebase_info_data_t tb;
    struct proc_taskinfo ti;

    // same-user access: task_for_pid() needs root or an entitlement
    if (proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &ti, (int)sizeof (ti)) !=
	(int)sizeof (ti) || mach_timebase_info(&tb) != KERN_SUCCESS ||
	!tb.denom)
	return -1;
    psbuf->pss = psbuf->rss = ti.pti_resident_size / 1024;
    psbuf->sz = ti.pti_virtual_size / 1024;
    // CPU times are in mach absolute time units
    psbuf->stime = ti.pti_total_system * tb.numer / tb.denom / 1000000;
    psbuf->utime = ti.pti_total_user * tb.numer / tb.denom / 1000000;
#elif defined(sun)
    char buf[PATH_MAX];
    FILE *f;
    psinfo_t psinfo;
    prusage_t usage;

    snprintf(buf, sizeof (buf), "/proc/%ld/psinfo", (long)pid);
    if ((f = fopen(buf, "r")) == NULL)
	return -1;
    if (fread(&psinfo, sizeof (psinfo), 1, f) == 1) {
	psbuf->sz = psinfo.pr_size;
	psbuf->pss = psbuf->rss = psinfo.pr_rssize;
    }
    fclose(f);
    snprintf(buf, sizeof (buf), "/proc/%ld/usage", (long)pid);
    if ((f = fopen(buf, "r")) != NULL) {
	if (fread(&usage, sizeof (usage), 1, f) == 1) {
	    psbuf->stime = (uint64_t)usage.pr_stime.tv_sec * 1000 +
		(uint64_t)usage.pr_stime.tv_nsec / 1000000;
	    psbuf->utime = (uint64_t)usage.pr_utime.tv_sec * 1000 +
		(uint64_t)usage.pr_utime.tv_nsec / 1000000;
	}
	fclose(f);
    }
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
    if (!full)
	return 0;
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

int pidstat(pid_t pid, struct pidstat *psbuf) {
    return procstats(pid, psbuf, 1);
}

#ifdef __linux__
DLL_LOCAL int pidmem(pid_t pid, struct pidstat *psbuf) {
    return procstats(pid, psbuf, 0);
}
#endif
