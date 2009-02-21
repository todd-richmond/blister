#include "stdapi.h"
#include <fcntl.h>
#include <sys/times.h>

msec_t mticks(void) { return (msec_t)((uticks() + 500) / 1000); }

usec_t uticks(void) {
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
}

int lockfile(int fd, short type, short whence, ulong start, ulong len,
    short test) {
    struct flock fl;

    fl.l_type = type;
    fl.l_whence = whence;
    fl.l_start = start;
    fl.l_len = len;
    return fcntl(fd, test ? F_SETLK : F_SETLKW, &fl);
}
