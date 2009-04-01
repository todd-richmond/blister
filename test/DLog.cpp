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
#include <signal.h>
#include "Config.h"
#include "Log.h"

static void signal_handler(int) {
    dlog.stop();
    exit(1);
}

static void log(Log::Level lvl, const tchar *str) {
    const tchar *p;

    if ((p = tstrchr(str, ' ')) != NULL || (p = tstrchr(str, '\t')) != NULL) {
	Log::Level l;
	tstring s;

	s.assign(str, 0, p - str);
	l = Log::str2enum(s.c_str());
	if (l != Log::None) {
	    lvl = l;
	    str += p - str + 1;
	}
    }
    dlog.log(lvl, str);
}

int main(int argc, tchar *argv[]) {
    int i;
    Log::Level lvl = Log::Info;
    ulong ka = 0;
    bool out = false;
    tstring s;

    signal(SIGINT, signal_handler);
    dlog.setmp(true);
    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-?")) || !tstricmp(argv[i], T("--help"))) {
	    break;
	} else if (!tstricmp(argv[i], T("-a")) || !tstricmp(argv[i],
	    T("--alert"))) {
	    ulong cnt = 3, sz = 10 * 1024 * 1024, tm = 0;
	    const tchar *file;
	    Log::Level lvl = Log::Err;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    file = strcmp(argv[i], T("-")) ? argv[i] : T("stderr");
	    if (i + 1 < argc && argv[i + 1][0] != '-') {
	    	if ((lvl = Log::str2enum(argv[++i])) == Log::None)
		    break;
	    }
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	cnt = atol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	sz = atol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	tm = atol(argv[++i]);
	    dlog.alert(lvl, file, cnt, sz, tm);
	} else if (!tstricmp(argv[i], T("-b")) || !tstricmp(argv[i],
	    T("--buffer"))) {
	    ulong sz = 32 * 1024, msec = 1000;

	    if (i + 1 < argc && argv[i + 1][0] != '-')
		sz = (ulong)atol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		msec = (ulong)atol(argv[++i]);
	    dlog.setmp(false);
	    dlog.buffer(sz, msec);
	} else if (!tstricmp(argv[i], T("-c")) || !tstricmp(argv[i],
	    T("--config"))) {
	    const tchar *file, *pre = NULL;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    file = argv[i];
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		pre = argv[++i];

	    Config cfg(file, pre);

	    dlog.set(cfg);
	} else if (!tstricmp(argv[i], T("-d")) || !tstricmp(argv[i],
	    T("--date"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    dlog.format(argv[i]);
	} else if (!tstricmp(argv[i], T("-f")) || !tstricmp(argv[i],
	    T("--file"))) {
	    ulong cnt = 3, sz = 10 * 1024 * 1024, tm = 0;
	    const tchar *file;
	    Log::Level lvl = Log::Info;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    file = strcmp(argv[i], T("-")) ? argv[i] : T("stdout");
	    if (i + 1 < argc && argv[i + 1][0] != '-') {
	    	if ((lvl = Log::str2enum(argv[++i])) == Log::None)
		    break;
	    }
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	cnt = atol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	sz = atol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	tm = atol(argv[++i]);
	    dlog.file(lvl, file, cnt, sz, tm);
	} else if (!tstricmp(argv[i], T("-k")) || !tstricmp(argv[i],
	    T("--keepalive"))) {
	    ka = 1000;
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		ka = (ulong)atol(argv[++i]);
	} else if (!tstricmp(argv[i], T("-l")) || !tstricmp(argv[i],
	    T("--level"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    if ((lvl = Log::str2enum(argv[i])) == Log::None)
		break;
	    dlog.level(lvl);
	} else if (!tstricmp(argv[i], T("-m")) || !tstricmp(argv[i],
	    T("--mail"))) {
	    const tchar *to;
	    const tchar *from = T("<>");
	    const tchar *host = T("localhost");
	    Log::Level lvl = Log::Err;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    to = argv[i];
	    if (i + 1 < argc && argv[i + 1][0] != '-') {
	    	if ((lvl = Log::str2enum(argv[++i])) == Log::None)
		    break;
	    }
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		from = argv[++i];
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		host = argv[++i];
	    dlog.mail(lvl, to, from, host);
	} else if (!tstricmp(argv[i], T("-n")) || !tstricmp(argv[i],
	    T("--name"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    dlog.source(argv[i]);
	} else if (!tstricmp(argv[i], T("-o")) || !tstricmp(argv[i],
	    T("--output"))) {
	    if (i + 1 == argc || argv[i + 1][0] == '-')
		break;
	} else if (!tstricmp(argv[i], T("-p")) || !tstricmp(argv[i],
	    T("--prefix"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    dlog.prefix(argv[i]);
	} else if (!tstricmp(argv[i], T("-s")) || !tstricmp(argv[i],
	    T("--syslog"))) {
	    uint fac = 1;
	    const tchar *host = T("localhost");
	    Log::Level lvl = Log::Err;

	    if (i + 1 < argc && argv[i + 1][0] != '-') {
	    	if ((lvl = Log::str2enum(argv[++i])) == Log::None)
		    break;
	    }
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		host = argv[++i];
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		fac = atoi(argv[++i]);
	    dlog.syslog(lvl, host, fac);
	} else if (!tstricmp(argv[i], T("-t")) || !tstricmp(argv[i],
	    T("--type"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    if (!tstricmp(argv[i], T("keyval")))
		dlog.type(Log::KeyVal);
	    else if (!tstricmp(argv[i], T("nolevel")))
		dlog.type(Log::NoLevel);
	    else if (!tstricmp(argv[i], T("syslog")))
		dlog.type(Log::Syslog);
	} else if (!tstricmp(argv[i], T("-u")) || !tstricmp(argv[i],
	    T("--unlocked"))) {
	    dlog.setmp(false);
	} else if (argv[i][0] != '-') {
	    log(lvl, argv[i]);
	    out = true;
	} else {
	    break;
	}
    }
    if (i < argc) {
	cerr << T("Usage: dlog\n"
	    "\t[-a|--alert file [level [count [size [time]]]]]\n"
	    "\t[-b|--buffer [msec [size]]]\n"
	    "\t[-c|--config cfgfile [prefix]]\n"
	    "\t[-d|--date strftime]\n"
	    "\t[-f|--file file [level [count [size [time]]]]]\n"
	    "\t[-k|--keepalive [polltime]]\n"
	    "\t[-l|--level emerg|alert|crit|err|warn|report|note|info|debug|trace]\n"
	    "\t[-m|--mail to [level [from [host]]]]\n"
	    "\t[-n|--name sourcename]\n"
	    "\t[-o|--output logstr ...]\n"
	    "\t[-p|--prefix logstr]\n"
	    "\t[-s|--syslog [level [host [facility]]]]\n"
	    "\t[-t|--type keyval|nolevel|simple|syslog]\n"
	    "\t[-u|--unlocked]\n"
	    "\t[logstr]*\n") << endl;
	    return 1;
    }
    while (!out) {
	while (getline(cin, s)) {
	    if (!s.empty())
		log(lvl, s.c_str());
	}
	if (ka) {
	    cin.clear();
	    msleep(ka);
	} else {
	    break;
	}
    }
    dlog.stop();
    return 0;
}
