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
#include <fstream>
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

int tmain(int argc, tchar *argv[]) {
    int i;
    tifstream ifs;
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
	    Log::Level alvl = Log::Err;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    file = tstrcmp(argv[i], T("-")) ? argv[i] : T("stderr");
	    if (i + 1 < argc && argv[i + 1][0] != '-') {
	    	if ((alvl = Log::str2enum(argv[++i])) == Log::None)
		    break;
	    }
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	cnt = ttol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	sz = ttol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	tm = ttol(argv[++i]);
	    dlog.alert(alvl, file, cnt, sz, tm);
	} else if (!tstricmp(argv[i], T("-b")) || !tstricmp(argv[i],
	    T("--buffer"))) {
	    ulong sz = 32 * 1024, msec = 1000;

	    if (i + 1 < argc && argv[i + 1][0] != '-')
		sz = (ulong)ttol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		msec = (ulong)ttol(argv[++i]);
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
	    ulong cnt = 10, sz = 10 * 1024 * 1024, tm = 0;
	    const tchar *file;
	    Log::Level flvl = Log::Info;

	    if (++i == argc)
		break;
	    file = tstrcmp(argv[i], T("-")) ? argv[i] : T("stdout");
	    if (i + 1 < argc && argv[i + 1][0] != '-') {
	    	if ((flvl = Log::str2enum(argv[++i])) == Log::None)
		    break;
	    }
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	cnt = ttol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	sz = ttol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
	    	tm = ttol(argv[++i]);
	    dlog.file(flvl, file, cnt, sz, tm);
	} else if (!tstricmp(argv[i], T("-i")) || !tstricmp(argv[i],
	    T("--input"))) {
	    if (++i == argc)
		break;
	    if (tstrcmp(argv[i], T("-")) != 0) {
		ifs.open(tchartoachar(argv[i]));
		if (!ifs.good()) {
		    tcerr<< T("unable to open ") << argv[i] << endl;
		    return 1;
		}
	    }
	} else if (!tstricmp(argv[i], T("-k")) || !tstricmp(argv[i],
	    T("--keepalive"))) {
	    ka = 1000;
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		ka = (ulong)ttol(argv[++i]);
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
	    Log::Level mlvl = Log::Err;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    to = argv[i];
	    if (i + 1 < argc && argv[i + 1][0] != '-') {
	    	if ((mlvl = Log::str2enum(argv[++i])) == Log::None)
		    break;
	    }
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		from = argv[++i];
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		host = argv[++i];
	    dlog.mail(mlvl, to, from, host);
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
	} else if (!tstricmp(argv[i], T("-r")) || !tstricmp(argv[i],
	    T("--roll"))) {
	    dlog.roll();
	    return 0;
	} else if (!tstricmp(argv[i], T("-s")) || !tstricmp(argv[i],
	    T("--syslog"))) {
	    uint fac = 1;
	    const tchar *host = T("localhost");
	    Log::Level slvl = Log::Err;

	    if (i + 1 < argc && argv[i + 1][0] != '-') {
	    	if ((slvl = Log::str2enum(argv[++i])) == Log::None)
		    break;
	    }
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		host = argv[++i];
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		fac = ttoi(argv[++i]);
	    dlog.syslog(slvl, host, fac);
	} else if (!tstricmp(argv[i], T("-t")) || !tstricmp(argv[i],
	    T("--type"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    if (!tstricmp(argv[i], T("keyval")))
		dlog.type(Log::KeyVal);
	    else if (!tstricmp(argv[i], T("nolevel")))
		dlog.type(Log::NoLevel);
	    else if (!tstricmp(argv[i], T("notime")))
		dlog.type(Log::NoTime);
	    else if (!tstricmp(argv[i], T("syslog")))
		dlog.type(Log::Syslog);
	} else if (!tstricmp(argv[i], T("-u")) || !tstricmp(argv[i],
	    T("--unlocked"))) {
	    dlog.setmp(false);
	} else if (!tstricmp(argv[i], T("-w")) || !tstricmp(argv[i],
	    T("--write"))) {
	    log(lvl, argv[++i]);
	    out = true;
	} else if (argv[i][0] != '-') {
	    log(lvl, argv[i]);
	    out = true;
	} else {
	    break;
	}
    }
    if (i < argc) {
	tcerr << T("Usage: dlog\n")
	    T("\t[-a|--alert file [level [count [size [time]]]]]\n")
	    T("\t[-b|--buffer [msec [size]]]\n")
	    T("\t[-c|--config cfgfile [prefix]]\n")
	    T("\t[-d|--date strftime]\n")
	    T("\t[-f|--file file [level [count [size [time]]]]]\n")
	    T("\t[-i|--input file]\n")
	    T("\t[-k|--keepalive [polltime]]\n")
	    T("\t[-l|--level emerg|alert|crit|err|warn|note|info|debug|trace]\n")
	    T("\t[-m|--mail to [level [from [host]]]]\n")
	    T("\t[-n|--name sourcename]\n")
	    T("\t[-o|--output logstr ...]\n")
	    T("\t[-p|--prefix logstr]\n")
	    T("\t[-r|--roll]\n")
	    T("\t[-s|--syslog [level [host [facility]]]]\n")
	    T("\t[-t|--type keyval|nolevel|notime|simple|syslog]\n")
	    T("\t[-u|--unlocked]\n")
	    T("\t[[-w|--write] logstr]*\n") << endl;
	    return 1;
    }
    while (!out) {
	while (getline(ifs.is_open() ? ifs : tcin, s)) {
	    if (!s.empty())
		log(lvl, s.c_str());
	}
	if (ka) {
	    tcin.clear();
	    msleep(ka);
	} else {
	    break;
	}
    }
    dlog.stop();
    return 0;
}
