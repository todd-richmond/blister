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
#include <fstream>
#include <signal.h>
#include "Config.h"
#include "Log.h"

[[noreturn]] static void signal_handler(int) {
    dlog.stop();
    exit(1);
}

static void log(Log::Level lvl, tstring &s) {
    const tchar *str = s.c_str();

    if (auto pos = s.find_first_of(T(" \t")); pos != s.npos) {
	tchar c = s[pos];

	s[pos] = '\0';
	if (Log::Level l = Log::str2enum(str); l != Log::None) {
	    lvl = l;
	    str += pos + 1;
	} else {
	    s[pos] = c;
	}
    }
    dlog.log(lvl, str);
}

int tmain(int argc, const tchar * const argv[]) {
    int i;
    tifstream ifs;
    Log::Level lvl = Log::Info;
    ulong ka = 0;
    bool out = false;
    tstring s;

    signal(SIGINT, signal_handler);
    dlog.setmp(true);
    for (i = 1; i < argc; i++) {
	if (tstrieq(argv[i], T("-?")) || tstrieq(argv[i], T("--help"))) {
	    break;
	} else if (tstrieq(argv[i], T("-a")) ||
	    tstrieq(argv[i], T("--alert"))) {
	    Log::Level alvl = Log::Err;
	    ulong cnt = 3, sz = 10UL * 1024 * 1024, tm = 0;
	    const tchar *file;

	    if (i + 1 == argc || (argv[++i][0] == '-' && argv[i][1]))
		break;
	    file = tstreq(argv[i], T("-")) ? T("stderr") : argv[i];
	    if (i + 1 < argc && argv[i + 1][0] != '-' &&
		(alvl = Log::str2enum(argv[++i])) == Log::None)
		break;
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		cnt = tstrtoul(argv[++i], nullptr, 10);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		sz = tstrtoul(argv[++i], nullptr, 10);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		tm = tstrtoul(argv[++i], nullptr, 10);
	    dlog.alertfile(alvl, file, (uint)cnt, sz, tm);
	} else if (tstrieq(argv[i], T("-b")) ||
	    tstrieq(argv[i], T("--buffer"))) {
	    ulong msec = 1000, sz = 32UL * 1024;

	    if (i + 1 < argc && argv[i + 1][0] != '-')
		sz = tstrtoul(argv[++i], nullptr, 10);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		msec = tstrtoul(argv[++i], nullptr, 10);
	    dlog.setmp(false);
	    dlog.buffer((uint)sz, msec);
	} else if (tstrieq(argv[i], T("-c")) ||
	    tstrieq(argv[i], T("--config"))) {
	    const tchar *file, *pre = nullptr;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    file = argv[i];
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		pre = argv[++i];

	    ConfigFile cfg(file, pre);

	    dlog.set(cfg);
	} else if (tstrieq(argv[i], T("-d")) ||
	    tstrieq(argv[i], T("--date"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    dlog.format(argv[i]);
	} else if (tstrieq(argv[i], T("-f")) ||
	    tstrieq(argv[i], T("--file"))) {
	    ulong cnt = 3, sz = 10UL * 1024 * 1024, tm = 0;
	    const tchar *file;
	    Log::Level flvl = Log::Info;

	    if (i + 1 == argc || (argv[++i][0] == '-' && argv[i][1]))
		break;
	    file = tstreq(argv[i], T("-")) ? T("stdout") : argv[i];
	    if (i + 1 < argc && argv[i + 1][0] != '-' && (flvl =
		Log::str2enum(argv[++i])) == Log::None)
		break;
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		cnt = tstrtoul(argv[++i], nullptr, 10);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		sz = tstrtoul(argv[++i], nullptr, 10);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		tm = tstrtoul(argv[++i], nullptr, 10);
	    dlog.file(flvl, file, (uint)cnt, sz, tm);
	} else if (tstrieq(argv[i], T("-i")) ||
	    tstrieq(argv[i], T("--input"))) {
	    if (++i == argc)
		break;
	    if (!tstreq(argv[i], T("-"))) {
		ifs.open(tchartoachar(argv[i]));
		if (!ifs.good()) {
		    tcerr << T("unable to open ") << argv[i] << endl;
		    return 1;
		}
	    }
	} else if (tstrieq(argv[i], T("-k")) ||
	    tstrieq(argv[i], T("--keepalive"))) {
	    ka = 1000;
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		ka = tstrtoul(argv[++i], nullptr, 10);
	} else if (tstrieq(argv[i], T("-l")) ||
	    tstrieq(argv[i], T("--level"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    if ((lvl = Log::str2enum(argv[i])) == Log::None)
		break;
	    dlog.level(lvl);
	} else if (tstrieq(argv[i], T("-m")) ||
	    tstrieq(argv[i], T("--mail"))) {
	    const tchar *to;
	    const tchar *from = T("<>");
	    const tchar *host = T("localhost");
	    Log::Level mlvl = Log::Err;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    to = argv[i];
	    if (i + 1 < argc && argv[i + 1][0] != '-' && (mlvl =
		Log::str2enum(argv[++i])) == Log::None)
		break;
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		from = argv[++i];
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		host = argv[++i];
	    dlog.mail(true);
	    dlog.mail(mlvl, to, from, host);
	} else if (tstrieq(argv[i], T("-n")) ||
	    tstrieq(argv[i], T("--name"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    dlog.source(argv[i]);
	} else if (tstrieq(argv[i], T("-o")) ||
	    tstrieq(argv[i], T("--output"))) {
	    if (i + 1 == argc || argv[i + 1][0] == '-')
		break;
	} else if (tstrieq(argv[i], T("-p")) ||
	    tstrieq(argv[i], T("--prefix"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    dlog.prefix(argv[i]);
	} else if (tstrieq(argv[i], T("-r")) ||
	    tstrieq(argv[i], T("--roll"))) {
	    dlog.roll();
	    return 0;
	} else if (tstrieq(argv[i], T("-s")) ||
	    tstrieq(argv[i], T("--syslog"))) {
	    uint fac = 1;
	    const tchar *host = T("localhost");
	    Log::Level slvl = Log::Err;

	    if (i + 1 < argc && argv[i + 1][0] != '-' && (slvl =
		Log::str2enum(argv[++i])) == Log::None)
		break;
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		host = argv[++i];
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		fac = (uint)tstrtoul(argv[++i], nullptr, 10);
	    dlog.syslog(true);
	    dlog.syslog(slvl, host, fac);
	} else if (tstrieq(argv[i], T("-t")) ||
	    tstrieq(argv[i], T("--type"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    if (tstrieq(argv[i], T("keyval")))
		dlog.type(Log::KeyVal);
	    else if (tstrieq(argv[i], T("nolevel")))
		dlog.type(Log::NoLevel);
	    else if (tstrieq(argv[i], T("notime")))
		dlog.type(Log::NoTime);
	    else if (tstrieq(argv[i], T("simple")))
		dlog.type(Log::Simple);
	    else if (tstrieq(argv[i], T("syslog")))
		dlog.type(Log::Syslog);
	    else
		break;
	} else if (tstrieq(argv[i], T("-u")) ||
	    tstrieq(argv[i], T("--unlocked"))) {
	    dlog.setmp(false);
	} else if (tstrieq(argv[i], T("-w")) ||
	    tstrieq(argv[i], T("--write"))) {
	    if (++i < argc) {
		dlog.log(lvl, argv[i]);
		out = true;
	    }
	} else if (argv[i][0] != '-') {
	    dlog.log(lvl, argv[i]);
	    out = true;
	} else {
	    break;
	}
    }
    if (i < argc) {
	tcerr << T("Usage: dlog\n")
	    T("\t[-a|--alert file [level [count [size [time]]]]]\n")
	    T("\t[-b|--buffer [size [msec]]]\n")
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
    if (!out) {
	tistream &is = ifs.is_open() ? ifs : tcin;

	for (;;) {
	    while (getline(is, s)) {
		if (!s.empty())
		    log(lvl, s);
	    }
	    if (!ka)
		break;
	    is.clear();
	    msleep(ka);
	}
    }
    dlog.stop();
    return 0;
}
