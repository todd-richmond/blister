#include "stdapi.h"
#include <signal.h>
#include "Config.h"
#include "Log.h"

static void signal_handler(int) {
    dlog.stop();
    exit(1);
}

static void log(Log::Level lvl, const char *str) {
    const char *p;

    if ((p = strchr(str, ' ')) != NULL || (p = strchr(str, '\t')) != NULL) {
	Log::Level l;
	string s;

	s.assign(str, 0, p - str);
	l = Log::str2enum(s.c_str());
	if (l != Log::None) {
	    lvl = l;
	    str += p - str + 1;
	}
    }
    dlog.log(lvl, str);
}

int main(int argc, char *argv[]) {
    int i;
    Log::Level lvl = Log::Info;
    ulong ka = 0;
    bool out = false;
    string s;

    signal(SIGINT, signal_handler);
    for (i = 1; i < argc; i++) {
	if (!stricmp(argv[i], "-?") || !stricmp(argv[i], "--help")) {
	    break;
	} else if (!stricmp(argv[i], "-a") || !stricmp(argv[i], "--alert")) {
	    ulong cnt = 3, sz = 10 * 1024 * 1024, tm = 0;
	    const char *file;
	    Log::Level lvl = Log::Err;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    file = strcmp(argv[i], "-") ? argv[i] : "stderr";
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
	} else if (!stricmp(argv[i], "-b") || !stricmp(argv[i], "--buffer")) {
	    ulong sz = 32 * 1024, msec = 1000;

	    if (i + 1 < argc && argv[i + 1][0] != '-')
		sz = (ulong)atol(argv[++i]);
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		msec = (ulong)atol(argv[++i]);
	    dlog.buffer(sz, msec);
	} else if (!stricmp(argv[i], "-c") || !stricmp(argv[i], "--config")) {
	    const char *file, *pre = NULL;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    file = argv[i];
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		pre = argv[++i];

	    Config cfg(file, pre);

	    dlog.set(cfg);
	} else if (!stricmp(argv[i], "-d") || !stricmp(argv[i], "--date")) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    dlog.format(argv[i]);
	} else if (!stricmp(argv[i], "-f") || !stricmp(argv[i], "--file")) {
	    ulong cnt = 3, sz = 10 * 1024 * 1024, tm = 0;
	    const char *file;
	    Log::Level lvl = Log::Info;

	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    file = strcmp(argv[i], "-") ? argv[i] : "stdout";
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
	} else if (!stricmp(argv[i], "-k") || !stricmp(argv[i], "--keepalive")) {
	    ka = 1000;
	    if (i + 1 < argc && argv[i + 1][0] != '-')
		ka = (ulong)atol(argv[++i]);
	} else if (!stricmp(argv[i], "-l") || !stricmp(argv[i], "--level")) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    if ((lvl = Log::str2enum(argv[i])) == Log::None)
		break;
	    dlog.level(lvl);
	} else if (!stricmp(argv[i], "-m") || !stricmp(argv[i], "--mail")) {
	    const char *to;
	    const char *from = "<>";
	    const char *host = "localhost";
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
	} else if (!stricmp(argv[i], "-n") || !stricmp(argv[i], "--name")) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    dlog.source(argv[i]);
	} else if (!stricmp(argv[i], "-o") || !stricmp(argv[i], "--output")) {
	    if (i + 1 == argc || argv[i + 1][0] == '-')
		break;
	} else if (!stricmp(argv[i], "-p") || !stricmp(argv[i], "--prefix")) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    dlog.prefix(argv[i]);
	} else if (!stricmp(argv[i], "-s") || !stricmp(argv[i], "--syslog")) {
	    uint fac = 1;
	    const char *host = "localhost";
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
	} else if (!stricmp(argv[i], "-t") || !stricmp(argv[i], "--type")) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    if (!stricmp(argv[i], "keyval"))
		dlog.type(Log::KeyVal);
	    else if (!stricmp(argv[i], "nolevel"))
		dlog.type(Log::NoLevel);
	    else if (!stricmp(argv[i], "syslog"))
		dlog.type(Log::Syslog);
	} else if (argv[i][0] != '-') {
	    log(lvl, argv[i]);
	    out = true;
	} else {
	    break;
	}
    }
    if (i < argc) {
	cerr << "Usage: dlog\n"
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
	    "\t[logstr]*\n" << endl;
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
