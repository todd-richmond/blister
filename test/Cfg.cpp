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
#include "Config.h"

static bool is_true(tchar c) {
    return c == 't' || c == 'T' || c == '1' || c == 'y' || c == 'Y';
}

int tmain(int argc, const tchar * const argv[]) {
    const tchar *attr = nullptr, *file = T("-"), *prefix = nullptr, *section = nullptr,
	*val = nullptr;
    ConfigFile cfg;
    bool boolean = false, check = false, integer = false, nonewline = false,
	quiet = false, update = false;
    int i;

    for (i = 1; i < argc; i++) {
	if (tstreq(argv[i], T("-?")) || tstreq(argv[i], T("--help"))) {
	    break;
	} else if (tstreq(argv[i], T("-b")) ||
	    tstreq(argv[i], T("--boolean"))) {
	    boolean = true;
	} else if (tstreq(argv[i], T("-c")) ||
	    tstreq(argv[i], T("--check"))) {
	    check = true;
	} else if (tstreq(argv[i], T("-f")) ||
	    tstreq(argv[i], T("--file"))) {
	    if (i + 1 == argc)
		break;
	    file = argv[++i];
	} else if (tstreq(argv[i], T("-i")) ||
	    tstreq(argv[i], T("--integer"))) {
	    integer = true;
	} else if (tstreq(argv[i], T("-n")) ||
	    tstreq(argv[i], T("--nonewline"))) {
	    nonewline = true;
	} else if (tstreq(argv[i], T("-p")) ||
	    tstreq(argv[i], T("--prefix"))) {
	    if (i + 1 == argc || argv[i + 1][0] == '-')
		break;
	    prefix = argv[++i];
	} else if (tstreq(argv[i], T("-q")) ||
	    tstreq(argv[i], T("--quiet"))) {
	    quiet = true;
	} else if (tstreq(argv[i], T("-s")) ||
	    tstreq(argv[i], T("--section"))) {
	    if (i + 1 == argc || argv[i + 1][0] == '-')
		break;
	    section = argv[++i];
	} else if (tstreq(argv[i], T("-u")) ||
	    tstreq(argv[i], T("--update"))) {
	    update = true;
	} else if (argv[i][0] != '-' && !attr) {
	    attr = argv[i];
	    if (i + 1 != argc)
		val = argv[++i];
	} else {
	    break;
	}
    }
    if (i < argc || !attr) {
	tcerr << T("Usage: cfg [options] attribute [value]\n")
	    T("\t[-b|--boolean]\n")
	    T("\t[-c|--check]\n")
	    T("\t[-f|--file cfgfile]\n")
	    T("\t[-i|--integer]\n")
	    T("\t[-n|--nonewline]\n")
	    T("\t[-p|--prefix prefix]\n")
	    T("\t[-q|--quiet]\n")
	    T("\t[-s|--section section]\n")
	    T("\t[-u|--update]\n");
	return -1;
    }
    bool stdio = tstreq(file, T("-"));

    if (!(stdio ? cfg.read(tcin, prefix) : cfg.read(file, prefix))) {
	tcerr << T("unable to read ") << file << T(": ") << tstrerror(errno) <<
	    endl;
	return -1;
    }
    if (check) {
	return cfg.exists(attr, section) ? 0 : 1;
    } else if (boolean) {
	return cfg.get(attr, val && is_true(*val), section) ? 0 : 1;
    } else if (integer) {
	return cfg.get(attr, val ? atoi<int>(val) : 0, section);
    } else if (update) {
	if (val)
	    cfg.set(attr, val, section);
	else
	    cfg.erase(attr, section);
	if (!(stdio ? cfg.write(tcout) : cfg.write())) {
	    tcerr << T("unable to write ") << file << T(": ") <<
		tstrerror(errno) << endl;
	    return -1;
	}
	return 0;
    } else if (val || cfg.exists(attr, section)) {
	tcout << cfg.get(attr, val, section);
	if (!nonewline)
	    tcout << endl;
	return 0;
    } else {
	if (!quiet)
	    tcerr << attr << T(" not found") << endl;
	return -1;
    }
}
