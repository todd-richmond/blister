/*
 * Copyright 2001-2014 Todd Richmond
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

int tmain(int argc, tchar *argv[]) {
    const tchar *attr = NULL, *file = NULL, *prefix = NULL, *section = NULL;
    Config cfg;
    bool boolean = false, check = false, integer = false, nonewline = false;
    bool exists;
    int i;

    for (i = 1; i < argc; i++) {
	if (!tstrcmp(argv[i], T("-?")) || !tstrcmp(argv[i], T("--help"))) {
	    break;
	} else if (!tstrcmp(argv[i], T("-b")) ||
	    !tstrcmp(argv[i], T("--boolean"))) {
	    boolean = true;
	} else if (!tstrcmp(argv[i], T("-c")) ||
	    !tstrcmp(argv[i], T("--check"))) {
	    check = true;
	} else if (!tstrcmp(argv[i], T("-i")) ||
	    !tstrcmp(argv[i], T("--integer"))) {
	    integer = true;
	} else if (!tstrcmp(argv[i], T("-n")) ||
	    !tstrcmp(argv[i], T("--nonewline"))) {
	    nonewline = true;
	} else if (!tstrcmp(argv[i], T("-p")) ||
	    !tstrcmp(argv[i], T("--prefix"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    prefix = argv[i];
	} else if (!tstrcmp(argv[i], T("-s")) ||
	    !tstrcmp(argv[i], T("--section"))) {
	    if (i + 1 == argc || argv[++i][0] == '-')
		break;
	    section = argv[i];
	} else if (argv[i][0] != '-') {
	    attr = argv[i];
	    if (i + 1 != argc && argv[i + 1][0] != '-')
		file = argv[++i];
	} else {
	    break;
	}
    }
    if (i < argc || !attr) {
	tcerr << T("Usage: cfg\n")
	    T("\t[-b|--boolean]\n")
	    T("\t[-c|--check]\n")
	    T("\t[-i|--integer]\n")
	    T("\t[-n|--nonewline]\n")
	    T("\t[-p|--prefix prefix]\n")
	    T("\t[-s|--section section]\n")
	    T("\tattribute [file]\n") << endl;
	    return -1;
    }
    if (file) {
	if (!cfg.read(file, prefix)) {
	    tcerr << T("unable to read ") << file << endl;
	    return -1;
	}
    } else {
	cfg.read(tcin, prefix);
    }
    exists = cfg.exists(attr, section);
    if (check) {
	return exists ? 0 : 1;
    } else if (boolean) {
	return cfg.get(attr, false, section) ? 0 : 1;
    } else if (integer) {
	return cfg.get(attr, 0, section);
    } else if (exists) {
	tcout << cfg.get(attr, (tchar *)NULL, section);
	if (!nonewline)
	    tcout << endl;
	return 0;
    } else {
	tcerr << attr << T(" not found") << endl;
	return -1;
    }
}
