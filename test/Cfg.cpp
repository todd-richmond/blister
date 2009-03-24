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
#include "Config.h"

int main(int argc, tchar *argv[]) {
    const tchar *attr = NULL, *file = NULL, *prefix = NULL, *section = NULL;
    Config cfg;
    bool boolean = false, check = false, integer = false;
    bool exists;
    int i;
    string s;

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
	tcerr << T("Usage: cfg\n"
	    "\t[-b|--boolean]\n"
	    "\t[-c|--check]\n"
	    "\t[-i|--integer]\n"
	    "\t[-p|--prefix prefix]\n"
	    "\t[-s|--section section]\n"
	    "\tattribute [file]\n") << endl;
	    return -1;
    }
    if (file) {
	if (!cfg.read(file)) {
	    tcerr << T("unable to read ") << file << endl;
	    return -1;
	}
    } else {
	cfg.read(cin);
    }
    exists = cfg.exists(attr, section);
    if (check) {
	return exists ? 0 : 1;
    } else if (boolean) {
	return cfg.get(attr, false, section) ? 0 : 1;
    } else if (integer) {
	return cfg.get(attr, 0, section);
    } else if (exists) {
	tcout << cfg.get(attr, NULL, section) << endl;
	return 0;
    } else {
	tcerr << attr << T(" not found") << endl;
	return -1;
    }
}
