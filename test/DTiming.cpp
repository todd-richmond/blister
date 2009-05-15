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
#include <fstream>
#include "Timing.h"

static void timing(const tchar *key, usec_t usec) {
    dtiming.add(key, usec);
}

int tmain(int argc, tchar *argv[]) {
    bool byname = false;
    uint columns = TIMINGCOLUMNS;
    int i;
    uint mult = 1;
    bool out = false;
    tifstream ifs;
    tstring s;

    for (i = 1; i < argc; i++) {
	if (!tstricmp(argv[i], T("-?")) || !tstricmp(argv[i], T("--help"))) {
	    break;
	} else if (!tstricmp(argv[i], T("-c")) || !tstricmp(argv[i],
	    T("--columns"))) {
	    if (i + 1 == argc || argv[i + 1][0] == '-')
		break;
	    columns = ttoi(argv[++i]);
	} else if (!tstricmp(argv[i], T("-i")) || !tstricmp(argv[i],
	    T("--input"))) {
	    if (++i == argc)
		break;
	    if (tstrcmp(argv[i], T("-"))) {
		ifs.open(tchartoachar(argv[i]));
		if (!ifs.good()) {
		    tcerr<< T("unable to open ") << argv[i] << endl;
		    break;
		}
	    }
	} else if (!tstricmp(argv[i], T("-m")) || !tstricmp(argv[i],
	    T("--msec"))) {
	    mult = 1000;
	} else if (!tstricmp(argv[i], T("-n")) || !tstricmp(argv[i],
	    T("--sortbyname"))) {
	    byname = true;
	} else if (!tstricmp(argv[i], T("-s")) || !tstricmp(argv[i],
	    T("--sec"))) {
	    mult = 1000000;
	} else if (!tstricmp(argv[i], T("-u")) || !tstricmp(argv[i],
	    T("--usec"))) {
	    mult = 1;
	} else if (argv[i][0] != '-') {
	    if (i + 1 == argc || argv[i + 1][0] == '-')
		break;
	    timing(argv[i], tstrtoul(argv[i + 1], NULL, 10) * mult);
	    i++;
	    out = true;
	} else {
	    break;
	}
    }
    if (i < argc) {
	tcerr << T("Usage: dlog\n")
	    T("\t[-i|--input file]\n")
	    T("\t[-m|--msec]\n")
	    T("\t[-n|--sortbyname]\n")
	    T("\t[-s|--sec]\n")
	    T("\t[-u|--usec]\n")
	    T("\t[key duration]*\n") << endl;
	    return 1;
    }
    while (!out) {
	while (getline(ifs.is_open() ? ifs : tcin, s)) {
	    if (!s.empty()) {
		const tchar *p = s.c_str(), *pp;
		tstring key;

		while (istspace(*p))
		    p++;
		pp = p;
		while (!istspace(*pp))
		    pp++;
		key.assign(p, pp - p);
		timing(key.c_str(), tstrtoul(pp, NULL, 10) * mult);
	    }
	}
	break;
    }
    tcout << dtiming.data(byname, columns);
    return 0;
}

