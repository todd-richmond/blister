/*
 * Copyright 2001-2019 Todd Richmond
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
#include "Timing.h"

static void timing(const tchar *key, usec_t usec) {
    dtiming.add(key, usec);
}

int tmain(int argc, const tchar * const argv[]) {
    bool byname = false;
    uint columns = Timing::TIMINGSLOTS - 2;
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
	    columns = (uint)ttoi(argv[++i]);
	} else if (!tstricmp(argv[i], T("-i")) || !tstricmp(argv[i],
	    T("--input"))) {
	    if (++i == argc)
		break;
	    if (tstrcmp(argv[i], T("-")) != 0) {
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
	    timing(argv[i], (usec_t)tstrtoul(argv[i + 1], NULL, 10) * mult);
	    i++;
	    out = true;
	} else {
	    break;
	}
    }
    if (i < argc) {
	tcerr << T("Usage: dtiming\n")
	    T("\t[-i|--input file]\n")
	    T("\t[-m|--msec]\n")
	    T("\t[-n|--sortbyname]\n")
	    T("\t[-s|--sec]\n")
	    T("\t[-u|--usec]\n")
	    T("\t<key[= ]duration>\\n*") << endl;
	    return 1;
    }
    if (!out) {
	while (getline(ifs.is_open() ? ifs : tcin, s)) {
	    if (!s.empty()) {
		const tchar *p = s.c_str(), *pp;
		tstring key;

		while (istspace(*p))
		    p++;
		pp = p;
		while (*pp != '=' && !istspace(*pp))
		    pp++;
		key.assign(p, (tstring::size_type)(pp - p));
		timing(key.c_str(), (usec_t)tstrtoul(pp, NULL, 10) * mult);
	    }
	}
    }
    tcout << dtiming.data(byname, columns);
    return 0;
}

