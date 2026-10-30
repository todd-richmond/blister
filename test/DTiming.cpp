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
#include "Timing.h"

// parse "key[= ]duration", skipping lines without a key
static bool add_line(const tchar *line, uint mult) {
    const tchar *p = line, *pp;

    while (istspace(*p))
	p++;
    pp = p;
    while (*pp && *pp != '=' && !istspace(*pp))
	pp++;
    if (pp == p)
	return false;

    uint klen = (uint)(pp - p);

    while (*pp == '=' || istspace(*pp))
	pp++;
    dtiming.add(p, klen, (usec_t)atoi<ulong>(pp) * mult);
    return true;
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
	if (tstrieq(argv[i], T("-?")) || tstrieq(argv[i], T("--help"))) {
	    break;
	} else if (tstrieq(argv[i], T("-c")) ||
	    tstrieq(argv[i], T("--columns"))) {
	    if (i + 1 == argc || argv[i + 1][0] == '-')
		break;
	    columns = atoi<uint>(argv[++i]);
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
	} else if (tstrieq(argv[i], T("-m")) ||
	    tstrieq(argv[i], T("--msec"))) {
	    mult = 1000;
	} else if (tstrieq(argv[i], T("-n")) ||
	    tstrieq(argv[i], T("--sortbyname"))) {
	    byname = true;
	} else if (tstrieq(argv[i], T("-s")) ||
	    tstrieq(argv[i], T("--sec"))) {
	    mult = 1000000;
	} else if (tstrieq(argv[i], T("-u")) ||
	    tstrieq(argv[i], T("--usec"))) {
	    mult = 1;
	} else if (argv[i][0] != '-') {
	    if (tstrpbrk(argv[i], T("= \t"))) {
		if (!add_line(argv[i], mult))
		    break;
	    } else if (i + 1 == argc || argv[i + 1][0] == '-') {
		break;
	    } else {
		dtiming.add(argv[i], (usec_t)atoi<ulong>(argv[i + 1]) * mult);
		i++;
	    }
	    out = true;
	} else {
	    break;
	}
    }
    if (i < argc) {
	tcerr << T("Usage: dtiming\n")
	    T("\t[-c|--columns #]\n")
	    T("\t[-i|--input file]\n")
	    T("\t[-m|--msec]\n")
	    T("\t[-n|--sortbyname]\n")
	    T("\t[-s|--sec]\n")
	    T("\t[-u|--usec]\n")
	    T("\t<key[= ]duration>\\n*") << endl;
	return 1;
    }
    if (!out) {
	tistream &is = ifs.is_open() ? ifs : tcin;

	while (getline(is, s))
	    add_line(s.c_str(), mult);
    }
    tcout << dtiming.data(byname, columns);
    return 0;
}

