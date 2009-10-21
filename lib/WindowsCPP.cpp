/*
 * Copyright 2001-2010 Todd Richmond
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

// hack to work around broken Microsoft libraries
#if !defined(_DLL)

#ifdef std
#undef std
#endif

extern "C" {
    fpos_t std::_Fpz = {0, 0};
}

#endif

const wstring _achartowstring(const char *s, int len) {
    wchar sbuf[512];
    int sz;
    
    if (len == 0) {
	return L"";
    } else if ((sz = MultiByteToWideChar(CP_ACP, 0, s, len, sbuf,
	sizeof (sbuf) / sizeof (wchar))) > 0) {
	return sbuf;
    } else {
	sz = MultiByteToWideChar(CP_ACP, 0, s, len, NULL, 0);

	wchar *buf = new wchar[sz];
	wstring ret;
    	
	MultiByteToWideChar(CP_ACP, 0, s, len, buf, sz);
	ret.assign(buf, sz - 1);
	delete [] buf;
	return ret;
    }
}

const string _wchartoastring(const wchar *s, int len) {
    char sbuf[1024];
    int sz;

    if (len == 0) {
	return "";
    } else if ((sz = WideCharToMultiByte(CP_ACP, 0, s, len, sbuf, sizeof (sbuf),
	NULL, NULL)) > 0) {
	return sbuf;
    } else {
	sz = WideCharToMultiByte(CP_ACP, 0, s, len, NULL, 0, NULL, NULL);

	char *buf = new char[sz];
	string ret;

	WideCharToMultiByte(CP_ACP, 0, s, len, buf, len, NULL, NULL);
	ret.assign(buf, sz - 1);
	delete [] buf;
	return ret;
    }
}
