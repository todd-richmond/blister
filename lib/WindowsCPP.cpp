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
#ifdef _WIN32

// hack to work around broken Microsoft libraries
#ifndef _DLL

#ifdef std
#undef std
#endif

extern "C" {
    fpos_t std::_Fpz = {0, 0};
}

#endif

const wstring _achartowstring(const char *s, size_t len) {
    wchar sbuf[512];
    int sz;

    if (len == 0)
	return L"";
    else if ((sz = MultiByteToWideChar(CP_UTF8, 0, s, (int)len, sbuf,
	sizeof (sbuf) / sizeof (wchar))) > 0)
	return sbuf;
    else if ((sz = MultiByteToWideChar(CP_UTF8, 0, s, (int)len, NULL, 0)) == 0)
	return L"";

    wchar *buf = new wchar[(uint)sz];
    wstring ret;

    MultiByteToWideChar(CP_UTF8, 0, s, (int)len, buf, sz);
    ret.assign(buf, sz - 1);
    delete [] buf;
    return ret;
}

const string _wchartoastring(const wchar *s, size_t len) {
    char sbuf[1024];
    int sz;

    if (len == 0)
	return "";
    else if ((sz = WideCharToMultiByte(CP_UTF8, 0, s, (int)len, sbuf,
	sizeof (sbuf), NULL, NULL)) > 0)
	return sbuf;
    else if ((sz = WideCharToMultiByte(CP_UTF8, 0, s, (int)len, NULL, 0, NULL,
	NULL)) == 0)
	return "";

    char *buf = new char[(uint)sz];
    string ret;

    WideCharToMultiByte(CP_UTF8, 0, s, (int)len, buf, (int)len, NULL, NULL);
    ret.assign(buf, sz - 1);
    delete [] buf;
    return ret;
}
#endif

