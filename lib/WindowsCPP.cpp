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
#ifdef _WIN32

// hack to work around broken Microsoft libraries
#ifndef _DLL

#ifdef std
#undef std
#endif

extern "C" {
    fpos_t std::_Fpz = { 0, 0 };
}

#endif

// UTF-16 never needs more code units than the UTF-8 input has bytes
wstring _achartowstring(string_view s) {
    wstring ret;

    ret.resize_and_overwrite(s.size(), [&](wchar *buf, size_t n) {
	return (size_t)MultiByteToWideChar(CP_UTF8, 0, s.data(),
	    (int)s.size(), buf, (int)n);
    });
    return ret;
}

// each UTF-16 code unit expands to at most 3 UTF-8 bytes
string _wchartoastring(wstring_view s) {
    string ret;

    ret.resize_and_overwrite(s.size() * 3, [&](char *buf, size_t n) {
	return (size_t)WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(),
	    buf, (int)n, NULL, NULL);
    });
    return ret;
}
#endif

