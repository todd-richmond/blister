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
