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
#include <stdarg.h>
#include <algorithm>
#include <fstream>
#include "Config.h"

Config::Value::Value(const tchar *val, size_t len): expand(false), quote(0) {
    if (len > 1 && (val[0] == '"' || val[0] == '\'') && val[len - 1] == val[0]) {
	quote = val[0];
	value.assign(val, 1, len - 2);
    } else {
	const tchar *p = val;

	value.assign(val, 0, len);
	while ((p = tstrchr(p, '$')) != NULL && *++p) {
	    if ((*p == '{' || *p == '(') && tstrchr(p, *p == '(' ? ')' : '}') !=
		NULL) {
		expand = true;
		return;
	    }
	}
    }
}

Config::Config(const tchar *file, const tchar *str): ini(false), locker(0) {
    if (file)
	read(file, str);
}

const tstring &Config::expand(const Value *value) const {
    tstring::size_type epos, spos;

    if (!value->expand)
	return value->value;
    _buf = value->value;
    while ((spos = _buf.rfind(T("$("))) != _buf.npos ||
	(spos = _buf.rfind(T("${"))) != _buf.npos) {
	if ((epos = _buf.find(_buf[spos + 1] == '(' ? ')' : '}', spos + 2)) ==
	    _buf.npos)
	    break;

	attrmap::const_iterator it;
	tstring s(_buf, spos + 2, epos - spos - 2);

	if (!pre.empty() && s.compare(0, pre.size(), pre) == 0 &&
	    s.size() > pre.size() + 1 && s[pre.size()] == '.')
	    s.erase(0, pre.size() + 1);
	it = amap.find(s.c_str());
	if (it == amap.end())
	    break;
	_buf.replace(spos, epos - spos + 1, it->second->value);
    }
    return _buf;
}

void Config::clear(void) {
    attrmap::iterator it;
    Locker lkr(lck, !THREAD_ISSELF(locker));

    while ((it = amap.begin()) != amap.end()) {
	const tchar *p = it->first;

	delete it->second;
	amap.erase(it);
	free((tchar *)p);
    }
}

void Config::erase(const tchar *attr, const tchar *sect) {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    attrmap::iterator it = amap.find(keystr(attr, sect));

    if (it != amap.end()) {
	const tchar *p = it->first;

	delete it->second;
	amap.erase(it);
	free((tchar *)p);
    }
}

const tstring Config::get(const tchar *attr, const tchar *def,
    const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const Value *val = lookup(attr, sect);
    static tstring empty;

    return val ? expand(val) : def ? def : empty;
}

bool Config::get(const tchar *attr, bool def, const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const Value *val = lookup(attr, sect);

    if (!val)
	return def;

    const tstring &s(expand(val));
    tchar c = (tchar)totlower(s[0]);

    return c == 't' || c == 'y' || c == '1';
}

long Config::get(const tchar *attr, long def, const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const Value *val = lookup(attr, sect);

    return val ? tstrtol(expand(val).c_str(), NULL, 10) : def;
}

ulong Config::get(const tchar *attr, ulong def, const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const Value *val = lookup(attr, sect);

    return val ? tstrtoul(expand(val).c_str(), NULL, 10) : def;
}

double Config::get(const tchar *attr, double def, const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const Value *val = lookup(attr, sect);

    return val ? tstrtod(expand(val).c_str(), NULL) : def;
}

void Config::set(const tchar *attr, const tchar *val, const tchar *sect, bool
    append) {
    attrmap::iterator it;
    const tchar *key = keystr(attr, sect);

    it = amap.find(key);
    if (it == amap.end()) {
	amap.insert(make_pair<const tchar *, Value *>(tstrdup(key), new
	    Value(val, tstrlen(val))));
    } else {
	Value *value = it->second;

	if (append) {
	    if (value->quote && !tstrstr(val, T("${")) && !tstrstr(val,
		T("$("))) {
		_buf = value->quote;
		_buf += value->value;
		_buf += val;
		_buf += value->quote;
	    } else {
		_buf = value->value;
		_buf += val;
	    }
	    val = _buf.c_str();
	}
	delete value;
	it->second = new Value(val, tstrlen(val));
    }
}

void Config::setv(const tchar *attr1, const tchar *val1, ...) {
    const tchar *arg, *attr = NULL, *sect = NULL;
    Locker lkr(lck, !THREAD_ISSELF(locker));
    va_list vl;

    va_start(vl, val1);
    while ((arg = va_arg(vl, const tchar *)) != NULL)
	sect = sect == NULL ? arg : NULL;
    va_end(vl);
    set(attr1, val1, sect, false);
    va_start(vl, val1);
    while ((arg = va_arg(vl, const tchar *)) != NULL) {
	if (attr) {
	    set(attr, arg, sect, false);
	    attr = NULL;
	} else {
	    attr = arg;
	}
    }
    va_end(vl);
}

void Config::trim(tstring &s) {
    tstring::size_type i, j = s.size();

    for (i = 0; i < j; i++)
	if (!istspace(s[i]))
	    break;
    if (i == j) {
	s.erase();
	return;
    }
    for (j--; j; j--)
	if (!istspace(s[j]))
	    break;
    if (i || j != s.size() - 1)
	s = s.substr(i, j - i + 1);
}

bool Config::parse(tistream &is) {
    tstring attr, s, sect, val;
    uint line = 0;
    const tchar *p;

    if (!is)
	return false;
    while (getline(is, attr)) {
	line++;
	trim(attr);
	if (!tstrnicmp(attr.c_str(), T("#include"), 8)) {
	    attr = attr.substr(9, attr.size() - 9);
	    trim(attr);

	    tifstream ifs(attr.c_str());

	    if (!parse(ifs))
		return false;
	    continue;
	}
	if (attr.empty() || attr[0] == ';' || attr[0] == '#' || attr[0] == '=')
	    continue;

	bool append = false;
	tstring::size_type pos;
	tstring::size_type sz = attr.size();

	while (attr[sz - 1] == '\\') {
	    if (getline(is, s)) {
		trim(s);
		if (s[0] == ';' || s[0] == '#') {
		    if (!s.empty() && s[s.size() - 1] != '\\') {
			attr = attr.substr(0, sz - 1);
			trim(attr);
			sz = attr.size();
		    	break;
		    }
		} else {
		    attr = attr.substr(0, sz - 1) + s;
		    sz = attr.size();
		}
	    }
	}
	pos = attr[0] == '[' ? attr.npos : attr.find('=');
	if (pos == attr.npos) {
	    val.erase();
	} else {
	    if (attr[pos - 1] == '+')
		append = true;
	    val = attr.substr(pos + 1, sz - pos);
	    trim(val);
	    attr.erase(pos - (append ? 1 : 0), attr.size());
	    trim(attr);
	}
	if (attr.size() > 2 && attr[0] == '*' && attr[1] == '.') {
	    attr.erase(0, 2);
	} else if (!pre.empty()) {
	    if (attr.compare(0, pre.size(), pre) == 0 &&
		attr.size() > pre.size() + 1 && attr[pre.size()] == '.')
		attr.erase(0, pre.size() + 1);
	    else if (attr.find('.') != attr.npos)
		continue;
	}
	if (attr[0] == '[') {
	    sect = attr.substr(1, attr.size() - 2);
	    trim(sect);
	    p = sect.c_str();
	    if (!tstricmp(p, T("common")) || !tstricmp(p, T("global")))
		sect.erase();
	    ini = true;
	    continue;
	}
	set(attr.c_str(), val.c_str(), sect.c_str(), append);
    }
    return true;
}

bool Config::read(tistream &is, const tchar *str, bool app) {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    bool ret;

    if (!is)
	return false;
    prefix(str);
    if (!app)
	clear();
    ret = parse(is);
    return ret;
}

bool Config::read(const tchar *file, const tchar *str, bool app) {
    if (file)
	path = file;

    tifstream is(path.c_str());

    return read(is, str, app);
}

bool Config::write(tostream &os, bool inistyle) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    attrmap::const_iterator it;
    vector<tstring> lines;
    vector<tstring>::const_iterator lit;
    tstring s;

    for (it = amap.begin(); it != amap.end(); ++it) {
	Value *val = it->second;

	s = it->first;
	s += '=';
	if (val->quote)
	    s += val->quote;
	s += val->value;
	if (val->quote)
	    s += val->quote;
	lines.push_back(s);
    }
    sort(lines.begin(), lines.end());
    for (lit = lines.begin(); lit != lines.end(); ++lit) {
	os << *lit << '\n';
	(void)inistyle;
	// TODO - write ini style cfg
	//os << T("[") << it->first << T("]") << '\n';
    }
    return os.good();
}

bool Config::write(const tchar *file, bool inistyle) const {
    if (!file)
	file = path.c_str();

    tofstream os(tchartoachar(file), ios::binary);

    return write(os, inistyle);
}

