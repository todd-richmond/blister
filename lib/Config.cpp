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
	    if ((*p == '{' || *p == '(') && tstrchr(p, *p == '(' ? ')' : '}')
		!= NULL) {
		expand = true;
		return;
	    }
	}
    }
}

Config::Config(const tchar *file, const tchar *pre): ini(false), locker(0) {
    prefix(pre);
    if (file)
	read(file);
}

const tstring &Config::expand(const Value *value) const {
    tstring::size_type epos, spos;

    if (!value->expand)
	return value->value;
    buf = value->value;
    while ((spos = buf.rfind(T("$("))) != buf.npos ||
	(spos = buf.rfind(T("${"))) != buf.npos) {
	if ((epos = buf.find(buf[spos + 1] == '(' ? ')' : '}', spos + 2)) ==
	    buf.npos)
	    break;

	attrmap::const_iterator it;
	tstring s(buf, spos + 2, epos - spos - 2);

	if (!pre.empty() && s.compare(0, pre.size(), pre) == 0 &&
	    s.size() > pre.size() + 1 && s[pre.size()] == '.')
	    s.erase(0, pre.size() + 1);
	it = amap.find(s.c_str());
	if (it == amap.end())
	    break;
	buf.replace(spos, epos - spos + 1, it->second->value);
    }
    return buf;
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

void Config::erase(const tchar *attr) {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    attrmap::iterator it = amap.find(attr);

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
	amap[tstrdup(key)] = new Value(val, tstrlen(val));
    } else {
	Value *value = it->second;

	if (append) {
	    if (value->quote && !tstrstr(val, T("${")) && !tstrstr(val,
		T("$("))) {
		buf = value->quote;
		buf += value->value;
		buf += val;
		buf += value->quote;
	    } else {
		buf = value->value;
		buf += val;
	    }
	    val = buf.c_str();
	}
	delete value;
	it->second = new Value(val, tstrlen(val));
    }
}

void Config::set(const tchar *attr1, const tchar *val1, const tchar *attr2,
    const tchar *val2, ...) {
    const tchar *arg, *attr = NULL, *sect = NULL;
    attrmap::iterator it;
    Locker lkr(lck, !THREAD_ISSELF(locker));
    va_list vl;

    va_start(vl, val2);
    while ((arg = va_arg(vl, const tchar *)) != NULL)
	sect = sect == NULL ? arg : NULL;
    va_end(vl);
    set(attr1, val1, sect, false);
    set(attr2, val2, sect, false);
    va_start(vl, val2);
    while ((arg = va_arg(vl, const tchar *)) != NULL) {
	if (attr) {
	    set(attr, arg, sect, false);
	    attr = NULL;
	} else {
	    attr = keystr(arg, sect);
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
    bool head = true;
    attrmap::iterator it;
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

	    tifstream is(attr.c_str());

	    if (!parse(is))
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
	    head = sect.empty();
	    ini = true;
	    continue;
	}
	set(attr.c_str(), val.c_str(), sect.c_str(), append);
    }
    return true;
}

bool Config::read(tistream &is, bool app) {
    bool ret;

    if (!is)
	return false;
    lock();
    if (!app)
	clear();
    ret = parse(is);
    unlock();
    return ret;
}

bool Config::read(const tchar *f, bool app) {
    if (f)
	file = f;

    tifstream is(file.c_str());

    return read(is, app);
}

bool Config::write(tostream &os, bool ini) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    attrmap::const_iterator it;
    vector<tstring> lines;
    vector<tstring>::const_iterator lit;
    tstring s, sect;

    for (it = amap.begin(); it != amap.end(); it++) {
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
    for (lit = lines.begin(); lit != lines.end(); lit++) {
	os << *lit << endl;
	(void)ini;
	// TODO - write ini style cfg
	//os << T("[") << it->first << T("]") << endl;
    }
    return os.good();
}

bool Config::write(const tchar *f, bool ini) const {
    if (!f)
	f = file.c_str();

    tofstream os(tchartoachar(f), ios::binary);

    return write(os, ini);
}

