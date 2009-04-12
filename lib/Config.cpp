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
#include <algorithm>
#include "Config.h"

Config::Value::Value(const tstring val): expand(false), quote(0) {
    tstring::size_type sz = val.size();

    if (sz > 1 && (val[0] == '"' || val[0] == '\'') && val[sz] == val[0]) {
	quote = val[0];
	value.assign(val, 1, sz - 2);
    } else {
	tstring::size_type pos = val.find('$');

	if (((pos = val.find(T("$("))) != val.npos ||
	    (pos = val.find(T("${"))) != val.npos) &&
	    val.find(val[pos + 1] == '(' ? ')' : '}', pos + 2) != val.npos)
	    expand = true;
	value = val;
    }
}

Config::Config(const tchar *file, const tchar *pre): ini(false), locker(0) {
    prefix(pre);
    if (file)
	read(file);
}

const tstring &Config::expand(const Value *value) const {
    tstring::size_type spos, epos;

    if (!value->expand)
	return value->value;
    buf = value->value;
    while ((spos = buf.find(T("$("))) != buf.npos ||
	(spos = buf.find(T("${"))) != buf.npos) {
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

    return s[0] == '1' || totlower(s[0]) == 't' || totlower(s[0]) == 'y' ||
	!tstricmp(s.c_str(), T("on"));
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

void Config::set(const tchar *attr, const tchar *val, const tchar *sect) {
    attrmap::iterator it;
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const tchar *key = keystr(attr, sect);

    it = amap.find(key);
    if (it == amap.end()) {
	amap[stringdup(key)] = new Value(val);
    } else {
	delete it->second;
	it->second = new Value(val);
    }
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
    tstring s, attr, val, sect;
    attrmap::iterator it;
    const tchar *p;
    uint line = 0;
    bool head = true;

    if (!is)
	return false;
    while (getline(is, attr)) {
	line++;
	trim(attr);
	if (!tstrnicmp(attr.c_str(), T("#include"), 8)) {
	    attr = attr.substr(9, attr.size() - 9);
	    trim(attr);

	    tifstream is(tstringtoa(attr).c_str());

	    if (!parse(is))
		return false;
	    continue;
	}
	if (attr.empty() || attr[0] == ';' || attr[0] == '#' || attr[0] == '=')
	    continue;

	bool plus = false;
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
		plus = true;
	    val = attr.substr(pos + 1, sz - pos);
	    trim(val);
	    attr.erase(pos - (plus ? 1 : 0), attr.size());
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

	const tchar *key = keystr(attr.c_str(), sect.empty() ? NULL :
	    sect.c_str());

	it = amap.find(key);
	if (it == amap.end()) {
	    amap[tstrdup(key)] = new Value(val);
	} else {
	    if (plus)
		it->second->value += val;
	    else
	    	it->second->value = val;
	}
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

    tifstream is(tstringtoa(file).c_str());

    return read(is, app);
}

bool Config::write(tostream &os, bool ini) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    attrmap::const_iterator it;
    vector<tstring> lines;
    vector<tstring>::const_iterator lit;
    tstring s;
    tstring sect;

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
	// incomplete - write ini style cfg
	//os << T("[") << it->first << T("]") << endl;
    }
    return os.good();
}

bool Config::write(const tchar *f, bool ini) const {
    if (!f)
	f = file.c_str();

    tofstream os(tchartoa(f).c_str(), ios::binary);

    return write(os, ini);
}

