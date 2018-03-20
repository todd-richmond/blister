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
#include <stdarg.h>
#include <algorithm>
#include <fstream>
#include <vector>
#include "Config.h"

void Config::Value::append(const tchar *val) {
    size_t len = tstrlen(val);

    if (len > 1 && (val[0] == '"' || val[0] == '\'') && val[len - 1] == val[0]) {
	if (!quote)
	    quote = val[0];
	value.append(val, 1, len - 2);
    } else {
	value.append(val, 0, len);
    }
    if (!expand && quote != '\'') {
	const tchar *p = val;

	while ((p = tstrchr(p, '$')) != NULL && *++p) {
	    if ((*p == '{' || *p == '(') && tstrchr(p, *p == '(' ? ')' : '}') !=
		NULL) {
		expand = true;
		break;
	    }
	}
    }
}

void Config::clear(void) {
    attrmap::iterator it;
    WLocker lkr(lck);

    while ((it = amap.begin()) != amap.end()) {
	const tchar *p = it->first;

	delete it->second;
	amap.erase(it);
	delete [] p;
    }
}

void Config::erase(const tchar *attr, const tchar *sect) {
    attrmap::iterator it;
    WLocker lkr(lck);

    if (sect && *sect) {
	tstring s(sect);

	s += '.';
	s += attr;
	it = amap.find(s.c_str());
    } else {
	it = amap.find(attr);
    }
    if (it != amap.end()) {
	const tchar *p = it->first;

	delete it->second;
	amap.erase(it);
	delete [] p;
    }
}

bool Config::expand(const Value *value, tstring &val) const {
    tstring::size_type epos, spos;

    val = value->value;
    while ((spos = val.rfind(T("$("))) != val.npos ||
	(spos = val.rfind(T("${"))) != val.npos) {
	if ((epos = val.find(val[spos + 1] == '(' ? ')' : '}', spos + 2)) ==
	    val.npos)
	    break;

	attrmap::const_iterator it;
	tstring s(val, spos + 2, epos - spos - 2);

	if (!pre.empty() && s.compare(0, pre.size(), pre) == 0 && s.size() >
	    pre.size() + 1 && s[pre.size()] == '.')
	    s.erase(0, pre.size() + 1);
	it = amap.find(s.c_str());
	if (it == amap.end())
	    break;
	val.replace(spos, epos - spos + 1, it->second->value);
    }
    return !val.empty();
}

const tstring Config::get(const tchar *attr, const tchar *def,
    const tchar *sect) const {
    RLocker lkr(lck);
    const Value *val = lookup(attr, sect);
    static tstring empty;

    if (val && val->expand) {
	tstring s;

	return expand(val, s) ? s.c_str() : def ? def : empty;
    }
    return val ? val->value : def ? def : empty;
}

bool Config::get(const tchar *attr, bool def, const tchar *sect) const {
    RLocker lkr(lck);
    const Value *val = lookup(attr, sect);
    tchar c;

    if (val) {
	if (val->expand) {
	    tstring s;

	    if (!expand(val, s))
		return def;
	    c = (tchar)totlower(s[0]);
	} else {
	    c = (tchar)totlower(val->value[0]);
	}
    } else {
	return def;
    }
    return c == 't' || c == 'y' || c == '1';
}

long Config::get(const tchar *attr, long def, const tchar *sect) const {
    RLocker lkr(lck);
    const Value *val = lookup(attr, sect);

    if (val && val->expand) {
	tstring s;

	return expand(val, s) ? tstrtol(s.c_str(), NULL, 10) : def;
    }
    return val ? tstrtol(val->value.c_str(), NULL, 10) : def;
}

ulong Config::get(const tchar *attr, ulong def, const tchar *sect) const {
    RLocker lkr(lck);
    const Value *val = lookup(attr, sect);

    if (val && val->expand) {
	tstring s;

	return expand(val, s) ? tstrtoul(s.c_str(), NULL, 10) : def;
    }
    return val ? tstrtoul(val->value.c_str(), NULL, 10) : def;
}

double Config::get(const tchar *attr, double def, const tchar *sect) const {
    RLocker lkr(lck);
    const Value *val = lookup(attr, sect);

    if (val && val->expand) {
	tstring s;

	return expand(val, s) ? tstrtod(s.c_str(), NULL) : def;
    }
    return val ? tstrtod(val->value.c_str(), NULL) : def;
}

const Config::Value *Config::lookup(const tchar *attr, const tchar *sect) const {
    attrmap::const_iterator it;

    if (sect && *sect) {
	string s(sect);

	s += '.';
	s += attr;
	it = amap.find(s.c_str());
    } else {
	it = amap.find(attr);
    }
    return it == amap.end() ? NULL : it->second;
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
		    attr.resize(sz - 1);
		    attr += s;
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
    WLocker lkr(lck);

    if (!is)
	return false;
    prefix(str);
    if (!app) {
	attrmap::iterator it;
	const tchar *p;

	while ((it = amap.begin()) != amap.end()) {
	    p = it->first;
	    delete it->second;
	    amap.erase(it);
	    delete [] p;
	}
    }
    return parse(is);
}

void Config::set(const tchar *attr, const tchar *val, const tchar *sect, bool
    append) {
    attrmap::iterator it;
    char *key;
    uint sz;
    Value *value;

    if (sect && *sect) {
	tstring s(sect);

	s += '.';
	s += attr;
	it = amap.find(s.c_str());
	if (it == amap.end()) {
	    sz = (uint)s.size() + 1;
	    key = new char[sz];
	    amap.insert(make_pair((const char *)memcpy(key, s.c_str(), sz),
		new Value(val)));
	    return;
	}
    } else {
	it = amap.find(attr);
	if (it == amap.end()) {
	    sz = (uint)tstrlen(attr) + 1;
	    key = new char[sz];
	    amap.insert(make_pair((const char *)memcpy(key, attr, sz),
		new Value(val)));
	    return;
	}
    }
    attr = it->first;
    value = it->second;
    if (append) {
	value->append(val);
    } else {
	delete value;
	amap[attr] =  new Value(val);
    }
}

void Config::setv(const tchar *attr1, const tchar *val1, ...) {
    const tchar *arg, *attr = NULL, *sect = NULL;
    va_list vl;

    va_start(vl, val1);
    while ((arg = va_arg(vl, const tchar *)) != NULL)
	sect = sect == NULL ? arg : NULL;
    va_end(vl);
    lck.wlock();
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
    lck.wunlock();
    va_end(vl);
}

void Config::trim(tstring &s) const {
    tstring::size_type i, j;

    for (j = s.size(); j; j--)
	if (!istspace(s[j]))
	    break;
    if (++j < s.size())
	s.erase(j);
    for (i = 0; i < j; i++)
	if (!istspace(s[i]))
	    break;
    if (i)
	s.erase(0, i);
}

bool Config::write(tostream &os, bool inistyle) const {
    ulong cnt = 0;
    RLocker lkr(lck);
    attrmap::const_iterator it;
    vector<const tchar *> keys;
    vector<const tchar *>::const_iterator kit;
    tstring sect;

    keys.reserve(amap.size());
    for (it = amap.begin(); it != amap.end(); ++it)
	keys.push_back(it->first);
    if (inistyle) {
	struct {
	    bool operator ()(const tchar *a, const tchar *b) const {
		const tchar *ap = tstrchr(a, '.');
		const tchar *bp = tstrchr(b, '.');

		if (!ap)
		    return bp ? true : stringless(a, b);
		else if (!bp)
		    return false;
		return stringless(a, b);
	    }
	} cmp;

	sort(keys.begin(), keys.end(), cmp);
    } else {
	strless<tchar> cmp;

	sort(keys.begin(), keys.end(), cmp);
    }
    for (uint u = 0; u < keys.size(); ++u) {
	const tchar *dot;
	const tchar *key = keys[u];
	const Value *val = amap.find(key)->second;

	if ((dot = tstrchr(key, '.')) == NULL) {
	    if (inistyle) {
		sect = '.';
	    } else {
		sect.assign(key);
		if (cnt > 1 || (cnt == 1 && u < keys.size() - 1 &&
		    !tstrncmp(keys[u + 1], sect.c_str(), sect.size()) &&
		    keys[u + 1][sect.size()] == '.' ))
		    os << endl;
		cnt = 0;
	    }
	} else {
	    if (tstrncmp(key, sect.c_str(), (size_t)(dot - key))) {
		sect.assign(key, (size_t)(dot - key));
		if (cnt) {
		    os << endl;
		    cnt = 0;
		}
		if (inistyle)
		    os << T("[") << sect << T("]") << endl;
	    }
	    if (inistyle)
		key = dot + 1;
	}
	++cnt;
	os << key << '=';
	if (val->quote)
	    os << val->quote;
	os << val->value;
	if (val->quote)
	    os << val->quote;
	os << endl;
    }
    return os.good();
}

ConfigFile::ConfigFile(const tchar *file, const tchar *str): Config(str) {
    if (file)
	read(file, str);
}

bool ConfigFile::read(const tchar *file, const tchar *str, bool app) {
    if (file)
	path = file;

    tifstream is(path.c_str());

    return read(is, str, app);
}

bool ConfigFile::write(const tchar *file, bool inistyle) const {
    if (file) {
	tofstream os(tchartoachar(file));

	return write(os, inistyle);
    } else {
	string tmp(path + T(".tmp"));
	tofstream os(tchartoachar(tmp));

	if (!write(os, inistyle) || !rename(tstringtoachar(tmp),
	    tstringtoachar(path))) {
	    unlink(tstringtoachar(tmp));
	    return false;
	}
	return true;
    }
}
