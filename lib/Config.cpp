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
#include <stdarg.h>
#include <algorithm>
#include <fstream>
#include <vector>
#include "Config.h"

// 1 allocation for key, val, state
const Config::KV *Config::newkv(const tchar *key, const tchar *val) const {
    size_t klen = tstrlen(key);
    size_t vlen = tstrlen(val);
    char *ret = new char[sizeof (KV) + klen + vlen + 2];
    KV *kv = (KV *)ret;

    kv->expand = false;
    if (vlen > 1 && (val[0] == '"' || val[0] == '\'') && val[vlen - 1] ==
	val[0]) {
	kv->quote = val[0];
	++val;
	vlen -= 2;
    } else {
	kv->quote = '\0';
    }
    memcpy(kv->val, val, vlen);
    kv->val[vlen] = '\0';
    kv->key = (const tchar *)memcpy(kv->val + vlen + 1, key, klen + 1);
    if (kv->quote != '\'') {
	const tchar *p = val;

	while ((p = tstrchr(p, '$')) != NULL && *++p) {
	    if ((*p == '{' || *p == '(') && tstrchr(p, *p == '(' ? ')' : '}') !=
		NULL) {
		kv->expand = true;
		break;
	    }
	}
    }
    // cppcheck-suppress memleak
    return kv;
}

void Config::clear(void) {
    kvmap::iterator it;
    WLocker lkr(lck, !THREAD_ISSELF(locker));

    while ((it = amap.begin()) != amap.end()) {
	const KV *kv = it->second;

	amap.erase(it);
	delkv(kv);
    }
}

void Config::erase(const tchar *attr, const tchar *sect) {
    kvmap::iterator it;
    WLocker lkr(lck, !THREAD_ISSELF(locker));

    if (sect && *sect) {
	tstring s(sect);

	s += '.';
	s += attr;
	it = amap.find(s.c_str());
    } else {
	it = amap.find(attr);
    }
    if (it != amap.end()) {
	const KV *kv = it->second;

	amap.erase(it);
	delkv(kv);
    }
}

bool Config::expandkv(const KV *kv, tstring &val) const {
    tstring::size_type epos, spos;

    val = kv->val;
    while ((spos = val.rfind(T("$("))) != val.npos ||
	(spos = val.rfind(T("${"))) != val.npos) {
	if ((epos = val.find(val[spos + 1] == '(' ? ')' : '}', spos + 2)) ==
	    val.npos)
	    break;

	kvmap::const_iterator it;
	tstring s(val, spos + 2, epos - spos - 2);

	if (!pre.empty() && s.compare(0, pre.size(), pre) == 0 && s.size() >
	    pre.size() + 1 && s[pre.size()] == '.')
	    s.erase(0, pre.size() + 1);
	it = amap.find(s.c_str());
	if (it == amap.end())
	    break;
	val.replace(spos, epos - spos + 1, it->second->val);
    }
    return !val.empty();
}

const tstring Config::get(const tchar *attr, const tchar *def,
    const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(attr, sect);
    static tstring empty;

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? s : def ? def : empty;
    }
    return kv ? kv->val : def ? def : empty;
}

bool Config::get(const tchar *attr, bool def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(attr, sect);
    tchar c;

    if (kv) {
	if (kv->expand) {
	    tstring s;

	    if (!expandkv(kv, s))
		return def;
	    c = (tchar)totlower(s[0]);
	} else {
	    c = (tchar)totlower(kv->val[0]);
	}
    } else {
	return def;
    }
    return c == 't' || c == 'y' || c == '1';
}

long Config::get(const tchar *attr, long def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(attr, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? tstrtol(s.c_str(), NULL, 10) : def;
    }
    return kv ? tstrtol(kv->val, NULL, 10) : def;
}

llong Config::get(const tchar *attr, llong def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(attr, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? tstrtoll(s.c_str(), NULL, 10) : def;
    }
    return kv ? tstrtoll(kv->val, NULL, 10) : def;
}

ulong Config::get(const tchar *attr, ulong def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(attr, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? tstrtoul(s.c_str(), NULL, 10) : def;
    }
    return kv ? tstrtoul(kv->val, NULL, 10) : def;
}

ullong Config::get(const tchar *attr, ullong def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(attr, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? tstrtoull(s.c_str(), NULL, 10) : def;
    }
    return kv ? tstrtoull(kv->val, NULL, 10) : def;
}

double Config::get(const tchar *attr, double def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(attr, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? tstrtod(s.c_str(), NULL) : def;
    }
    return kv ? tstrtod(kv->val, NULL) : def;
}

const Config::KV *Config::getkv(const tchar *attr, const tchar *sect) const {
    kvmap::const_iterator it;

    if (sect && *sect) {
	tstring s(sect);

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
    WLocker lkr(lck, !THREAD_ISSELF(locker));

    if (!is)
	return false;
    prefix(str);
    if (!app) {
	kvmap::iterator it;

	while ((it = amap.begin()) != amap.end()) {
	    const KV *kv = it->second;

	    amap.erase(it);
	    delkv(kv);
	}
    }
    return parse(is);
}

void Config::set(const tchar *attr, const tchar *val, const tchar *sect, bool
    append) {
    kvmap::iterator it;
    const KV *kv, *oldkv;

    if (sect && *sect) {
	tstring s(sect);

	s += '.';
	s += attr;
	it = amap.find(s.c_str());
	if (it == amap.end()) {
	    kv = newkv(s.c_str(), val);
	    addkv(kv);
	    return;
	}
    } else {
	it = amap.find(attr);
	if (it == amap.end()) {
	    kv = newkv(attr, val);
	    addkv(kv);
	    return;
	}
    }
    oldkv = it->second;
    if (append) {
	size_t len = tstrlen(val);
	tstring s;

	if (oldkv->quote)
	    s += oldkv->quote;
	s += oldkv->val;
	if (len > 1 && (val[0] == '"' || val[0] == '\'') && val[len - 1] == val[0])
	    s.append(val + 1, len - 2);
	else
	    s.append(val, len);
	if (oldkv->quote)
	    s += oldkv->quote;
	kv = newkv(oldkv->key, s.c_str());
    } else {
	kv = newkv(oldkv->key, val);
    }
    amap.erase(it);
    delkv(oldkv);
    addkv(kv);
}

void Config::setv(const tchar *attr1, const tchar *val1, ...) {
    const tchar *arg, *attr = NULL, *sect = NULL;
    va_list vl;

    va_start(vl, val1);
    while ((arg = va_arg(vl, const tchar *)) != NULL)
	sect = sect == NULL ? arg : NULL;
    va_end(vl);
    lock();
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
    unlock();
    va_end(vl);
}

void Config::trim(tstring &s) const {
    tstring::size_type i, j;

    for (j = s.size(); j; j--)
	if (!istspace(s[j - 1]))
	    break;
    if (j < s.size())
	s.erase(j);
    for (i = 0; i < j; i++)
	if (!istspace(s[i]))
	    break;
    if (i)
	s.erase(0, i);
}

bool Config::write(tostream &os, bool inistyle) const {
    ulong cnt = 0;
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    kvmap::const_iterator it;
    vector<const tchar *> keys;
    tstring sect;

    keys.reserve(amap.size());
    for (it = amap.begin(); it != amap.end(); ++it)
	keys.push_back(it->first);
    if (inistyle) {
	struct keyless cmp;

	sort(keys.begin(), keys.end(), cmp);
    } else {
	strless<tchar> cmp;

	sort(keys.begin(), keys.end(), cmp);
    }
    for (vector<const tchar *>::size_type u = 0; u < keys.size(); ++u) {
	const tchar *dot;
	const tchar *key = keys[u];
	const KV *kv = amap.find(key)->second;

	if ((dot = tstrchr(key, '.')) == NULL) {
	    if (inistyle) {
		sect = '.';
	    } else {
		sect.assign(key);
		if (cnt > 1 || (cnt == 1 && u + 1 < keys.size() &&
		    !tstrncmp(keys[u + 1], sect.c_str(), sect.size()) &&
		    keys[u + 1][sect.size()] == '.'))
		    os << endl;
		cnt = 0;
	    }
	} else {
	    if (tstrncmp(key, sect.c_str(), (size_t)(dot - key)) != 0) {
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
	if (kv->quote)
	    os << kv->quote;
	os << kv->val;
	if (kv->quote)
	    os << kv->quote;
	os << endl;
    }
    return os.good();
}

ConfigFile::ConfigFile(const tchar *file, const tchar *_pre): Config(_pre) {
    if (file)
	read(file, _pre);
}

bool ConfigFile::read(const tchar *file, const tchar *_pre, bool app) {
    if (file)
	path = file;

    tifstream is(path.c_str());

    return read(is, _pre, app);
}

bool ConfigFile::write(const tchar *file, bool inistyle) const {
    if (file) {
	tofstream os(tchartoachar(file));

	return write(os, inistyle);
    } else {
	tstring tmp(path + T(".tmp"));
	tofstream os(tstringtoachar(tmp));

	if (!write(os, inistyle) || rename(tstringtoachar(tmp),
	    tstringtoachar(path))) {
	    unlink(tstringtoachar(tmp));
	    return false;
	}
	return true;
    }
}
