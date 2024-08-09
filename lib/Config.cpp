/*
 * Copyright 2001-2023 Todd Richmond
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

#ifdef WIN32
#define ENDL "\r\n"
#else
#define ENDL '\n'
#endif

void Config::clear(void) {
    kvmap::iterator it;
    WLocker lkr(lck, !THREAD_ISSELF(locker));

    while ((it = amap.begin()) != amap.end()) {
	const KV *kv = it->second;

	amap.erase(it);
	delkv(kv);
    }
}

void Config::erase(const tchar *key, const tchar *sect) {
    kvmap::iterator it;
    WLocker lkr(lck, !THREAD_ISSELF(locker));

    if (sect && *sect) {
	size_t klen = tstrlen(key);
	size_t slen = tstrlen(sect);
	tstring s;

	s.reserve(slen + 1 + klen);
	s.append(sect, slen).append(1, (tchar)'.').append(key, klen);
	it = amap.find(s.c_str());
    } else {
	it = amap.find(key);
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
	tstring::size_type off = val[spos + 2] == '*' && val[spos + 3] == '.' ?
            2 : 0;
        tstring s(val, spos + 2 + off, epos - spos - 2 - off);

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

const tstring Config::get(const tchar *key, const tchar *def, const tchar
    *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);
    static tstring empty;

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? std::move(s) : def ? def : empty;
    }
    return kv ? kv->val : def ? def : empty;
}

bool Config::get(const tchar *key, bool def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);
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

long Config::get(const tchar *key, long def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? stol(s) : def;
    }
    return kv ? tstrtol(kv->val, NULL, 10) : def;
}

llong Config::get(const tchar *key, llong def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? stoll(s) : def;
    }
    return kv ? tstrtoll(kv->val, NULL, 10) : def;
}

ulong Config::get(const tchar *key, ulong def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? stoul(s) : def;
    }
    return kv ? tstrtoul(kv->val, NULL, 10) : def;
}

ullong Config::get(const tchar *key, ullong def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? stoull(s) : def;
    }
    return kv ? tstrtoull(kv->val, NULL, 10) : def;
}

double Config::get(const tchar *key, double def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (kv && kv->expand) {
	tstring s;

	return expandkv(kv, s) ? stod(s) : def;
    }
    return kv ? tstrtod(kv->val, NULL) : def;
}

const Config::KV *Config::getkv(const tchar *key, const tchar *sect) const {
    kvmap::const_iterator it;

    if (sect && *sect) {
	size_t klen = tstrlen(key);
	size_t slen = tstrlen(sect);
	tstring s;

	s.reserve(slen + 1 + klen);
	s.append(sect, slen).append(1, (tchar)'.').append(key, klen);
	it = amap.find(s.c_str());
    } else {
	it = amap.find(key);
    }
    return it == amap.end() ? NULL : it->second;
}

// 1 allocation for key, val, state
const Config::KV *Config::newkv(const tchar *key, size_t klen, const tchar
    *val, size_t vlen) {
    KV *kv = (KV *)new char[offsetof(KV, val) + klen + vlen + 2];

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
    kv->key = (const tchar *)memcpy(kv->val + vlen + 1, key, klen);
    ((char *)kv->key)[klen] = '\0';
    if (kv->quote != '\'') {
	const tchar *p = kv->val;

	while ((p = tstrchr(p, '$')) != NULL) {
	    ++p;
	    if ((*p == '{' || *p == '(') && tstrchr(p, *p == '(' ? ')' : '}') !=
		NULL) {
		kv->expand = true;
		break;
	    }
	}
    }
#pragma warning(disable: 26402)
    return kv;
}

bool Config::parse(tistream &is) {
    tstring key, s, sect, val;
    const tchar *p;

    if (!is)
	return false;
    while (getline(is, key)) {
	trim(key);
	if (!tstrnicmp(key.c_str(), T("#include"), 8)) {
	    key.erase(0, 9);
	    trim(key);

	    tifstream ifs(key.c_str());

	    if (!parse(ifs))
		return false;
	    continue;
	}
	if (key.empty() || key[0] == ';' || key[0] == '#' || key[0] == '=')
	    continue;

	bool app = false;
	tstring::size_type pos;
	tstring::size_type sz = key.size();

	while (key[sz - 1] == '\\') {
	    if (getline(is, s)) {
		trim(s);
		if (s.empty()) {
		} else if (s[0] == ';' || s[0] == '#') {
		    if (s[s.size() - 1] != '\\') {
			key.resize(sz - 1);
			trim(key);
			sz = key.size();
			break;
		    }
		} else {
		    key.resize(sz - 1);
		    key += s;
		    sz = key.size();
		}
	    }
	}
	pos = key[0] == '[' ? key.npos : key.find('=');
	if (pos == key.npos) {
	    val.erase();
	} else {
	    if (key[pos - 1] == '+')
		app = true;
	    val.assign(key.c_str() + pos + 1, sz - pos - 1);
	    trim(val);
	    key.erase(pos - (app ? 1 : 0), key.size());
	    trim(key);
	}
	if (key.size() > 2 && key[0] == '*' && key[1] == '.') {
	    key.erase(0, 2);
	} else if (!pre.empty()) {
	    if (key.compare(0, pre.size(), pre) == 0 &&
		key.size() > pre.size() + 1 && key[pre.size()] == '.')
		key.erase(0, pre.size() + 1);
	    else if (key.find('.') != key.npos)
		continue;
	}
	if (key[0] == '[') {
	    sect.assign(key.c_str() +  1, key.size() - 2);
	    trim(sect);
	    p = sect.c_str();
	    if (!tstricmp(p, T("common")) || !tstricmp(p, T("global")))
		sect.erase();
	    ini = true;
	    continue;
	}
	set(key.c_str(), key.size(), val.c_str(), val.size(), sect.c_str(),
	    sect.size(), app);
    }
    return true;
}

bool Config::read(tistream &is, const tchar *str, bool app) {
    WLocker lkr(lck, !THREAD_ISSELF(locker));

    if (!is)
	return false;
    prefix(str);
    if (!app) {
	if (THREAD_ISSELF(locker)) {
	    clear();
	} else {
	    locker = THREAD_ID();
	    clear();
	    locker = 0;
	}
    }
    return parse(is);
}

Config &Config::set(const tchar *key, size_t klen, const tchar *val, size_t
    vlen, const tchar *sect, size_t slen, bool append) {
    const KV *kv, *oldkv;

    if (slen) {
	tstring s;

	s.reserve(slen + 1 + klen);
	s.append(sect, slen).append(1, (tchar)'.').append(key, klen);
	kv = newkv(s.c_str(), s.size(), val, vlen);
    } else {
	kv = newkv(key, klen, val, vlen);
    }

    pair<kvmap::const_iterator, bool> old(amap.emplace(kv->key, kv));

    if (old.second)
	return *this;
    oldkv = old.first->second;
    if (append) {
	tstring s;

	delkv(kv);
	if (oldkv->quote)
	    s = oldkv->quote;
	s += oldkv->val;
	if (vlen > 1 && (val[0] == '"' || val[0] == '\'') && val[vlen - 1] ==
	    val[0])
	    s.append(val + 1, vlen - 2);
	else
	    s.append(val, vlen);
	if (oldkv->quote)
	    s += oldkv->quote;
	vlen = s.size();
	kv = newkv(oldkv->key, tstrlen(oldkv->key), s.c_str(), vlen);
    }
    amap.erase(old.first);
    delkv(oldkv);
    amap.emplace(kv->key, kv);
    return *this;
}

Config &Config::setv(const tchar *key1, const tchar *val1, ...) {
    const tchar *arg, *key = NULL, *sect = NULL;
    size_t slen;
    va_list vl;

    va_start(vl, val1);
    while ((arg = va_arg(vl, const tchar *)) != NULL)
	sect = sect == NULL ? arg : NULL;
    va_end(vl);
    slen = sect ? tstrlen(sect) : 0;
    lock();
    set(key1, tstrlen(key1), val1, tstrlen(val1), sect, slen);
    va_start(vl, val1);
    while ((arg = va_arg(vl, const tchar *)) != NULL) {
	if (key) {
	    set(key, tstrlen(key), arg, tstrlen(arg), sect, slen);
	    key = NULL;
	} else {
	    key = arg;
	}
    }
    unlock();
    va_end(vl);
    return *this;
}

void Config::trim(tstring &s) {
    tstring::size_type i, j = s.size();

    while (UNLIKELY(j && istspace(s[--j])))
	s.erase(j);
    for (i = 0; i < j; i++)
	if (LIKELY(!istspace(s[i])))
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
	keys.emplace_back(it->first);
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
	const KV *kv;

	it = amap.find(key);
	if (it == amap.end())
	    continue;
	kv = it->second;
	if ((dot = tstrchr(key, '.')) == NULL) {
	    if (inistyle) {
		sect = '.';
	    } else {
		sect.assign(key);
		if (cnt > 1 || (cnt == 1 && u + 1 < keys.size() &&
		    !tstrncmp(keys[u + 1], sect.c_str(), sect.size()) &&
		    keys[u + 1][sect.size()] == '.'))
		    os << ENDL;
		cnt = 0;
	    }
	} else {
	    if (tstrncmp(key, sect.c_str(), (size_t)(dot - key)) != 0) {
		sect.assign(key, (size_t)(dot - key));
		if (cnt) {
		    os << ENDL;
		    cnt = 0;
		}
		if (inistyle)
		    os << T("[") << sect << T("]") << ENDL;
	    }
	    if (inistyle)
		key = dot + 1;
	}
	++cnt;
	os << key << '=';
	if (kv->quote)
	    os << kv->quote << kv->val << kv->quote;
	else
	    os << kv->val;
	os << ENDL;
    }
    os.flush();
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
