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
#include <stdarg.h>
#include <algorithm>
#include <fstream>
#include <vector>
#include <sys/stat.h>
#include "Config.h"

#ifdef WIN32
#define ENDL "\r\n"
#else
#define ENDL '\n'
#endif

constexpr uint BUFSZ = 32 * 1024U;
constexpr uint KEYSZ = 256;

template<typename T>
static T atou(const tchar *str) {
    tchar c = *str;
    T val = 0;

    while (c >= '0' && c <= '9') {
	val = val * 10 + (T)(c - '0');
	c = *(++str);
    }
    return val;
}

template<typename T>
static T atoi(const tchar *str) {
    return *str == '-' ? -1 * atou<T>(str + 1) : atou<T>(str);
}

void Config::clear(void) {
    WLocker lkr(lck, !THREAD_ISSELF(locker));
    kvmap::size_type sz = amap.size(), u = sz;
    const KV **kvs = new const KV *[(uint)sz];

    for (kvmap::const_iterator it = amap.begin(); it != amap.end(); ++it)
	kvs[--u] = it->second;
    amap.clear();
    for (u = 0; u < sz; ++u)
	delkv(kvs[u]);
    delete [] kvs;
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

const tstring Config::get(const tchar *key, const tchar *def, const tchar *sect)
    const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (LIKELY(kv)) {
	if (LIKELY(!kv->expand))
	    return kv->val;
	tstring s;
	if (expandkv(kv, s))
	    return s;
    }
    return def ? tstring(def) : tstring();
}

bool Config::get(const tchar *key, bool def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (LIKELY(kv)) {
	tchar c;
	if (LIKELY(!kv->expand)) {
	    c = (tchar)totlower(kv->val[0]);
	} else {
	    tstring s;
	    if (!expandkv(kv, s))
		return def;
	    c = (tchar)totlower(s[0]);
	}
	return c == 't' || c == 'y' || c == '1';
    }
    return def;
}

long Config::get(const tchar *key, long def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (LIKELY(kv)) {
	if (LIKELY(!kv->expand))
	    return atoi<long>(kv->val);
	tstring s;
	if (expandkv(kv, s))
	    return atoi<long>(s.c_str());
    }
    return def;
}

llong Config::get(const tchar *key, llong def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (LIKELY(kv)) {
	if (LIKELY(!kv->expand))
	    return atoi<llong>(kv->val);
	tstring s;
	if (expandkv(kv, s))
	    return atoi<llong>(s.c_str());
    }
    return def;
}

ulong Config::get(const tchar *key, ulong def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (LIKELY(kv)) {
	if (LIKELY(!kv->expand))
	    return atou<ulong>(kv->val);
	tstring s;
	if (expandkv(kv, s))
	    return atou<ulong>(s.c_str());
    }
    return def;
}

ullong Config::get(const tchar *key, ullong def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (LIKELY(kv)) {
	if (LIKELY(!kv->expand))
	    return atou<ullong>(kv->val);
	tstring s;
	if (expandkv(kv, s))
	    return atou<ullong>(s.c_str());
    }
    return def;
}

double Config::get(const tchar *key, double def, const tchar *sect) const {
    RLocker lkr(lck, !THREAD_ISSELF(locker));
    const KV *kv = getkv(key, sect);

    if (LIKELY(kv)) {
	if (LIKELY(!kv->expand))
	    return atoi<long>(kv->val);
	tstring s;
	if (expandkv(kv, s))
	    return atoi<long>(kv->val);
    }
    return def;
}

const Config::KV *Config::getkv(const tchar *key, const tchar *sect) const {
    kvmap::const_iterator it;

    if (sect && *sect) {
	size_t klen = tstrlen(key);
	size_t slen = tstrlen(sect);
	size_t total = slen + 1 + klen;

	if (LIKELY(total + 1 < KEYSZ)) {
	    tchar buf[KEYSZ];
	    tchar *p = buf;

	    memcpy(p, sect, slen * sizeof (tchar));
	    p += slen;
	    *p++ = (tchar)'.';
	    memcpy(p, key, (klen + 1) * sizeof (tchar));
	    it = amap.find(buf);
	} else {
	    tstring s;

	    s.reserve(total);
	    s.append(sect, slen).append(1, (tchar)'.').append(key, klen);
	    it = amap.find(s.c_str());
	}
    } else {
	it = amap.find(key);
    }
    return it == amap.end() ? NULL : it->second;
}

// 1 allocation for key, val, state
const Config::KV *Config::newkv(const tchar *key, size_t klen, const tchar *val,
    size_t vlen) {
    KV *kv = (KV *)new char[offsetof(KV, val) + klen + vlen + 2];
    tchar quote = '\0';

    if (UNLIKELY(vlen > 1 && (val[0] == '"' || val[0] == '\''))) {
	if (val[vlen - 1] == val[0]) {
	    quote = val[0];
	    ++val;
	    vlen -= 2;
	}
    }
    kv->quote = quote;
    memcpy(kv->val, val, vlen * sizeof (tchar));
    kv->val[vlen] = '\0';
    kv->key = (tchar *)memcpy(kv->val + vlen + 1, key, klen * sizeof (tchar));
    kv->key[klen] = '\0';
    kv->expand = false;
    if (LIKELY(vlen > 3 && quote != '\'')) {
#ifdef _UNICODE
	const tchar *p = tstrchr(kv->val, '$');
#else
	const tchar *p = (const tchar *)memchr(kv->val, '$', vlen);
#endif
	while (p != NULL) {
	    ++p;
	    if (*p == '{' || *p == '(') {
		tchar close = *p == '(' ? ')' : '}';
		if (tstrchr(p, close) != NULL) {
		    kv->expand = true;
		    break;
		}
	    }
#ifdef _UNICODE
	    p = tstrchr(p, '$');
#else
	    size_t remaining = vlen - (size_t)(p - kv->val);
	    p = (const tchar *)memchr(p, '$', remaining);
#endif
	}
    }
#pragma warning(disable: 26402)
    return kv;
}

bool Config::parse(tistream &is) {
    bool app;
    tstring_view key, val;
    tstring line, sect;
    tstring::size_type pos;

    if (!is)
	return false;
    while (getline(is, line)) {
	size_t len = line.size();

	while (len > 0 && istspace(line[len - 1]))
	    --len;
	if (len == 0)
	    continue;
	line.resize(len);
	while (line.back() == '\\') {
	    tstring s;

	    line.pop_back();
	    len = line.size();
	    while (len > 0 && istspace(line[len - 1]))
		--len;
	    line.resize(len);
	    if (getline(is, s)) {
		tstring_view sv(s);

		trim(sv);
		if (!sv.empty())
		    line += sv.front() == ';' || sv.front() == '#' ? "\\" : s;
	    }
	}
	len = line.size();
	while (UNLIKELY(len > 0 && istspace(line[len - 1])))
	    --len;
	if (UNLIKELY(len == 0))
	    continue;
	key = tstring_view(line.data(), len);
	switch (key.front()) {
	case ';':
	case '=':
	    break;
	case '#':
	    if (key.rfind(T("include"), 1) == 1) {
		string file;
		struct stat sbuf;

		key.remove_prefix(9);
		trim(key);
		file.assign(key);
		if (stat(file.c_str(), &sbuf)) {
		    return false;
		} else {
		    tifstream iis;

		    reserve((ulong)sbuf.st_size);
		    if (sbuf.st_size > BUFSZ)
			iis.rdbuf()->pubsetbuf(NULL, BUFSZ);
		    iis.open(file.c_str());
		    if (!parse(iis))
			return false;
		}
	    }
	    break;
	case '[':
	    key.remove_prefix(1);
	    key.remove_suffix(1);
	    trim(key);
	    if (key == T("common") || key == T("global"))
		sect.erase();
	    else
		sect.assign(key);
	    ini = true;
	    break;
	default:
	    app = false;
	    pos = key.find('=');
	    if (UNLIKELY(pos == key.npos)) {
		val = tstring_view();
	    } else {
		const tchar *kstart, *kend, *vstart, *vend;

		if (UNLIKELY(pos > 0 && key[pos - 1] == '+')) {
		    app = true;
		    --pos;
		}
		kstart = key.data();
		kend = kstart + pos;
		while (kend > kstart && istspace(kend[-1]))
		    --kend;
		vstart = key.data() + (app ? pos + 2 : pos + 1);
		vend = key.data() + key.size();
		while (vstart < vend && istspace(*vstart))
		    ++vstart;
		while (vend > vstart && istspace(vend[-1]))
		    --vend;
		key = tstring_view(kstart, (size_t)(kend - kstart));
		val = tstring_view(vstart, (size_t)(vend - vstart));
	    }
	    if (UNLIKELY(key.size() > 1 && key[0] == '*' && key[1] == '.')) {
		key.remove_prefix(2);
	    } else if (!pre.empty()) {
		if (key.size() > pre.size() + 1 && key[pre.size()] == '.' &&
		    key.compare(0, pre.size(), pre) == 0)
		    key.remove_prefix(pre.size() + 1);
		else if (key.find('.') != key.npos)
		    continue;
	    }
	    set(key.data(), key.size(), val.data(), val.size(), sect.data(),
		sect.size(), app);
	    break;
	}
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

    if (UNLIKELY(slen)) {
	tstring s;

	s.reserve(slen + 1 + klen);
	s.append(sect, slen).append(1, (tchar)'.').append(key, klen);
	kv = newkv(s.c_str(), s.size(), val, vlen);
    } else {
	kv = newkv(key, klen, val, vlen);
    }

    pair<kvmap::const_iterator, bool> old(amap.emplace(kv->key, kv));

    if (LIKELY(old.second))
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
    va_end(vl);
    unlock();
    return *this;
}

void Config::trim(tstring_view &s) {
    const tchar *start, *end;

    if (UNLIKELY(s.empty()))
	return;
    start = s.data();
    end = start + s.size();
    while (end > start && istspace(end[-1]))
	--end;
    while (start < end && istspace(*start))
	++start;
    s = tstring_view(start, (size_t)(end - start));
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
    struct stat sbuf;

    if (file)
	path = file;
    if (stat(path.c_str(), &sbuf)) {
	return false;
    } else {
	tifstream is;

	reserve((ulong)sbuf.st_size);
	if (sbuf.st_size > BUFSZ)
	    is.rdbuf()->pubsetbuf(NULL, BUFSZ);
	is.open(path.c_str());
	return read(is, _pre, app);
    }
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
