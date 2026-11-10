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
#include <algorithm>
#include <fstream>
#include <memory>
#include <vector>
#include <sys/stat.h>
#include "Config.h"

constexpr uint MINBUFSZ = 4 * 1024U;
constexpr uint MAXEXPAND = 64;
constexpr uint MAXINCLUDE = 16;

tstring_view Config::joinkey(tchar (&buf)[KEYSZ], tstring &str, const tchar
    *sect, size_t slen, const tchar *key, size_t klen) {
    size_t total = slen + 1 + klen;

    if (LIKELY(total + 1 < KEYSZ)) {
	tchar *p = buf;

	memcpy(p, sect, slen * sizeof (tchar));
	p += slen;
	*p++ = (tchar)'.';
	memcpy(p, key, klen * sizeof (tchar));
	return {buf, total};
    }
    str.reserve(total);
    str.append(sect, slen).append(1, (tchar)'.').append(key, klen);
    return str;
}

void Config::clear_locked(void) {
    for (const auto &[key, kv] : amap)
	delkv(kv);
    amap.clear();
    sum = 0;
    ini = false;
}

void Config::clear(void) {
    SpinWLocker lkr(lck);

    clear_locked();
}

void Config::erase(const strkey &key, const tchar *sect) {
    SpinWLocker lkr(lck);

    if (const KV *kv = getkv(key, sect)) {
	amap.erase(kv->key());
	delkv(kv);
    }
}

void Config::expandkv(const KV *kv, tstring &val) const {
    tstring::size_type epos, spos, search = 0;
    uint expansions = 0;

    val.assign(kv->val, kv->vlen);
    while ((spos = val.find('$', search)) != val.npos) {
	tchar open;

	if (spos + 1 >= val.size())
	    break;
	open = val[spos + 1];
	if (open != '(' && open != '{') {
	    search = spos + 1;
	    continue;
	}
	if ((epos = val.find(open == '(' ? ')' : '}', spos + 2)) == val.npos)
	    break;

	uint off = (spos + 3 < val.size() && val[spos + 2] == '*' &&
	    val[spos + 3] == '.') ? 2 : 0;
	tstring_view sv(val.data() + spos + 2 + off, epos - spos - 2 - off);

	if (!pre.empty() && sv.starts_with(pre) && sv.size() > pre.size() + 1 &&
	    sv[pre.size()] == '.')
	    sv.remove_prefix(pre.size() + 1);
	auto it = amap.find(sv);
	if (it == amap.end()) {
	    search = epos + 1;
	    continue;
	}
	// stop runaway expansion of self referencing values
	if (++expansions > MAXEXPAND)
	    break;
	const KV *ekv = it->second;

	val.replace(spos, epos - spos + 1, ekv->val, ekv->vlen);
	// rescan only values that themselves expand so '' stays literal
	search = ekv->expand ? spos : spos + ekv->vlen;
    }
}

tstring Config::getstr(const strkey &key, const tchar *def, const tchar *sect)
    const {
    SpinRLocker lkr(lck);
    const KV *kv = getkv(key, sect);

    if (LIKELY(kv)) {
	if (LIKELY(!kv->expand))
	    return {kv->val, kv->vlen};
	tstring s;
	expandkv(kv, s);
	return s;
    }
    return def ? tstring(def) : tstring();
}

// a literal key hash is only usable without a section
const Config::KV *Config::getkv(const strkey &key, const tchar *sect) const {
    tchar buf[KEYSZ];
    tstring str;
    auto it = sect && *sect ? amap.find(joinkey(buf, str, sect, tstrlen(sect),
	key.data(), key.size())) : amap.find(key);

    return it == amap.end() ? nullptr : it->second;
}

// 1 allocation for key, val, state
WARN_PUSH_DISABLE(26402)
Config::KV *Config::newkv(const tchar *key, size_t klen, const tchar *val,
    size_t vlen) {
    KV *kv;
    tchar quote = '\0';

    if ((UNLIKELY(vlen > 1 && (val[0] == '"' || val[0] == '\''))) && val[vlen -
	1] == val[0]) {
	quote = val[0];
	++val;
	vlen -= 2;
    }
    kv = (KV *)new char[offsetof(KV, val) + (klen + vlen + 2) * sizeof (tchar)];
    kv->quote = quote;
    kv->klen = (uint)klen;
    kv->vlen = (uint)vlen;
    memcpy(kv->val, val, vlen * sizeof (tchar));
    kv->val[vlen] = '\0';
    memcpy(kv->val + vlen + 1, key, klen * sizeof (tchar));
    kv->val[vlen + 1 + klen] = '\0';
    kv->expand = false;
    if (LIKELY(vlen > 3 && quote != '\'')) {
	tstring_view v(kv->val, vlen);

	for (size_t pos = v.find('$'); pos != v.npos && pos + 1 < vlen;
	    pos = v.find('$', pos + 1)) {
	    tchar open = v[pos + 1];

	    if ((open == '{' || open == '(') &&
		v.substr(pos + 2).contains(open == '(' ? ')' : '}')) {
		kv->expand = true;
		break;
	    }
	}
    }
    return kv;
}
WARN_POP()

bool Config::open_file(const tstring &file, tifstream &is, unique_ptr<tchar[]>
    &fbuf, ulong &sz) {
    struct stat sbuf;
    size_t bufsz;

    if (stat(tstringtoachar(file), &sbuf))
	return false;
    sz = (ulong)sbuf.st_size;
    bufsz = max((size_t)sbuf.st_size + 1, (size_t)MINBUFSZ);
    fbuf = make_unique_for_overwrite<tchar[]>(bufsz);
    is.rdbuf()->pubsetbuf(fbuf.get(), (streamsize)bufsz);
    is.open(file.c_str());
    return (bool)is;
}

bool Config::parse(tistream &is, uint depth) {
    bool app;
    tstring_view key, val;
    tstring line, sect;

    if (!is)
	return false;
#ifdef _UNICODE
    if (is.peek() == L'\xFEFF')
	is.get();
#endif
    line.reserve(240);
    while (getline(is, line)) {
	size_t len = line.size();

	while (len > 0 && istspace(line[len - 1]))
	    --len;
	if (len == 0)
	    continue;
	if (UNLIKELY(line[len - 1] == '\\')) {
	    line.resize(len);
	    tstring s;

	    do {
		line.pop_back();
		len = line.size();
		while (len > 0 && istspace(line[len - 1]))
		    --len;
		line.resize(len);
		if (getline(is, s)) {
		    tstring_view sv(s);

		    trim(sv);
		    if (sv.empty())
			continue;
		    if (sv.front() == ';' || sv.front() == '#')
			line += '\\';
		    else	// keep indentation, drop trailing space
			line.append(s.data(), (size_t)(sv.data() + sv.size() -
			    s.data()));
		}
	    } while (!line.empty() && line.back() == '\\');
	    len = line.size();
	    while (UNLIKELY(len > 0 && istspace(line[len - 1])))
		--len;
	    if (UNLIKELY(len == 0))
		continue;
	}
	key = tstring_view(line.data(), len);
	trim(key);
	switch (key.front()) {
	case ';':
	case '=':
	    break;
	case '#':
	    if (key.size() > 8 && key.substr(1, 7) == T("include") &&
		istspace(key[8])) {
		tstring file;
		unique_ptr<tchar[]> fbuf;
		tifstream iis;
		ulong sz;

		key.remove_prefix(9);
		trim(key);
		file.assign(key);
		if (depth >= MAXINCLUDE || !open_file(file, iis, fbuf, sz) ||
		    !parse(iis, depth + 1))
		    return false;
	    }
	    break;
	case '[':
	    key.remove_prefix(1);
	    if (!key.empty() && key.back() == ']')
		key.remove_suffix(1);
	    trim(key);
	    if (key == T("common") || key == T("global"))
		sect.clear();
	    else
		sect.assign(key);
	    ini = true;
	    break;
	default:
	    auto pos = key.find('=');

	    app = false;
	    if (UNLIKELY(pos == key.npos)) {
		val = tstring_view(T(""));
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
		    key.starts_with(pre))
		    key.remove_prefix(pre.size() + 1);
		else if (key.contains('.'))
		    continue;
	    }
	    set(key.data(), key.size(), val.data(), val.size(), sect.data(),
		sect.size(), app);
	    break;
	}
    }
    return true;
}

bool Config::read(tistream &is, const tchar *str, bool app, ulong sz) {
    if (!is)
	return false;
    if (app) {
	SpinWLocker lkr(lck);

	if (str)
	    pre = str;
	if (sz)
	    reserve(sz);
	return parse(is);
    }
    // parse outside the lock so readers are not blocked by file I/O
    Config tmp(str ? str : prefix().c_str(), ck);

    if (sz)
	tmp.reserve(sz);
    if (!tmp.parse(is))
	return false;

    SpinWLocker lkr(lck);

    pre.swap(tmp.pre);
    ini = tmp.ini;
    amap.swap(tmp.amap);
    sum = tmp.sum;
    return true;
}

Config &Config::set(const tchar *key, size_t klen, const tchar *val, size_t
    vlen, const tchar *sect, size_t slen, bool append) {
    tchar kbuf[KEYSZ];
    tstring kstr, s;
    tstring_view fkey = UNLIKELY(slen) ? joinkey(kbuf, kstr, sect, slen, key,
	klen) : tstring_view(key, klen);

    if (UNLIKELY(ck))
	sum = rapid_hash(val, vlen * sizeof (tchar), rapid_hash(fkey.data(),
	    fkey.size() * sizeof (tchar), sum));
    if (auto it = append ? amap.find(fkey) : amap.end(); it != amap.end()) {
	const KV *oldkv = it->second;

	s.reserve(oldkv->vlen + vlen + (oldkv->quote ? 2 : 0));
	if (oldkv->quote)
	    s += oldkv->quote;
	s.append(oldkv->val, oldkv->vlen);
	if (vlen > 1 && (val[0] == '"' || val[0] == '\'') && val[vlen - 1] ==
	    val[0])
	    s.append(val + 1, vlen - 2);
	else
	    s.append(val, vlen);
	if (oldkv->quote)
	    s += oldkv->quote;
	val = s.c_str();
	vlen = s.size();
    }

    KV *kv = newkv(fkey.data(), fkey.size(), val, vlen);
    auto [it, inserted] = amap.try_emplace(kv->key(), kv);

    if (!inserted) {
	// reuse the map node rather than erase + emplace
	const KV *oldkv = it->second;
	auto nh = amap.extract(it);

	nh.key() = kv->key();
	nh.mapped() = kv;
	amap.insert(std::move(nh));
	delkv(oldkv);
    }
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
    SpinRLocker lkr(lck);
    vector<pair<const tchar *, const KV *>> keys;
    tstring sect;

    keys.reserve(amap.size());
    for (const auto &[k, v] : amap)
	keys.emplace_back(k, v);
    if (inistyle)
	ranges::sort(keys, keyless{}, &pair<const tchar *, const KV *>::first);
    else
	ranges::sort(keys, strless{},
	    &pair<const tchar *, const KV *>::first);
    for (size_t u = 0; u < keys.size(); ++u) {
	const tchar *dot;
	const tchar *key = keys[u].first;
	const KV *kv = keys[u].second;

	if ((dot = tstrchr(key, '.')) == nullptr) {
	    if (inistyle) {
		sect = '.';
	    } else {
		sect.assign(key);
		if (cnt > 1 || (cnt == 1 && u + 1 < keys.size() &&
		    tstring_view(keys[u + 1].first).starts_with(sect) &&
		    keys[u + 1].first[sect.size()] == '.'))
		    os << '\n';
		cnt = 0;
	    }
	} else {
	    if (tstring_view(key, (size_t)(dot - key)) != sect) {
		sect.assign(key, (size_t)(dot - key));
		if (cnt) {
		    os << '\n';
		    cnt = 0;
		}
		if (inistyle)
		    os << '[' << sect << ']' << '\n';
	    }
	    if (inistyle)
		key = dot + 1;
	}
	++cnt;
	os << key << '=';
	if (kv->quote)
	    os << kv->quote << kv->val << kv->quote;
	else if (kv->vlen && (istspace(kv->val[0]) ||
	    istspace(kv->val[kv->vlen - 1])))
	    os << '"' << kv->val << '"';
	else
	    os << kv->val;
	os << '\n';
    }
    os.flush();
    return os.good();
}

ConfigFile::ConfigFile(const tchar *file, const tchar *_pre, bool cksum):
    Config(_pre, cksum) {
    if (file)
	read(file, _pre);
}

bool ConfigFile::read(const tchar *file, const tchar *_pre, bool app) {
    unique_ptr<tchar[]> fbuf;
    tifstream is;
    ulong sz;

    if (file)
	path = file;
    return open_file(path, is, fbuf, sz) && read(is, _pre, app, sz);
}

bool ConfigFile::write(const tchar *file, bool inistyle) const {
    const tstring out(file ? tstring(file) : path + T(".tmp"));
    tofstream os(tstringtoachar(out));
    bool ok;

#ifdef _UNICODE
    os.put(L'\xFEFF');
#endif
    if (file)
	return write(os, inistyle);
    ok = write(os, inistyle);
    os.close();
    if (!ok || rename(tstringtoachar(out), tstringtoachar(path))) {
	unlink(tstringtoachar(out));
	return false;
    }
    return true;
}
