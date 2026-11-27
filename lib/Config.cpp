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
#include <fcntl.h>
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
    order = 0;
}

void Config::clear(void) {
    SpinWLocker lkr(lck);

    clear_locked();
}

void Config::erase(const strkey &key, const tchar *sect) {
    SpinWLocker lkr(lck);

    if (auto it = findkv(key, sect); it != amap.end()) {
	const KV *kv = it->second;

	amap.erase(it);
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
	    tstring name(sv);	// sv aliases val and isn't NUL terminated
	    const tchar *env = tgetenv(name.c_str());

	    if (env) {
		tstring::size_type len = tstrlen(env);

		val.replace(spos, epos - spos + 1, env, len);
		search = spos + len;
	    } else {
		search = epos + 1;
	    }
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
Config::kvmap::const_iterator Config::findkv(const strkey &key, const tchar
    *sect) const {
    tchar buf[KEYSZ];
    tstring str;

    return sect && *sect ? amap.find(joinkey(buf, str, sect, tstrlen(sect),
	key.data(), key.size())) : amap.find(key);
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
    kv->vlen = (uint)vlen;
    kv->order = kv->slen = 0;
    if (vlen)
	memcpy(kv->val, val, vlen * sizeof (tchar));
    kv->val[vlen] = '\0';
    if (klen)
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

bool Config::parse(tistream &is, tstring_view dir, bool unscoped, uint depth) {
    tstring_view key, val;
    tstring line, sect;
    auto rtrim = [](const tstring &str) {
	size_t len = str.size();

	while (len > 0 && istspace(str[len - 1]))
	    --len;
	return len;
    };

    if (!is)
	return false;
#ifdef _UNICODE
    if (is.peek() == L'\xFEFF')
	is.get();
#endif
    line.reserve(240);
    while (getline(is, line)) {
	size_t len = rtrim(line);

	if (len == 0)
	    continue;
	if (UNLIKELY(line[len - 1] == '\\')) {
	    line.resize(len);
	    tstring s;

	    do {
		line.pop_back();
		line.resize(rtrim(line));
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
	    if (UNLIKELY((len = rtrim(line)) == 0))
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
		if (!key.starts_with('/') && !key.starts_with('\\') &&
		    !(key.size() > 1 && key[1] == ':'))
		    file = dir;
		file += key;
		if (depth >= MAXINCLUDE || !open_file(file, iis, fbuf, sz) ||
		    !parse(iis, dirname(file), unscoped, depth + 1))
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
	    bool app = false;

	    if (UNLIKELY(pos == key.npos)) {
		val = {};
	    } else {
		val = key.substr(pos + 1);
		app = pos > 0 && key[pos - 1] == '+';
		key = key.substr(0, app ? pos - 1 : pos);
		trim(key);
		trim(val);
	    }
	    if (!unscoped) {
		if (key.starts_with(T("*."))) {
		    key.remove_prefix(2);
		} else if (!pre.empty()) {
		    if (key.size() > pre.size() + 1 && key[pre.size()] == '.' &&
			key.starts_with(pre))
			key.remove_prefix(pre.size() + 1);
		    else if (key.contains('.'))
			continue;
		}
	    }
	    set(key.data(), key.size(), val.data(), val.size(), sect.data(),
		sect.size(), app);
	    break;
	}
    }
    return is.eof() && !is.bad();
}

bool Config::load(tistream &is, const tchar *str, bool app, ulong sz,
    tstring_view dir) {
    return load(is, str, app, sz, dir, false);
}

bool Config::load(tistream &is, const tchar *str, bool app, ulong sz,
    tstring_view dir, bool unscoped) {
    if (!is)
	return false;
    if (app) {
	SpinWLocker lkr(lck);

	if (str)
	    pre = str;
	if (sz)
	    reserve(sz);
	return parse(is, dir, unscoped);
    }
    // parse outside the lock so readers are not blocked by file I/O
    Config tmp(str ? str : prefix().c_str(), ck);

    if (unscoped)
	tmp.order = 1;
    if (sz)
	tmp.reserve(sz);
    if (!tmp.parse(is, dir, unscoped))
	return false;

    SpinWLocker lkr(lck);

    pre.swap(tmp.pre);
    ini = tmp.ini;
    order = tmp.order;
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
	sum = rapid_hash(vlen ? val : T(""), vlen * sizeof (tchar),
	    rapid_hash(fkey.empty() ? T("") : fkey.data(),
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
	else if (vlen)
	    s.append(val, vlen);
	if (oldkv->quote)
	    s += oldkv->quote;
	val = s.c_str();
	vlen = s.size();
    }

    KV *kv = newkv(fkey.data(), fkey.size(), val, vlen);
    auto [it, inserted] = amap.try_emplace(kv->key(), kv);

    if (order) {
	kv->order = order++;
	if (slen || !inserted)
	    kv->slen = slen ? (uint)slen : it->second->slen;
    }
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
    vector<const KV *> kvs;
    tstring sect;

    kvs.reserve(amap.size());
    for (const auto &[k, v] : amap)
	kvs.push_back(v);
    if (order)
	ranges::sort(kvs, {}, &KV::order);
    else if (inistyle)
	ranges::sort(kvs, keyless{}, &KV::key);
    else
	ranges::sort(kvs, strless{}, &KV::key);
    for (size_t u = 0; u < kvs.size(); ++u) {
	const tchar *dot;
	const tchar *key = kvs[u]->key();
	const KV *kv = kvs[u];

	if (inistyle && order)
	    dot = kv->slen ? key + kv->slen : nullptr;
	else
	    dot = tstrchr(key, '.');
	if (!dot) {
	    if (inistyle) {
		if (order && !sect.empty()) {
		    os << T("\n[global]\n");
		    sect.clear();
		    cnt = 0;
		} else if (!order) {
		    sect = '.';
		}
	    } else {
		sect.assign(key);
		if (cnt > 1 || (cnt == 1 && u + 1 < kvs.size() &&
		    tstring_view(kvs[u + 1]->key()).starts_with(sect) &&
		    kvs[u + 1]->key()[sect.size()] == '.'))
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
    return open_file(path, is, fbuf, sz) && load(is, _pre, app, sz,
	dirname(path));
}

bool ConfigFile::readunscoped(const tchar *file) {
    unique_ptr<tchar[]> fbuf;
    tifstream is;
    ulong sz;

    path = file;
    return open_file(path, is, fbuf, sz) && load(is, T(""), false, sz,
	dirname(path), true);
}

bool ConfigFile::write(const tchar *file, bool inistyle) const {
    if (file) {
	tofstream os(file);

#ifdef _UNICODE
	os.put(L'\xFEFF');
#endif
	const bool ok = write(os, inistyle);

	os.close();
	return ok && !os.fail();
    }
    if (path.empty()) {
	errno = ENOENT;
	return false;
    }

    tstring dir = path + T(".tmp.XXXXXX");
    struct stat orig;
    const bool exists = !tlstat(path.c_str(), &orig);
    bool ok;

    if (!exists && errno != ENOENT)
	return false;
    if (exists && !S_ISREG(orig.st_mode)) {
	errno = EINVAL;
	return false;
    }
    if (!tmkdtemp(dir.data()))
	return false;

    const tstring out = dir + T("/config");

    errno = 0;
    tofstream os(out.c_str());

#ifdef _UNICODE
    os.put(L'\xFEFF');
#endif
    ok = write(os, inistyle);
    os.close();
    ok = ok && !os.fail();
    if (!ok && !errno)
	errno = EIO;
#ifndef _WIN32
    if (ok) {
	const int fd = open(out.c_str(), O_RDONLY | O_CLOEXEC);
	struct stat created;

	ok = fd >= 0;
	if (ok) {
	    ok = (!exists || (!fstat(fd, &created) &&
		((orig.st_uid == created.st_uid && orig.st_gid == created.st_gid) ||
		!fchown(fd, orig.st_uid, orig.st_gid)))) &&
		!fchmod(fd, exists ? orig.st_mode & 0777 : 0600);
	    const int err = errno;

	    if (close(fd) && ok)
		ok = false;
	    else if (!ok)
		errno = err;
	}
    }
#endif
    if (ok)
	ok = !trename(out.c_str(), path.c_str());

    const int err = errno;

    if (!ok)
	(void)tunlink(out.c_str());
    (void)trmdir(dir.c_str());
    errno = err;
    return ok;
}
