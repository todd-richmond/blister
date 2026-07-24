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

#ifndef Config_h
#define Config_h

#include <charconv>
#include <unordered_map>
#include "Thread.h"

/*
 * The Config class is used to read either property (key = value) or
 * ini ([ section ]) style configuration files. Property files may have any
 * number of subsections delimited by '.'. Ini files are stored as property
 * strings by using the section as the key prefix. get() functions allow
 * fetches with default values and set() functions can modify existing values
 *
 * When reading configuration, a "prefix" value may be specified so multiple
 * programs can share a common config file. This works by pruning off the
 * prefix string so that shared libraries can use a common key substring.
 * "*" used as a key prefix enables all prefixes to share a single value
 *
 * key/value lines have a few extra features not found in many config readers
 *   1) value enclosed in "" or '' will keep leading and trailing spaces and
 *      '' will not be expanded.
 *   2) lines ending in \ will have their values continued on the next line
 *   3) ${key} or $(key) substrings will be recursively expanded during get()
 *   4) lines beginning with # are comments
 *   5) lines beginning with #include will recursively include the filename arg
 *   6) key += val appends the value
 *   7) repeated keys are stored as "last read key wins"
 *
 *   host = hostname
 *   prog1.key1 = value1
 *   prog2.key1 = " value2 "
 *   *.key2 = ${host}
 *
 *   config.read("common.cfg", "prog1");
 *   config.get("key1", "default");    // return app specific value of key1
 *   config.get("key2", "default");    // return app shared value of key2
 */

class BLISTER Config: nocopy {
public:
    explicit Config(const tchar *prestr = nullptr): ini(false) {
	prefix(prestr);
    }
    explicit Config(tistream &is, const tchar *prestr = nullptr): ini(false) {
	(void)read(is, prestr);
    }
    ~Config() { clear(); }

    friend tistream &operator >>(tistream &is, Config &cfg) {
	if (!cfg.read(is, nullptr, true))
	    is.setstate(ios::badbit);
	return is;
    }
    friend tostream &operator <<(tostream &os, const Config &cfg) {
	(void)cfg.write(os);
	return os;
    }

    bool iniformat(void) const { return ini; }
    const tstring &prefix(void) const { return pre; }

    Config &append(const tchar *key, const tchar *val, const tchar *sect =
	nullptr) {
	SpinWLocker lkr(lck);

	return set(key, tstrlen(key), val, tstrlen(val), sect, sect ?
	    tstrlen(sect) : 0, true);
    }
    void clear(void);
    void erase(const tchar *key, const tchar *sect = nullptr);
    bool exists(const tchar *key, const tchar *sect = nullptr) const {
	SpinRLocker lkr(lck);

	return getkv(key, sect) != nullptr;
    }
    tstring get(const tchar *key, const tchar *def = nullptr, const tchar
	*sect = nullptr) const;
    template<size_t N>
    tstring get(const tchar (&key)[N], const tchar *def = nullptr, const tchar
	*sect = nullptr) const {
	return get(tstring_view(key, N - 1), def, sect);
    }
    tstring get(const tstring &key) const { return get(key.c_str()); }
    tstring get(const tstring &key, const tstring &def) const {
	return get(key.c_str(), def.c_str());
    }
    tstring get(const tstring &key, const tstring &def, const tstring &sect)
	const {
	return get(key.c_str(), def.c_str(), sect.c_str());
    }
    bool get(const tchar *key, bool def, const tchar *sect = nullptr) const;
    template<size_t N>
    bool get(const tchar (&key)[N], bool def, const tchar *sect = nullptr) const
    {
	return get(tstring_view(key, N - 1), def, sect);
    }
    double get(const tchar *key, double def, const tchar *sect = nullptr) const
    {
	return get_num(key, def, sect,
	    [](const tchar *s, size_t) { return atod<double>(s); });
    }
    template<size_t N>
    double get(const tchar (&key)[N], double def, const tchar *sect = nullptr)
	const {
	return get_num(tstring_view(key, N - 1), def, sect,
	    [](const tchar *s, size_t) { return atod<double>(s); });
    }
    float get(const tchar *key, float def, const tchar *sect = nullptr) const {
	return (float)get(key, (double)def, sect);
    }
    template<size_t N>
    float get(const tchar (&key)[N], float def, const tchar *sect = nullptr)
	const {
	return (float)get_num(tstring_view(key, N - 1), (double)def, sect,
	    [](const tchar *s, size_t) { return atod<double>(s); });
    }
    int get(const tchar *key, int def, const tchar *sect = nullptr) const {
	return (int)get(key, (long)def, sect);
    }
    template<size_t N>
    int get(const tchar (&key)[N], int def, const tchar *sect = nullptr) const {
	return (int)get_num(tstring_view(key, N - 1), (long)def, sect,
	    atoin<long>);
    }
    long get(const tchar *key, long def, const tchar *sect = nullptr) const {
	return get_num(key, def, sect, atoin<long>);
    }
    template<size_t N>
    long get(const tchar (&key)[N], long def, const tchar *sect = nullptr) const {
	return get_num(tstring_view(key, N - 1), def, sect, atoin<long>);
    }
    llong get(const tchar *key, llong def, const tchar *sect = nullptr) const {
	return get_num(key, def, sect, atoin<llong>);
    }
    template<size_t N>
    llong get(const tchar (&key)[N], llong def, const tchar *sect = nullptr)
	const {
	return get_num(tstring_view(key, N - 1), def, sect, atoin<llong>);
    }
    short get(const tchar *key, short def, const tchar *sect = nullptr) const {
	return (short)get(key, (long)def, sect);
    }
    template<size_t N>
    short get(const tchar (&key)[N], short def, const tchar *sect = nullptr)
	const {
	return (short)get_num(tstring_view(key, N - 1), (long)def, sect,
	    atoin<long>);
    }
    tchar get(const tchar *key, tchar def, const tchar *sect = nullptr) const {
	tchar buf[2];

	buf[0] = def; buf[1] = '\0'; return get(key, buf, sect)[0];
    }
    template<size_t N>
    tchar get(const tchar (&key)[N], tchar def, const tchar *sect = nullptr)
	const {
	tchar buf[2];

	buf[0] = def; buf[1] = '\0';
	return get(tstring_view(key, N - 1), buf, sect)[0];
    }
    uint get(const tchar *key, uint def, const tchar *sect = nullptr) const {
	return (uint)get(key, (ulong)def, sect);
    }
    template<size_t N>
    uint get(const tchar (&key)[N], uint def, const tchar *sect = nullptr) const
	{
	return (uint)get_num(tstring_view(key, N - 1), (ulong)def, sect,
	    atoun<ulong>);
    }
    ulong get(const tchar *key, ulong def, const tchar *sect = nullptr) const {
	return get_num(key, def, sect, atoun<ulong>);
    }
    template<size_t N>
    ulong get(const tchar (&key)[N], ulong def, const tchar *sect = nullptr)
	const {
	return get_num(tstring_view(key, N - 1), def, sect, atoun<ulong>);
    }
    ullong get(const tchar *key, ullong def, const tchar *sect = nullptr) const
	{
	return get_num(key, def, sect, atoun<ullong>);
    }
    template<size_t N>
    ullong get(const tchar (&key)[N], ullong def, const tchar *sect = nullptr)
	const {
	return get_num(tstring_view(key, N - 1), def, sect, atoun<ullong>);
    }
    ushort get(const tchar *key, ushort def, const tchar *sect = nullptr) const
	{
	return (ushort)get(key, (ulong)def, sect);
    }
    template<size_t N>
    ushort get(const tchar (&key)[N], ushort def, const tchar *sect = nullptr)
	const {
	return (ushort)get_num(tstring_view(key, N - 1), (ulong)def, sect,
	    atoun<ulong>);
    }
    void prefix(const tchar *str) { pre = str ? str : T(""); }
    bool read(tistream &is, const tchar *pre = nullptr,
	bool append = false, ulong sz = 0);
    void reserve(ulong sz) { amap.reserve(amap.size() + sz / 64); }
    template<typename T>
    Config &set(const tchar *key, T val, const tchar *sect = nullptr) {
	tchar buf[64];
	auto [ptr, ec] = to_chars(buf, buf + std::size(buf), val);
	SpinWLocker lkr(lck);

	*ptr = '\0';
	return set(key, tstrlen(key), buf, (size_t)(ptr - buf), sect, sect ?
	    tstrlen(sect) : 0);
    }
    Config &set(const tchar *key, const tchar *val, const tchar *sect =
	nullptr) {
	SpinWLocker lkr(lck);

	return set(key, tstrlen(key), val, tstrlen(val), sect, sect ?
	    tstrlen(sect) : 0);
    }
    Config &set(const tchar *key, const bool val, const tchar *sect = nullptr) {
	return set(key, val ? T("t") : T("f"), sect);
    }
    Config &set(const tstring &key, const tstring &val, const tstring &sect) {
	SpinWLocker lkr(lck);

	return set(key.c_str(), key.size(), val.c_str(), val.size(),
	    sect.c_str(), sect.size());
    }
    Config &set(tstring_view key, tstring_view val, tstring_view sect = {}) {
	SpinWLocker lkr(lck);

	return set(key.data(), key.size(), val.data(), val.size(),
	    sect.data(), sect.size());
    }
    Config &setv(const tchar *key, const tchar *val, ... /* , const tchar
	*sect = nullptr, nullptr */);
    bool write(tostream &os) const { return write(os, ini); }
    bool write(tostream &os, bool ini) const;
    void lock(void) { lck.lock(); }
    void unlock(void) { lck.unlock(); }

protected:
    static ulong open_file(const tstring &file, tifstream &is,
	unique_ptr<tchar[]> &fbuf);

private:
    struct BLISTER KV {
	const tchar *key;
	uint klen, vlen;
	bool expand;
	tchar quote;
	tchar val[];
    };

    struct keyless {
	bool operator ()(const tchar *a, const tchar *b) const {
	    const tchar *ap = tstrchr(a, '.');
	    const tchar *bp = tstrchr(b, '.');

	    if (!ap)
		return bp ? true : stringless(a, b);
	    else if (!bp)
		return false;
	    return stringless(a, b);
	}
    };

    using kvmap = unordered_map<const tchar *, KV *, strhash<tchar>, streq>;

    kvmap amap;
    mutable SpinRWLock lck;
    tstring pre;
    bool ini;

    void clear_locked(void);
    bool expandkv(const KV *kv, tstring &val) const;
    const KV *getkv(const tchar *key, const tchar *sect) const;
    const KV *getkv(tstring_view key, const tchar *sect) const;
    tstring get(tstring_view key, const tchar *def, const tchar *sect) const;
    bool get(tstring_view key, bool def, const tchar *sect) const;
    template<typename K, typename T, typename F>
    T get_num(K key, T def, const tchar *sect, F conv) const {
	SpinRLocker lkr(lck);
	const KV *kv = getkv(key, sect);

	if (LIKELY(kv)) {
	    if (LIKELY(!kv->expand))
		return (T)conv(kv->val, kv->vlen);
	    tstring s;
	    if (expandkv(kv, s))
		return (T)conv(s.c_str(), s.size());
	}
	return def;
    }
    bool parse(tistream &is);
    Config &set(const tchar *key, size_t klen, const tchar *val, size_t vlen,
	const tchar *sect, size_t slen, bool append = false);
    static void delkv(KV *kv) { delete [] (char *)kv; }
    static KV *newkv(const tchar *key, size_t klen, const tchar *val, size_t
	vlen);
    static void trim(tstring_view &str);
};

class BLISTER ConfigFile: public Config {
public:
    using Config::Config;
    explicit ConfigFile(const tchar *file = nullptr, const tchar *_pre = nullptr);

    using Config::read;
    bool read(const tchar *file = nullptr, const tchar *_pre = nullptr, bool append =
	false);
    using Config::write;
    bool write(void) const { return write(nullptr, iniformat()); }
    bool write(const tchar *file, bool ini = false) const;

private:
    tstring path;
};

#endif // Config_h
