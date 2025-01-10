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

#ifndef Config_h
#define Config_h

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
    explicit Config(const tchar *prestr = NULL): locker(0), ini(false) {
	prefix(prestr);
    }
    explicit Config(tistream &is, const tchar *prestr = NULL): locker(0),
	ini(false) {
	read(is, prestr);
    }
    ~Config() { clear(); }

    bool iniformat(void) const { return ini; }
    const tstring &prefix(void) const { return pre; }

    Config &append(const tchar *key, const tchar *val, const tchar *sect =
	NULL) {
	WLocker lkr(lck, !THREAD_ISSELF(locker));

	return set(key, tstrlen(key), val, tstrlen(val), sect, sect ?
	    tstrlen(sect) : 0, true);
    }
    void clear(void);
    void erase(const tchar *key, const tchar *sect = NULL);
    bool exists(const tchar *key, const tchar *sect = NULL) const {
	RLocker lkr(lck, !THREAD_ISSELF(locker));

	return getkv(key, sect) != NULL;
    }
    const tstring get(const tchar *key, const tchar *def = NULL, const tchar
	*sect = NULL) const;
    const tstring get(const tstring &key) const { return get(key.c_str()); }
    const tstring get(const tstring &key, const tstring &def) const {
	return get(key.c_str(), def.c_str());
    }
    const tstring get(const tstring &key, const tstring &def, const tstring
	&sect) const {
	return get(key.c_str(), def.c_str(), sect.c_str());
    }
    bool get(const tchar *key, bool def, const tchar *sect = NULL) const;
    double get(const tchar *key, double def, const tchar *sect = NULL) const;
    float get(const tchar *key, float def, const tchar *sect = NULL) const {
	return (float)get(key, (double)def, sect);
    }
    int get(const tchar *key, int def, const tchar *sect = NULL) const {
	return (int)get(key, (long)def, sect);
    }
    long get(const tchar *key, long def, const tchar *sect = NULL) const;
    llong get(const tchar *key, llong def, const tchar *sect = NULL) const;
    short get(const tchar *key, short def, const tchar *sect = NULL) const {
	return (short)get(key, (long)def, sect);
    }
    tchar get(const tchar *key, tchar def, const tchar *sect = NULL) const {
	tchar buf[2];
	buf[0] = def; buf[1] = '\0'; return get(key, buf, sect)[0];
    }
    uint get(const tchar *key, uint def, const tchar *sect = NULL) const {
	return (uint)get(key, (ulong)def, sect);
    }
    ulong get(const tchar *key, ulong def, const tchar *sect = NULL) const;
    ullong get(const tchar *key, ullong def, const tchar *sect = NULL) const;
    ushort get(const tchar *key, ushort def, const tchar *sect = NULL) const {
	return (ushort)get(key, (ulong)def, sect);
    }
    void prefix(const tchar *str) { pre = str ? str : T(""); }
    bool read(tistream &is, const tchar *pre = NULL, bool append = false);
    void reserve(ulong sz) { amap.reserve(amap.size() + sz / 40); }
    Config &set(const tchar *key, const tchar *val, const tchar *sect = NULL) {
	WLocker lkr(lck, !THREAD_ISSELF(locker));

	return set(key, tstrlen(key), val, tstrlen(val), sect, sect ?
	    tstrlen(sect) : 0);
    }
    Config &set(const tstring &key, const tstring &val, const tstring &sect) {
	WLocker lkr(lck, !THREAD_ISSELF(locker));

	return set(key.c_str(), key.size(), val.c_str(), val.size(),
	    sect.c_str(), sect.size());
    }
    Config &set(const tchar *key, const bool val, const tchar *sect = NULL) {
	return set(key, val ? T("t") : T("f"), sect);
    }
    Config &set(const tchar *key, double val, const tchar *sect = NULL) {
	tchar buf[24]; tsprintf(buf, T("%g"), val); return set(key, buf, sect);
    }
    Config &set(const tchar *key, float val, const tchar *sect = NULL) {
	tchar buf[24];
	tsprintf(buf, T("%f"), (double)val);
	return set(key, buf, sect);
    }
    Config &set(const tchar *key, int val, const tchar *sect = NULL) {
	tchar buf[24]; tsprintf(buf, T("%d"), val); return set(key, buf, sect);
    }
    Config &set(const tchar *key, long val, const tchar *sect = NULL) {
	tchar buf[24]; tsprintf(buf, T("%ld"), val); return set(key, buf, sect);
    }
    Config &set(const tchar *key, llong val, const tchar *sect = NULL) {
	tchar buf[48];
	tsprintf(buf, T("%lld"), val);
	return set(key, buf, sect);
    }
    Config &set(const tchar *key, short val, const tchar *sect = NULL) {
	tchar buf[16]; tsprintf(buf, T("%hd"), val); return set(key, buf, sect);
    }
    Config &set(const tchar *key, tchar val, const tchar *sect = NULL) {
	tchar buf[2]; buf[0] = val; buf[1] = '\0'; return set(key, buf, sect);
    }
    Config &set(const tchar *key, uint val, const tchar *sect = NULL) {
	tchar buf[24]; tsprintf(buf, T("%u"), val); return set(key, buf, sect);
    }
    Config &set(const tchar *key, ulong val, const tchar *sect = NULL) {
	tchar buf[24]; tsprintf(buf, T("%lu"), val); return set(key, buf, sect);
    }
    Config &set(const tchar *key, ullong val, const tchar *sect = NULL) {
	tchar buf[48];
	// cppcheck-suppress invalidPrintfArgType_uint
	tsprintf(buf, T("%llu"), val);
	return set(key, buf, sect);
    }
    Config &set(const tchar *key, ushort val, const tchar *sect = NULL) {
	tchar buf[24]; tsprintf(buf, T("%hu"), val); return set(key, buf, sect);
    }
    Config &setv(const tchar *key, const tchar *val, ... /* , const tchar
	*sect = NULL, NULL */);
    bool write(tostream &os) const { return write(os, ini); }
    bool write(tostream &os, bool ini) const;
    void lock(void) { lck.wlock(); locker = THREAD_ID(); }
    void unlock(void) { locker = 0; lck.wunlock(); }
    friend tistream &operator >>(tistream &is, Config &cfg);
    friend tostream &operator <<(tostream &os, const Config &cfg);

private:
    struct BLISTER KV {
	const tchar *key;
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

    typedef unordered_map<const tchar *, const KV *, strhash<tchar>,
	streq<tchar> > kvmap;

    kvmap amap;
    mutable RWLock lck;
    thread_id_t locker;
    tstring pre;
    bool ini;

    bool expandkv(const KV *kv, tstring &val) const;
    const KV *getkv(const tchar *key, const tchar *sect) const;
    bool parse(tistream &is);
    Config &set(const tchar *key, size_t klen, const tchar *val, size_t vlen,
	const tchar *sect, size_t slen, bool append = false);
    static void delkv(const KV *kv) { delete [] (char *)kv; }
    static const KV *newkv(const tchar *key, size_t klen, const tchar *val,
	size_t vlen);
    static void trim(tstring_view &str);
};

inline tistream &operator >>(tistream &is, Config &cfg) {
    if (!cfg.read(is, NULL, true))
	is.setstate(ios::badbit);
    return is;
}

inline tostream &operator <<(tostream &os, const Config &cfg) {
    cfg.write(os);
    return os;
}

class BLISTER ConfigFile: public Config {
public:
    explicit ConfigFile(const tchar *file = NULL, const tchar *_pre = NULL);

    bool read(tistream &is, const tchar *_pre = NULL, bool append = false) {
	return Config::read(is, _pre, append);
    }
    bool read(const tchar *file = NULL, const tchar *_pre = NULL, bool append =
	false);
    // cppcheck-suppress duplInheritedMember
    bool write(tostream &os, bool inifmt) const {
	return Config::write(os, inifmt);
    }
    bool write(void) const { return write(NULL, iniformat()); }
    bool write(const tchar *file, bool ini = false) const;

private:
    tstring path;
};

#endif // Config_h
