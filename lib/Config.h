/*
 * Copyright 2001-2014 Todd Richmond
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

#include STL_UNORDERED_MAP_H
#include "Thread.h"

/*
 * The Config class is used to read either property (attr = value) or
 * ini ([ section ]) style configuration files. Property files may have any
 * number of subsections delimited by '.'. Ini files are stored as property
 * strings by using the section as the attr prefix. get() functions allow
 * fetches with default values and set() functions can modify existing values
 * 
 * When reading configuration, a "prefix" value may be specified so multiple
 * programs can share a common config file. This works by pruning off the
 * prefix string so that shared libraries can use a common attribute substring
 * "*" may be used as an attribute prefix to enable all prefixes to share a
 * single value
 *
 * attr/value lines have a few extra features not found in many config readers
 *   1) value enclosed in "" or '' will keep leading and trailing spaces and
 *      not be expanded.
 *   2) lines ending in \ will have their values continued on the next line
 *   3) ${attr} or $(attr) substrings will be recursively expanded during get()
 *   4) lines beginning with # are comments
 *   5) lines beginning with #include will recursively include the filename arg
 *   6) attr += val appends the value
 *   7) repeated attributes are stored as "last read attr wins"
 *
 *   host = hostname
 *   prog1.attr1 = value1
 *   prog2.attr1 = " value2 "
 *   *.attr2 = ${host}
 * 
 *   config.read("prog.cfg", "prog1");
 *   config.get("attr1", "default"); // return app specific version of "attr1"
 *   config.get("attr2", "default"); // return app shared value of "attr2"
 */

class Config: nocopy {
public:
    Config(const tchar *file = NULL, const tchar *pre = NULL);
    explicit Config(tistream &is): ini(false), locker(0) { is >> *this; }
    ~Config() { clear(); }

    void clear(void);
    void erase(const tchar *attr, const tchar *sect = NULL);
    bool exists(const tchar *attr, const tchar *sect = NULL) {
	Locker lkr(lck, !THREAD_ISSELF(locker));

	return lookup(attr, sect) != NULL;
    }
    const tstring get(const tchar *attr, const tchar *def = NULL, const tchar
	*sect = NULL) const;
    const tstring get(const tstring &attr, const tstring &def, const tstring
	&sect) const {
	return get(attr.c_str(), def.c_str(), sect.c_str());
    }
    const tstring get(const tstring &attr, const tstring &def) const {
	return get(attr.c_str(), def.c_str());
    }
    const tstring get(const tstring &attr) const { return get(attr.c_str()); }
    bool get(const tchar *attr, bool def, const tchar *sect = NULL) const;
    double get(const tchar *attr, double def, const tchar *sect = NULL) const;
    float get(const tchar *attr, float def, const tchar *sect = NULL) const {
	return (float)get(attr, (double)def, sect);
    }
    int get(const tchar *attr, int def, const tchar *sect = NULL) const {
	return (int)get(attr, (long)def, sect);
    }
    long get(const tchar *attr, long def, const tchar *sect = NULL) const;
    uint get(const tchar *attr, uint def, const tchar *sect = NULL) const {
	return (uint)get(attr, (ulong)def, sect);
    }
    ulong get(const tchar *attr, ulong def, const tchar *sect = NULL) const;
    void set(const tchar *attr, const tchar *val, const tchar *sect = NULL) {
	Locker lkr(lck, !THREAD_ISSELF(locker));

	set(attr, val, sect, false);
    }
    void set(const tchar *attr, const bool val, const tchar *sect = NULL)
	{ set(attr, val ? T("t") : T("f"), sect); }
    void set(const tchar *attr, int val, const tchar *sect = NULL)
	{ tchar buf[24]; tsprintf(buf, T("%d"), val); set(attr, buf, sect); }
    void set(const tchar *attr, uint val, const tchar *sect = NULL)
	{ tchar buf[24]; tsprintf(buf, T("%u"), val); set(attr, buf, sect); }
    void set(const tchar *attr, long val, const tchar *sect = NULL)
	{ tchar buf[24]; tsprintf(buf, T("%ld"), val); set(attr, buf, sect); }
    void set(const tchar *attr, ulong val, const tchar *sect = NULL)
	{ tchar buf[24]; tsprintf(buf, T("%lu"), val); set(attr, buf, sect); }
    void set(const tchar *attr, float val, const tchar *sect = NULL)
	{ tchar buf[24]; tsprintf(buf, T("%f"), val); set(attr, buf, sect); }
    void set(const tchar *attr, double val, const tchar *sect = NULL)
	{ tchar buf[24]; tsprintf(buf, T("%g"), val); set(attr, buf, sect); }
    void setv(const tchar *attr, const tchar *val, ... /* , const tchar
	*sect = NULL, NULL */);
    void lock(void) { lck.lock(); locker = THREAD_ID(); }
    void unlock(void) { locker = 0; lck.unlock(); }
    bool iniformat(void) const { return ini; }
    const tstring &prefix(void) const { return pre; }
    void prefix(const tchar *str) { pre = str ? str : T(""); }
    bool read(const tchar *file, const tchar *pre = NULL, bool append = false);
    bool read(tistream &is, const tchar *pre = NULL, bool append = false);
    bool write(tostream &os) const { return write(os, ini); }
    bool write(tostream &os, bool ini) const;
    bool write(const tchar *file = NULL) const { return write(file, ini); }
    bool write(const tchar *file, bool ini) const;
    friend tistream &operator >>(tistream &is, Config &cfg);
    friend tostream &operator <<(tostream &os, const Config &cfg);

private:
    class Value {
    public:
	Value(const tchar *val, size_t len);

	bool expand;
	tchar quote;
	tstring value;
    };

    typedef unordered_map<const tchar *, Value *, strhash<tchar>, streq<tchar> >
	attrmap;

    attrmap amap;
    mutable tstring _buf, _key;
    bool ini;
    mutable Lock lck;
    thread_id_t locker;
    tstring path;
    tstring pre;

    const tstring &expand(const Value *val) const;
    const tchar *keystr(const tchar *attr, const tchar *sect) const {
	if (!sect || !*sect)
	    return attr;
	_key = sect;
	_key += '.';
	_key += attr;
	return _key.c_str();
    }
    const Value *lookup(const tchar *attr, const tchar *sect) const {
	attrmap::const_iterator it = amap.find(keystr(attr, sect));

	return it == amap.end() ? NULL : it->second;
    }
    bool parse(tistream &is);
    void set(const tchar *attr, const tchar *val, const tchar *sect, bool
	append);
    void trim(tstring &str);
};

inline tistream &operator >>(tistream &is, Config &cfg) {
    cfg.read(is, NULL, true);
    return is;
}

inline tostream &operator <<(tostream &os, const Config &cfg) {
    cfg.write(os);
    return os;
}

#endif // Config_h
