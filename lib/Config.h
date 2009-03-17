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

#ifndef Config_h
#define Config_h

#include STL_HASH_MAP
#include "Thread.h"

class Config: nocopy {
public:
    Config(const tchar *file = NULL, const tchar *pre = NULL);
    Config(tistream &is): ini(false), locker(0) { is >> *this; }
    ~Config() { clear(); }

    void clear(void);
    const tstring get(const tchar *attr, const tchar *def = NULL,
	const tchar *sect = NULL) const;
    const tstring get(const tstring &attr, const tstring &def,
	const tstring &sect) const
	{ return get(attr.c_str(), def.c_str(), sect.c_str()); }
    const tstring get(const tstring &attr, const tstring &def) const
	{ return get(attr.c_str(), def.c_str()); }
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
    void set(const tchar *attr, const tchar *val, const tchar *sect = NULL);
    void set(const tchar *attr, const bool val, const tchar *sect = NULL)
	{ set(attr, val ? T("true") : T("false"), sect); }
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
    void lock(void) { lck.lock(); locker = THREAD_HDL(); }
    void unlock(void) { lck.unlock(); locker = 0; }
    bool iniformat(void) const { return ini; }
    const tstring &prefix(void) const { return pre; }
    void prefix(const tchar *str) { pre = str ? str : ""; }
    bool read(const tchar *file, bool app = false);
    bool read(tistream &is, bool app = false);
    bool write(tostream &os) const { return write(os, ini); }
    bool write(tostream &os, bool ini) const;
    bool write(const tchar *file = NULL) const { return write(file, ini); }
    bool write(const tchar *file, bool ini) const;
    friend tistream &operator >>(tistream &is, Config &cfg);
    friend tostream &operator <<(tostream &os, const Config &cfg);

private:
    typedef hash_map<const tstring, const tchar *, strhash<tchar> > attrmap;

    attrmap amap;
    mutable tstring buf, key;
    tstring file;
    bool ini;
    mutable Lock lck;
    thread_t locker;
    tstring pre;

    const tstring &keystr(const tchar *attr, const tchar *sect) const;
    const tchar *lookup(const tchar *attr, const tchar *sect) const;
    bool parse(tistream &is);
    void trim(tstring &str);
    const tchar *stringdup(const tchar *str, size_t sz) const {
	return (const tchar *)memcpy(new tchar[sz], str, sz * sizeof (tchar));
    }
    const tchar *stringdup(const tchar *s) const
	{ return stringdup(s, tstrlen(s) + 1); }
    const tchar *stringdup(const string &s) const
	{ return stringdup(s.c_str(), s.size() + 1); }
};

inline tistream &operator >>(tistream &is, Config &cfg) { cfg.read(is, true); return is; }
inline tostream &operator <<(tostream &os, const Config &cfg) { cfg.write(os); return os; }

#endif // Config_h
