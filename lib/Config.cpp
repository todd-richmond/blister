#include "stdapi.h"
#include <fstream>
#include "Config.h"

Config::Config(const tchar *file, const tchar *pre): ini(false), locker(0) {
    prefix(pre);
    if (file)
	read(file);
}

const char *Config::lookup(const tchar *attr, const tchar *sect) const {
    attrmap::const_iterator it;
    const char *p, *pp, *ppp;
    uint sz;

    it = amap.find(keystr(attr, sect));
    if (it == amap.end())
	return NULL;
    p = it->second;
    if (p[0] && (p[0] == '"' || p[0] == '\'') &&
	p[sz = strlen(p)] == p[0] && sz > 1) {
	buf.assign(p + 1, sz - 2);
	return buf.c_str();
    }
    while ((pp = strchr(p, '$')) != NULL && (pp[1] == '(' || pp[1] == '{')) {
	if ((ppp = strchr(pp, pp[1] == '(' ? ')' : '}')) == NULL)
	    return p;

	tstring s(pp + 2, ppp - pp - 2);

	if (!pre.empty() && s.compare(0, pre.size(), pre) == 0 &&
	    s.size() > pre.size() + 1 && s[pre.size()] == '.')
	    s.erase(0, pre.size() + 1);
	it = amap.find(s);
	if (it == amap.end())
	    return p;
	s.assign(pp, ppp - pp + 1);
	if (s == it->second) {
	    s.assign(p, pp - p);
	    s.append(ppp + 1);
	} else {
	    s.assign(p, pp - p);
	    s.append(it->second);
	    s.append(ppp + 1);
	}
	buf = s;
	p = buf.c_str();
    }
    return p;
}

void Config::clear(void) {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    attrmap::iterator it;

    for (it = amap.begin(); it != amap.end(); it++)
	delete [] it->second;
    amap.clear();
}

const tstring Config::get(const tchar *attr, const tchar *def,
    const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const tchar *p = lookup(attr, sect);

    return p ? p : def ? def : "";
}

bool Config::get(const tchar *attr, bool def, const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const tchar *p = lookup(attr, sect);

    return p ? p[0] == L'1' || totlower(p[0]) == L't' ||
	totlower(p[0]) == L'y' || !tstricmp(p, T("on")) : def;
}

long Config::get(const tchar *attr, long def, const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const tchar *p = lookup(attr, sect);

    return p ? tstrtol(p, NULL, 10) : def;
}

ulong Config::get(const tchar *attr, ulong def, const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const tchar *p = lookup(attr, sect);

    return p ? tstrtoul(p, NULL, 10) : def;
}

double Config::get(const tchar *attr, double def, const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const tchar *p = lookup(attr, sect);

    return p ? tstrtod(p, NULL) : def;
}

const tstring &Config::keystr(const tchar *attr, const tchar *sect) const {
    if (sect && *sect) {
	key = sect;
	key += '.';
	key += attr;
    } else {
	key = attr;
    }
    return key;
}

void Config::set(const tchar *attr, const tchar *val, const tchar *sect) {
    attrmap::const_iterator it;
    Locker lkr(lck, !THREAD_ISSELF(locker));
    const tstring &key(keystr(attr, sect));

    it = amap.find(key);
    if (it != amap.end())
	delete [] it->second;
    amap[key] = stringdup(val);
}

void Config::trim(tstring &s) {
    int i, j = s.size();

    for (i = 0; i < j; i++)
	if (!istspace(s[i]))
	    break;
    if (i == j) {
	s.erase();
	return;
    }
    for (j--; j; j--)
	if (!istspace(s[j]))
	    break;
    if (i || j != (int)s.size() - 1)
	s = s.substr(i, j - i + 1);
}

bool Config::parse(tistream &is) {
    tstring s, attr, val, sect;
    attrmap::iterator it;
    const tchar *p;
    uint line = 0;
    bool head = true;

    if (!is)
	return false;
    while (getline(is, attr)) {
	line++;
	trim(attr);
	if (!tstrnicmp(attr.c_str(), T("#include"), 8)) {
	    attr = attr.substr(9, attr.size() - 9);
	    trim(attr);

	    tifstream is(tstringtoa(attr).c_str());

	    if (!parse(is))
		return false;
	    continue;
	}
	if (attr.empty() || attr[0] == ';' || attr[0] == '#' || attr[0] == '=')
	    continue;

	tstring::size_type pos;
	bool plus = false;
	int sz = attr.size();

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
		    attr = attr.substr(0, sz - 1) + s;
		    sz = attr.size();
		}
	    }
	}
	pos = attr[0] == '[' ? attr.npos : attr.find('=');
	if (pos == attr.npos) {
	    val.erase();
	} else {
	    if (attr[pos - 1] == '+')
		plus = true;
	    val = attr.substr(pos + 1, sz - pos);
	    trim(val);
	    attr.erase(pos - (plus ? 1 : 0), attr.size());
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
	    head = sect.empty();
	    ini = true;
	    continue;
	}

	const tstring &key(keystr(attr.c_str(), sect.c_str()));

	it = amap.find(key);
	if (it != amap.end()) {
	    if (plus) {
		buf = it->second;
		buf += val;
		val = buf;
	    }
	    delete [] it->second;
	}
	amap[key] = stringdup(val);
    }
    return true;
}

bool Config::read(tistream &is, bool app) {
    Locker lkr(lck, !THREAD_ISSELF(locker));

    if (!is)
	return false;
    if (!app)
	clear();
    return parse(is);
}

bool Config::read(const tchar *f, bool app) {
    if (f)
	file = f;

    tifstream is(tstringtoa(file).c_str());

    return read(is, app);
}

bool Config::write(tostream &os, bool ini) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    attrmap::const_iterator it;
    vector<tstring> lines;
    vector<tstring>::const_iterator lit;
    string s;
    string sect;

    for (it = amap.begin(); it != amap.end(); it++) {
	s = it->first;
	s += '=';
	s += it->second;
	lines.push_back(s);
    }
    sort(lines.begin(), lines.end());
    for (lit = lines.begin(); lit != lines.end(); lit++) {
	os << *lit << endl;
	(void)ini;
	//os << T("[") << it->first << T("]") << endl;
    }
    return os.good();
}

bool Config::write(const tchar *f, bool ini) const {
    if (!f)
	f = file.c_str();

    tofstream os(tchartoa(f).c_str(), ios::binary);

    return write(os, ini);
}

