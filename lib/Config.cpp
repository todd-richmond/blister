#include "stdapi.h"
#include <fstream>
#include "Config.h"

const char *Config::lookup(const tchar *attr, const tchar *sect) const {
    attrmap::const_iterator it;
    const char *p, *pp, *ppp;
    uint sz;

    attr = key(attr, sect);
    it = amap.find(attr);
    if (it == amap.end())
	return NULL;
    p = (*it).second;
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
	it = amap.find(s.c_str());
	if (it == amap.end())
	    return p;
	s.assign(pp, ppp - pp + 1);
	if (s == (*it).second) {
	    s.assign(p, pp - p);
	    s.append(ppp + 1);
	} else {
	    s.assign(p, pp - p);
	    s.append((*it).second);
	    s.append(ppp + 1);
	}
	buf = s;
	p = buf.c_str();
    }
    return p;
}

void Config::clear(void) {
    Locker lkr(lck, !THREAD_ISSELF(locker));

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

    return p ? p[0] == '1' || totlower(p[0]) == 't' ||
	totlower(p[0]) == 'y' || !tstricmp(p, T("on")) : def;
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

const tchar *Config::key(const tchar *attr, const tchar *sect) const {
    if (!sect || !*sect)
	return attr;
    buf = sect;
    buf += '.';
    buf += attr;
    return buf.c_str();
}

void Config::set(const tchar *attr, const tchar *val, const tchar *sect) {
    attrmap::const_iterator it;
    Locker lkr(lck, !THREAD_ISSELF(locker));

    attr = key(attr, sect);
    it = amap.find(attr);
    if (it != amap.end())
	delete [] (*it).second;
    amap[stringdup(attr)] = stringdup(val);
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
	    continue;
	}
	p = key(attr.c_str(), sect.c_str());
	it = amap.find(p);
	if (it == amap.end()) {
cout <<"tfr 1 "<<p<<" "<<val<<endl;
	    amap[stringdup(p)] = stringdup(val);
	} else {
	    p = (*it).first;
	    if (plus) {
		buf = (*it).second;
		buf += val;
		amap[p] = stringdup(buf);
	    } else {
		delete [] (*it).second;
		amap[p] = stringdup(val);
	    }
cout <<"tfr 2 "<<p<<" "<<val<<endl;
	}
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

bool Config::write(tostream &os, bool app) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    attrmap::const_iterator it;
    string sect;

    if (app)
	os.seekp(0, ios::end);
/*
    for (it = maps.begin(); it != maps.end(); it++) {
	if (*(*it).first)
	    os << T("[") << (*it).first << T("]") << endl;
	for (ait = am->begin(); ait != am->end(); ait++) {
	    os << (*ait).first;
	    if (*(*ait).second) {
		os << T("=");
		if ((*ait).second[0] == ' ' || (*ait).second[0] == '\t' ||
		    (*ait).second[0] == '\'' || (*ait).second[0] == '"') {
		    os << '"' << (*ait).second << '"';
		} else {
		    os << (*ait).second;
		}
	    }
	    os << endl;
	}
	os << endl;
    }
*/
    return os.good();
}

bool Config::write(const tchar *f, bool app) const {
    if (!f)
	f = file.c_str();

    tofstream os(tchartoa(f).c_str(), ios::binary);

    return write(os, app);
}

