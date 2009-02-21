#include "stdapi.h"
#include <fstream>
#include "Config.h"

void Config::clear() {
    for (sectmap::const_iterator it = maps.begin(); it != maps.end(); it++) {
	const attrmap *am = (*it).second;
	attrmap::const_iterator ait;

	for (ait = am->begin(); ait != am->end(); ait++) {
	    delete [] (*ait).first;
	    delete [] (*ait).second;
	}
	delete [] (*it).first;
	delete am;
    }
    maps.clear();
}

const char *Config::lookup(const tchar *attr, const tchar *sect) const {
    sectmap::const_iterator it;
    const char *p, *pp, *ppp;

    if (sect && !*sect)
	sect = NULL;
    if (!sect && (p = strchr(attr, '.')) != NULL) {
	buf.assign(attr, p - attr);
	sect = buf.c_str();
	attr = ++p;
    } else if (sect && (p = strchr(sect, '.')) != NULL) {
	buf.assign(sect, p - sect);
	buf2.assign(p + 1);
	buf2 += '.';
	buf2 += attr;
	sect = buf.c_str();
	attr = buf2.c_str();
    }
    it = maps.find(sect ? sect : T(""));
    if (it != maps.end()) {
	const attrmap *am = (*it).second;
	attrmap::const_iterator ait = am->find(attr);
	uint sz;

	if (ait != am->end()) {
	    p = (*ait).second;
	    if (p[0] && (p[0] == '"' || p[0] == '\'') &&
		p[sz = strlen(p)] == p[0] && sz > 1) {
		buf.append(p + 1, sz - 2);
		return buf.c_str();
	    } else while ((pp = strchr(p, '$')) != NULL &&
		(pp[1] == '(' || pp[1] == '{')) {
		if ((ppp = strchr(pp, pp[1] == '(' ? ')' : '}')) == NULL)
		    return p;

		tstring s(pp + 2, ppp - pp - 2);

		if (!pre.empty() && s.compare(0, pre.size(), pre) == 0 &&
		    s.size() > pre.size() + 1 && s[pre.size()] == '.')
		    s.erase(0, pre.size() + 1);
		ait = am->find(s.c_str());
		if (ait == am->end()) {
		    tstring::size_type pos;
		    tstring sect2;
		    sectmap::const_iterator it2;

		    if ((pos = s.find('.')) != s.npos) {
			sect2.assign(s.c_str(), 0, pos);
			s.erase(0, pos + 1);
		    }
		    it2 = maps.find(sect2.c_str());
		    if (it2 != maps.end()) {
			const attrmap *am2 = (*it2).second;

			if ((ait = am2->find(s.c_str())) == am2->end())
			    ait = am->end();
		    }
		}
		if (ait == am->end())
		    return p;
		s.assign(pp, ppp - pp + 1);
		if (s == (*ait).second) {
		    s.assign(p, pp - p);
		    s.append(ppp + 1);
		} else {
		    s.assign(p, pp - p);
		    s.append((*ait).second);
		    s.append(ppp + 1);
		}
		buf = s;
		p = buf.c_str();
	    }
	    return p;
	}
    }
    return NULL;
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

void Config::set(const tchar *attr, const tchar *val, const tchar *sect) {
    attrmap *am;
    attrmap::const_iterator ait;
    Locker lkr(lck, false);

    val = stringdup(val);
    if (!sect) {
	if ((sect = strchr(attr, '.')) == NULL) {
	    sect = T("");
	} else {
	    buf.assign(attr, sect - attr);
	    attr = sect + 1;
	    sect = buf.c_str();
	}
    }
    if (!THREAD_ISSELF(locker))
	lkr.lock();
    sectmap::const_iterator it = maps.find(sect);
    if (it == maps.end()) {
	if ((am = new attrmap) != NULL) {
	    maps[stringdup(sect)] = am;
	    (*am)[stringdup(attr)] = val;
	}
    } else {
	am = (*it).second;
	ait = am->find(attr);
	if (ait == am->end()) {
	    attr = stringdup(attr);
	} else {
	    attr = (*ait).first;
	    delete [] (*ait).second;
	}
	(*am)[attr] = val;
    }
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

#include "Log.h"
bool Config::parse(tistream &is) {
    tstring s, attr, val, sect;
    sectmap::const_iterator it = maps.find(T(""));
    attrmap::iterator ait;
    attrmap *am = NULL;
    const tchar *p, *pp;
    uint line = 0;
    bool head = true;

    if (!is)
	return false;
    if (it != maps.end())
	am = (*it).second;
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

	int sz = attr.size();
	tstring::size_type pos;
	bool plus = false;

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
	    attr = attr.substr(0, pos - (plus ? 1 : 0));
	    trim(attr);
	}
	if (attr.size() > 2 && attr[0] == '*' && attr[1] == '.') {
	    attr.erase(0, 2);
	} else if (!pre.empty()) {
	    if (attr.compare(0, pre.size(), pre) == 0 &&
		attr.size() > pre.size() + 1 &&
	        attr[pre.size()] == '.')
		attr.erase(0, pre.size() + 1);
	    else if (attr.find('.') != attr.npos)
		continue;
	}
	if (attr[0] == '[') {
	    sect = attr.substr(1, attr.size() - 2);
	    trim(sect);
	    head = sect.empty();
	    pos = sect.find('=');
	    if (pos != sect.npos) {
		val = sect.substr(pos + 1, sect.size() - pos);
		trim(val);
		sect = sect.substr(0, pos);
		trim(sect);
	    }
	    p = sect.c_str();
	    if (!tstricmp(p, T("global")) || !tstricmp(p, T("common")))
		sect.erase();
	    if ((it = maps.find(sect.c_str())) == maps.end()) {
		if ((am = new attrmap) == NULL)
		    break;
		p = stringdup(sect);
		maps.insert(pair<const tchar *, attrmap *> (p, am));
	    } else {
		am = (*it).second;
	    }
	    if (pos != sect.npos) {
		it = maps.find(val.c_str());
		if (it != maps.end()) {
		    attrmap::const_iterator cait;
		    attrmap *tmpam = (*it).second;

		    for (cait = tmpam->begin(); cait != tmpam->end(); cait++) {
			p = stringdup((*cait).first);
			pp = stringdup((*cait).second);
			am->insert(pair<const tchar *, const tchar *> (p, pp));
		    }
		}
	    }
	    continue;
	} else if (head) {
	    if ((pos = attr.find('.')) == attr.npos) {
		sect.erase();
	    } else {
		sect.assign(attr, 0, pos);
		attr.erase(0, pos + 1);
	    }
	    if ((it = maps.find(sect.c_str())) == maps.end())
		am = NULL;
	    else
		am = (*it).second;
	}
	if (!am) {
	    if ((am = new attrmap) == NULL)
		break;
	    p = stringdup(sect);
	    maps.insert(pair<const tchar *, attrmap *> (p, am));
	}
	ait = am->find(attr.c_str());
	if (ait == am->end()) {
	    p = stringdup(attr);
	    pp = stringdup(val);
	} else {
	    p = (*ait).first;
	    if (plus) {
		tchar *buf;

		pos = tstrlen((*ait).second);
		buf = new tchar [pos + val.size() + 1];
		memcpy(buf, (*ait).second, pos);
		memcpy(buf + pos, val.c_str(), (val.size() + 1) * sizeof (tchar));
		pp = buf;
	    } else {
		delete [] (*ait).second;
		am->erase(ait);
		pp = stringdup(val);
	    }
	}
	am->insert(pair<const tchar *, const tchar *> (p, pp));
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
    sectmap::const_iterator it;

    if (app)
	os.seekp(0, ios::end);
    for (it = maps.begin(); it != maps.end(); it++) {
	attrmap::const_iterator ait;
	const attrmap *am = (*it).second;

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
    return os.good();
}

bool Config::write(const tchar *f, bool app) const {
    if (!f)
	f = file.c_str();

    tofstream os(tchartoa(f).c_str(), ios::binary);

    return write(os, app);
}

const tstring Config::senum(const tchar *sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    sectmap::const_iterator it = maps.find(sect ? sect : T(""));

    if (it != maps.end()) 
	return kenum(*(*it).second);
    return T("");
}

const tstring Config::senum(uint sect) const {
    Locker lkr(lck, !THREAD_ISSELF(locker));
    sectmap::const_iterator it;

    for (it = maps.begin(); it != maps.end(); it++) {	
	if (!sect--)
	    return kenum(*(*it).second);	    
    }
    return T("");
}

const tstring Config::kenum(const attrmap &am) const {
    attrmap::const_iterator ait;
    tstring s;

    for (ait = am.begin(); ait != am.end(); ait++) {
	s += (*ait).first;
	s += '=';
	if ((*ait).second[0] == ' ' || (*ait).second[0] == '\t' ||
	    (*ait).second[0] == '\'' || (*ait).second[0] == '"') {
	    s += '"';
	    s += (*ait).second;
	    s += '"';
	} else {
	    s += (*ait).second;	
	}
	s += '\n';
    }
    return s;
}
