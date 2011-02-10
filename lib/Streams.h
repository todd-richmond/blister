/*
 * Copyright 2001-2010 Todd Richmond
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

#ifndef Streams_h
#define Streams_h

/*
 * faststreambuf is an optimized stream buffer that reads directly into user
 * buffers and coalesces writes from user buffers with writev to reduce
 * buffer copies when possible
 */
template<class C>
class faststreambuf: public streambuf {
public:
    faststreambuf(uint sz = 4096, char *p = NULL): alloced(false), buf(NULL),
	bufsz(0), fd(-1) { setbuf(p, sz); }
    faststreambuf(C &c, uint sz = 4096, char *p = NULL): alloced(false),
	buf(NULL), bufsz(0), fd(c) { setbuf(p, sz); }
    ~faststreambuf() { if (alloced) delete [] buf; }

    void attach(C &c) { fd = c; }
    const char *str(void) const { return buf; }
    void str(char *p, streamsize sz) { setbuf(p, sz); }
    streamsize read(void *in, streamsize sz) { return xsgetn((char *)in, sz); }
    streamsize write(const void *in, streamsize sz) { return xsputn((const char *)in, sz); }
    template<class T> streamsize read(T &t) { return read(t, sizeof (t)); }
    template<class T> streamsize write(const T &t) { return write(&t, sizeof (t)); }

    virtual int doallocate(void) {
	if (!buf) {
	    buf = new char[(uint)bufsz];
	    alloced = true;
	    setp(buf, buf + bufsz);
	    setg(buf, buf, buf);
	}
	return 0;
    }

    void reset(void) {
	if (buf) {
	    setg(buf, buf, buf);
	    setp(buf, buf + bufsz);
	}
    }
    /*
    virtual streampos seekoff(streamoff off, ios::seek_dir dir,
	int mode = ios::in | ios::out) {

	if (mode & ios::in) {
	    streamoff tmp = off;

	    if (dir == ios::cur)
		off += gptr() - buf;
	    else if (dir == ios::end)
		off += egptr() - buf;
	    if (off < 0 || off > egptr() - buf)
		return -1;
	    setg(buf, buf + off, egptr());
	    if (mode & ios::out)
		off = tmp;
	    else
		return off;
	}
	if (mode & ios::out) {
	    if (dir == ios::cur)
		off += pptr() - pbase();
	    else if (dir == ios::end)
		off += epptr() - pbase();
	    if (off < 0 || off > epptr() - pbase())
		return -1;
	    setp(pbase(), pbase() + off, epptr());
	}
	return off;
    }
    */
    virtual streambuf *setbuf(char *p, streamsize sz) {
	if (p || !sz || bufsz < sz) {
	    if (alloced) {
		delete [] buf;
		alloced = false;
	    }
	    if (!p && sz) {
		p = new char[(uint)sz];
		alloced = true;
	    }
	    buf = p;
	}
	bufsz = sz;
	setg(buf, buf, buf);
	setp(buf, buf + bufsz);
	return this;
    }

    virtual int sync(void) {
	char *pb = pbase(), *pp = pptr();
    
	if (pp > pb) {
	    if (fd.write(pb, (streamsize)(pp - pb)) != pp - pb)
		return -1;
	    setp(pb, pb + bufsz);
	}
	return 0;
    }

    virtual int underflow(void) {
	const char *p = gptr();

	if (p == NULL) {
	    char c;

	    return fd.read(&c, sizeof (c)) == sizeof (c) ? c : -1;
	} else if (p >= egptr()) {
	    char *pb = pbase();
	    streamsize left = (streamsize)(pptr() - pb);
	    int sz;

	    if (left) {
		if ((sz = fd.write(pb, (size_t)left)) != left && sz)
		    return -1;
		setp(pb, pb + bufsz);
	    }
	    if ((sz = fd.read(buf, (size_t)bufsz)) == -1)
		return -1;
	    setg(buf, buf, buf + sz);
	    return *buf;
	}
	return *p;
    }

    virtual int overflow(int i) {
	char c = (char)i;

	if (pptr() == NULL) {
	    return i == -1 || fd.write(&c, sizeof (c)) == sizeof (c) ? c : -1;
	} else {
	    int sz = i == -1 ? 0 : 1;

	    return xsputn(&c, sz) == sz ? i : -1;
	}
    }

    virtual streamsize xsgetn(char *p, streamsize size) {
	streamsize left = (egptr() - gptr());

	if (left && left >= size) {
	    memcpy(p, gptr(), (size_t)size);
	    gbump((int)size);
	    return size;
	}

	int in;
	char *pb = pbase();
	streamsize sz = size - left;

	memcpy(p, gptr(), (size_t)left);
	p += left;
	left = (pptr() - pb);
	if (left) {				// flush output
	    if (fd.write(pb, (size_t)left) != (int)left)
		return -1;
	    setp(pb, pb + bufsz);
	}
	setg(buf, buf, buf);
	if (sz >= bufsz || !bufsz) {		// read directly into user buf
	    while (sz) {
		if ((in = fd.read(p, (size_t)sz)) <= 0)
		    return size - sz;
		p += in;
		sz -= in;
	    }
	} else {				// read into stream buf
	    while (sz) {
		if ((in = fd.read(buf, (size_t)bufsz)) <= 0) {
		    return size - sz;
		} else if (in < sz) {
		    memcpy(p, buf, in);
		    p += in;
		    sz -= in;
		} else {
		    memcpy(p, buf, (size_t)sz);
		    setg(buf, buf + sz, buf + in);
		    break;
		}
	    };
	}
	return size;
    }

    virtual streamsize xsputn(const char *p, streamsize sz) {
	char *pb = pbase(), *pp = pptr();
	streamsize left = bufsz - (pp - pb);

	if (left < sz) {
	    iovec iov[2];
	    long out;

	    iov[0].iov_base = pb;
	    iov[0].iov_len = (ulong)(pp - pb);
	    iov[1].iov_base = (char *)p;
	    iov[1].iov_len = (size_t)sz;
	    out = fd.writev(iov, 2);
	    setp(pb, pb + bufsz);
	    return out == -1 || (ulong)out < iov[0].iov_len ? -1 :
		out - iov[0].iov_len;
	} else if (sz) {
	    memcpy(pp, p, (size_t)sz);
	    pbump((int)sz);
	} else {
	    left = (streamsize)(pp - pb);
	    if (left && fd.write(pb, (size_t)left) != (int)left)
		return -1;
	    setp(pb, pb + bufsz);
	}
	return sz;
    }

private:
    bool alloced;
    char *buf;
    streamsize bufsz;
    C fd;
};

/*
 * bufferstream is a string stream providing cross platform compatibility and
 * works around broken MSVC sstream::seekp() that leaks memory. Use this as a
 * replacement for strstream / sstream
 */
#if !defined(_STLP_NO_OWN_IOSTREAMS) || defined(_WIN32)
#include <sstream>

template <class C>
class bufferstream: public basic_ostream<C> {
public:
    bufferstream(): basic_ostream<C>(&sb), sb(ios::out) {}
    virtual ~bufferstream() {}

    streamsize pcount(void) const { return sb.pcount(); }
    streamsize size(void) const { return sb.pcount(); }
    const C *str(void) const { return sb.str(); }

    void reset(void) { if (sb.pcount()) basic_ostream<C>::seekp(0, ios::beg); }

private:
    class bufferbuf: public basic_stringbuf<C> {
    public:
	bufferbuf(ios::openmode m): basic_stringbuf<C>(m) {}

	streamsize pcount(void) const {
	    return basic_stringbuf<C>::pptr() - basic_stringbuf<C>::pbase();
	}
	const C *str(void) const { return basic_stringbuf<C>::pbase(); }
    };

    bufferbuf sb;
};

#else

#include <strstream>

template <class C>
class bufferstream: public basic_ostrstream<C> {
public:
    bufferstream() {}
    virtual ~bufferstream() { freeze(false); }

    void reset(void) { if (pcount()) { freeze(false); seekp(0, ios::beg); } }
    streamsize size(void) const { return ((basic_ostrstream<C> *)this)->pcount(); }
};
#endif

typedef bufferstream<tchar> tbufferstream;

/*
 * nullstream is a byte sink stream that ignores all writes
 */
class nullstream: public bufferstream<tchar> {
public:
    nullstream() {}

    nullstream &flush(void) { return *this; }
    nullstream &put(char_type) { return *this; }
    nullstream &seekp(pos_type) { return *this; }
    pos_type tellp(void) { return 0; }
    nullstream &write(const char_type *, streamsize) { return *this; }
};

template<class C> nullstream &operator <<(nullstream &os, const C &) {
    return os;
}

#endif // Streams_h

