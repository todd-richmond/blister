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
	    buf = new char[bufsz];
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

    virtual streambuf *setbuf(char *p, streamsize sz) {
	if (p || !sz || bufsz < sz) {
	    if (alloced)
		delete [] buf;
	    alloced = p == NULL;
	    if (!p && sz)
		p = new char[sz];
	    buf = p;
	}
	if (buf) {
	    bufsz = sz;
	    setp(buf, buf + sz);
	    setg(buf, buf, buf);
	} else {
	    bufsz = 0;
	}
	return this;
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
	char c;

	if (gptr() == NULL) {
	    return fd.read(&c, sizeof (c)) == sizeof (c) ? c : -1;
	} else if (gptr() >= egptr()) {
	    if (xsgetn(&c, 0) == -1)
		return -1;
	}
	return *gptr();
    }

    virtual int overflow(int i = -1) {
	char c = (char)i;

	if (pptr() == NULL) {
	    return i == -1 || fd.write(&c, sizeof (c)) == sizeof (c) ? c : -1;
	} else {
	    int len = i == -1 ? 0 : 1;
	    
	    return xsputn(&c, len) == len ? i : -1;
	}
    }

    virtual streamsize xsputn(const char *p, streamsize size) {
	char *pb = pbase(), *pp = pptr();
	streamsize room = bufsz - (streamsize)(pp - pb);
	streamsize sz = size;
    
	if (room <= sz) {
	    iovec iov[2];

	    iov[0].iov_base = pb;
	    iov[0].iov_len = (ulong)(pp - pb);
	    iov[1].iov_base = (char *)p;
	    iov[1].iov_len = size;
	    if (fd.writev(iov, 2) != (long)(iov[0].iov_len + iov[1].iov_len))
		return -1;
	    setp(pb, pb + bufsz);
	} else if (sz) {
	    memcpy(pp, p, sz);
	    pbump((int)sz);
	} else if (pp - pb) {
	    if (fd.write(pb, (streamsize)(pp - pb)) != pp - pb)
		return -1;
	    setp(pb, pb + bufsz);
	}
	return size;
    }

    virtual streamsize xsgetn(char *p, streamsize sz) {
	streamsize left = (streamsize)(egptr() - gptr());
    
	if (left && left >= sz) {
	    memcpy(p, gptr(), sz);
	    gbump((int)sz);
	} else {
	    char *pb = pbase();
	    streamsize len = (streamsize)(pptr() - pb);

	    if (len) {				// flush output
		if (fd.write(pb, len) != len)
		    return -1;
		setp(pb, pb + bufsz);
	    }
	    memcpy(p, gptr(), left);
	    p += left;
	    left = sz - left;
	    setg(buf, buf, buf);
	    if (left >= bufsz) {		// read directly into user buf
		while (left) {
		    if ((len = fd.read(p, left)) <= 0)
			return sz - left;
		    left -= len;
		    p += len;
		}
	    } else {				// read into stream buf
		while (left) {
		    if ((len = fd.read(buf, bufsz)) <= 0)
			return sz - left;
		    if (len < left) {
			memcpy(p, buf, len);
			left -= len;
			p += len;
		    } else {
			memcpy(p, buf, left);
			setg(buf, buf + left, buf + len);
			break;
		    }
		}
	    }
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

