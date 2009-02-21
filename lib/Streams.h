#ifndef Streams_h
#define Streams_h

// fast, optimized stream buffer using direct reads and writv
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
    streamsize read(void *in, int sz) { return xsgetn((char *)in, sz); }
    streamsize write(const void *in, int sz) { return xsputn((const char *)in, sz); }
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
	    if (fd.write(pb, pp - pb) != pp - pb)
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
	streamsize room = bufsz - (pp - pb);
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
	    pbump(sz);
	} else if (pp - pb) {
	    if (fd.write(pb, pp - pb) != pp - pb)
		return -1;
	    setp(pb, pb + bufsz);
	}
	return size;
    }

    virtual streamsize xsgetn(char *p, streamsize sz) {
	streamsize in;
	streamsize left = egptr() - gptr();
    
	if (left && left >= sz) {
	    memcpy(p, gptr(), sz);
	    gbump(sz);
	} else {
	    char *pb = pbase();
	    
	    in = pptr() - pb;
	    if (in) {			    // flush output
		if (fd.write(pb, in) != in)
		    return -1;
		setp(pb, pb + bufsz);
	    }
	    memcpy(p, gptr(), left);
	    p += left;
	    left = sz - left;
	    setg(buf, buf, buf);
	    if (left >= bufsz) {	    // reading directly into user buf
		while (left) {
		    if ((in = fd.read(p, left)) <= 0)
			return sz - left;
		    left -= in;
		    p += in;
		}
	    } else if (left || !sz) {	    // read into stream buf
		int len;
		
		do {
		    if ((in = fd.read(buf, bufsz)) <= 0)
			return sz ? sz - left : -1;
		    len = min(in, left);
		    left -= len;
		    memcpy(p, buf, len);
		    p += len;
		} while (left);
		if (len != in)
		    setg(buf, buf + len, buf + in);
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

class nullstream {
public:
    nullstream() {}

    template<class C> nullstream &operator <<(const C &c) { return *this; }
    size_t pcount(void) const { return 0; }
    size_t size(void) const { return 0; }
    const char *str(void) const { return NULL; }
    void reset(void) {}
};

// string buffer to work around broken MSVC stream::seekp()
#if !defined(_STLP_NO_OWN_IOSTREAMS) || defined(_WIN32)
#include <sstream>

class bufferstream: public ostream {
public:
    bufferstream(): ostream(&sb), sb(out) {}
    virtual ~bufferstream() {}

    size_t pcount(void) const { return sb.pcount(); }
    size_t size(void) const { return sb.pcount(); }
    const char *str(void) const { return sb.str(); }

    void reset(void) { if (pcount()) seekp(0, ios::beg); }

private:
    class bufferbuf: public stringbuf {
    public:
	bufferbuf(ios::openmode m): stringbuf(m) {}

	size_t pcount(void) const { return pptr() - pbase(); }
	const char *str(void) const { return pbase(); }
    };

    bufferbuf sb;
};

#else

#include <strstream>

class bufferstream: public ostrstream {
public:
    bufferstream() {}
    virtual ~bufferstream() { freeze(false); }

    void reset(void) { if (pcount()) { freeze(false); seekp(0, ios::beg); } }
    size_t size(void) const { return ((ostrstream *)this)->pcount(); }
};
#endif

#endif // Streams_h
