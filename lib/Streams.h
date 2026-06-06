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

#ifndef Streams_h
#define Streams_h

#include <charconv>
#include <sstream>
#include <type_traits>

// NOLINTBEGIN(misc-multiple-inheritance)

/*
 * faststreambuf is an optimized stream buffer that reads directly into user
 * buffers and coalesces writes from user buffers with writev to reduce
 * buffer copies when possible
 */
template<class C>
class BLISTER faststreambuf: public streambuf, private nocopy {
public:
    explicit faststreambuf(streamsize sz = 4096, char *p = nullptr):
	alloced(false), buf(nullptr), bufsz(0), fd(nullptr) {
	faststreambuf::setbuf(p, sz);
    }
    explicit faststreambuf(const C &c, streamsize sz = 4096, char *p = nullptr):
	alloced(false), buf(nullptr), bufsz(0), fd(&c) {
	faststreambuf::setbuf(p, sz);
    }
    virtual ~faststreambuf() { if (alloced) delete [] buf; }

    void attach(const C &c) { fd = &c; }
    const char *str(void) const { return buf; }
    // cppcheck-suppress nullPointer
    void str(char *p, streamsize sz) { setbuf(p, sz); }
    streamsize read(void *in, streamsize sz) { return xsgetn((char *)in, sz); }
    template<class T> streamsize read(T &t) { return read(t, sizeof (t)); }
    streamsize write(const void *in, streamsize sz) {
	return xsputn((const char *)in, sz);
    }
    template<class T> streamsize write(const T &t) {
	return write(&t, sizeof (t));
    }

    virtual int doallocate(void) {
	if (!buf) {
	    buf = new char[(size_t)bufsz];
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
    streambuf *setbuf(char *p, streamsize sz) override {
	if (p || !sz || bufsz < sz) {
	    if (alloced) {
		delete [] buf;
		alloced = false;
	    }
	    if (!p && sz) {
		p = new char[(size_t)sz];
		alloced = true;
	    }
	    buf = p;
	}
	bufsz = sz;
	setg(buf, buf, buf);
	setp(buf, buf + bufsz);
	return this;
    }

    int sync(void) override {
	char *pb = pbase();
	const char *pp = pptr();
	streamsize sz = pp - pb;

	if (LIKELY(sz > 0)) {
	    if (UNLIKELY(!fd || fd->write(pb, (uint)sz) != (int)sz))
		return -1;
	    setp(pb, pb + bufsz);
	}
	return 0;
    }

    int underflow(void) override {
	const char *gp = gptr();

	if (UNLIKELY(gp == NULL)) {
	    uchar c;

	    return fd->read((char *)&c, sizeof (c)) == (int)sizeof (c) ?
		(int)c : -1;
	}
	if (LIKELY(gp < egptr()))
	    return *gp;

	char *pb = pbase();
	const char *pp = pptr();
	streamsize left = pp - pb;

	if (left > 0) {
	    int sz = fd->write(pb, (uint)left);
	    if (UNLIKELY(sz != left))
		return -1;
	    setp(pb, pb + bufsz);
	}
	int sz = fd->read(buf, (uint)bufsz);
	if (UNLIKELY(sz <= 0))
	    return -1;
	setg(buf, buf, buf + sz);
	return (uchar)*buf;
    }

    int overflow(int i) override {
	uchar c = (uchar)i;

	if (pptr() == NULL) {
	    return i == -1 || fd->write((const char *)&c, sizeof (c)) ==
		(int)sizeof (c) ? i : -1;
	} else {
	    int sz = i == -1 ? 0 : 1;

	    return xsputn((const char *)&c, sz) == sz ? i : -1;
	}
    }

    streamsize xsgetn(char *p, streamsize size) override {
	const char *gp = gptr();
	const char *eg = egptr();
	streamsize left = eg - gp;

	if (LIKELY(left >= size)) {
	    memcpy(p, gp, (size_t)size);
	    gbump((int)size);
	    return size;
	}

	if (left > 0) {
	    memcpy(p, gp, (size_t)left);
	    p += left;
	}
	char *pb = pbase();
	const char *pp = pptr();
	streamsize sz = size - left;
	streamsize outleft = pp - pb;

	if (outleft) {				// flush output
	    if (UNLIKELY(fd->write(pb, (uint)outleft) != (int)outleft))
		return -1;
	    setp(pb, pb + bufsz);
	}
	setg(buf, buf, buf);
	if (sz >= bufsz || !bufsz) {		// read directly into user buf
	    while (sz) {
		int in = fd->read(p, (uint)sz);

		if (UNLIKELY(in <= 0))
		    return size - sz;
		p += in;
		sz -= in;
	    }
	} else {				// read into stream buf
	    while (sz) {
		int in = fd->read(buf, (uint)bufsz);
		if (UNLIKELY(in <= 0))
		    return size - sz;
		if (in < sz) {
		    memcpy(p, buf, (size_t)in);
		    p += in;
		    sz -= in;
		} else {
		    memcpy(p, buf, (size_t)sz);
		    setg(buf, buf + sz, buf + in);
		    break;
		}
	    }
	}
	return size;
    }

    streamsize xsputn(const char *p, streamsize sz) override {
	long out;
	char *pb = pbase();
	char *pp = pptr();
	streamsize used = pp - pb;
	streamsize left = bufsz - used;

	if (LIKELY(sz <= left)) {
	    if (LIKELY(sz > 0)) {
		memcpy(pp, p, (size_t)sz);
		pbump((int)sz);
	    } else if (used > 0) {
		if (UNLIKELY(fd->write(pb, (uint)used) != (int)used))
		    return -1;
		setp(pb, pb + bufsz);
	    }
	    return sz;
	}
	setp(pb, pb + bufsz);
	if (!used) {
	    out = fd->write(p, (uint)sz);
	    return UNLIKELY(out == -1) ? -1 : (streamsize)out;
	}
	iovec iov[2]{};
	iov[0].iov_base = pb;
	iov[0].iov_len = (iovlen_t)used;
	iov[1].iov_base = (char *)p;
	iov[1].iov_len = (iovlen_t)sz;
	out = fd->writev(iov, 2);
	return UNLIKELY(out == -1 || (ulong)out < (ulong)used) ? -1 :
	    (streamsize)out - (streamsize)used;
    }

private:
    bool alloced;
    char *buf;
    streamsize bufsz;
    const C *fd;
};

/*
 * bufferstream is a fast string stream providing cross platform compatibility
 * and works around broken MSVC sstream::seekp() that leaks memory. Use this as
 * a replacement for strstream / sstream
 */
template <class C>
class BLISTER bufferstream: public basic_ostream<C> {
public:
    bufferstream(): basic_ostream<C>(&sb), sb(ios::out) {}

    streamsize pcount(void) const { return sb.pcount(); }
    streamsize size(void) const { return pcount(); }
    const C *str(void) const { return sb.buffer(); }
    C back(void) const { return sb.back(); }

    void reset(void) { if (sb.pcount()) sb.reset(); }
    void write(C c) { sb.write(c); }
    void write(bool b) { sb.write(b ? C('t') : C('f')); }
    void write(const C *s, streamsize n) { sb.write(s, n); }
    template <typename T>
    __forceinline void write(const T &val) {
	if constexpr (is_integral_v<T> || is_floating_point_v<T>) {
#ifdef UNICODE
	    wchar buf[24];
	    auto [end, ec] = to_chars(buf, buf + sizeof (buf), val);

	    if (LIKELY(ec == errc{})) {
		wchar wbuf[24];

		for (auto *s = buf, *d = wbuf; s < end;)
		    *d++ = (wchar)*s++;
		write(wbuf, end - buf);
	    }
#else
	    if constexpr (is_integral_v<T>) {
		char buf[24];
		char *p = buf + sizeof (buf);
		auto uval = static_cast<make_unsigned_t<T>>(val);

		if constexpr (is_signed_v<T>)
		    if (val < 0)
			uval = 0 - uval;
		while (uval >= 100) {
		    auto const idx = (uval % 100) * 2;

		    uval /= 100;
		    *--p = digit_pairs[idx + 1];
		    *--p = digit_pairs[idx];
		}
		if (uval >= 10) {
		    auto const idx = uval * 2;

		    *--p = digit_pairs[idx + 1];
		    *--p = digit_pairs[idx];
		} else {
		    *--p = (char)('0' + uval);
		}
		if constexpr (is_signed_v<T>)
		    if (val < 0)
			*--p = '-';
		write(p, buf + sizeof (buf) - p);
	    } else {
		char buf[24];
		auto [end, ec] = to_chars(buf, buf + sizeof (buf), val);

		if (LIKELY(ec == errc{}))
		    write(buf, end - buf);
	    }
#endif
	} else if constexpr (is_enum_v<T>) {
	    write(static_cast<underlying_type_t<T>>(val));
	} else {
	    *this << val;
	}
    }

private:
    static constexpr char digit_pairs[] =
	"00010203040506070809"
	"10111213141516171819"
	"20212223242526272829"
	"30313233343536373839"
	"40414243444546474849"
	"50515253545556575859"
	"60616263646566676869"
	"70717273747576777879"
	"80818283848586878889"
	"90919293949596979899";
    class BLISTER bufferbuf: public basic_stringbuf<C> {
    public:
	explicit bufferbuf(ios::openmode m): basic_stringbuf<C>(m) {}

	streamsize pcount(void) const {
	    return basic_stringbuf<C>::pptr() - basic_stringbuf<C>::pbase();
	}
	const C *buffer(void) const { return basic_stringbuf<C>::pbase(); }
	C back(void) const { return *(basic_stringbuf<C>::pptr() - 1); }
	void reset(void) {
	    basic_stringbuf<C>::setp(basic_stringbuf<C>::pbase(),
		basic_stringbuf<C>::epptr());
	}
	void write(C c) {
	    C *pp = basic_stringbuf<C>::pptr();

	    if (LIKELY(pp < basic_stringbuf<C>::epptr())) {
		*pp = c;
		basic_stringbuf<C>::pbump(1);
	    } else {
		basic_stringbuf<C>::sputc(c);
	    }
	}
	void write(const C *s, streamsize n) {
	    C *pp = basic_stringbuf<C>::pptr();

	    if (LIKELY(pp + n <= basic_stringbuf<C>::epptr())) {
		memcpy(pp, s, (size_t)n * sizeof (C));
		basic_stringbuf<C>::pbump((int)n);
	    } else {
		basic_stringbuf<C>::sputn(s, n);
	    }
	}
    };

    bufferbuf sb;
};

using tbufferstream = bufferstream<tchar>;

class BLISTER memstream: public istream {
public:
    memstream(const void *data, streamsize sz): istream(&mb), mb(data, sz) {}

private:
    class BLISTER membuf: public streambuf, private nocopy {
    public:
	explicit membuf(const void *data, streamsize sz): begin((char *)data),
	    end(begin + sz) {
	    setg(begin, begin, end);
	}

    private:
	streampos seekoff(off_type off, ios_base::seekdir dir,
	    ios_base::openmode) override {
	    if (dir == ios_base::cur) {
		char *np = gptr() + off;

		setg(begin, np < begin ? begin : np >= end ? end : np, end);
	    } else if (dir == ios_base::beg) {
		char *np = begin + off;

		setg(begin, np < begin ? begin : np >= end ? end : np, end);
	    } else {
		setg(begin, end, end);
	    }
	    return gptr() - eback();
	}
	streampos seekpos(streampos pos, ios_base::openmode mode) override {
	    return seekoff(pos, ios_base::beg, mode);
	}

	char *begin, *end;
    };

    membuf mb;
};

/*
 * nullstream is a byte sink stream that ignores all writes
 */
class BLISTER nullstream: public bufferstream<tchar> {
public:
    nullstream() {}

    nullstream &flush(void) { return *this; }
    nullstream &put(char_type) { return *this; }
    nullstream &seekp(pos_type) { return *this; }
    pos_type tellp(void) { return 0; }
    // NOLINTNEXTLINE bugprone-derived-method-shadowing-base-method
    nullstream &write(const char_type *, streamsize) { return *this; }
};

template<class C> nullstream &operator <<(nullstream &os, const C &) {
    return os;
}

// NOLINTEND(misc-multiple-inheritance)

#endif // Streams_h
