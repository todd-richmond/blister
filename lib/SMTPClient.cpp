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

#include "stdapi.h"
#include <algorithm>
#include <array>
#include <random>
#include "Log.h"
#include "SMTPClient.h"
#include "Thread.h"

#pragma warning(disable: 6328 6330)

#define CMD_NOREPLY 0

const char SMTPClient::crlf[] = "\r\n";

static constexpr bool nonascii(tchar c) { return (tuchar)c > 0x7f; }

// ---- base64 / uuencode / uudecode / high bit scanning ----
// AVX2 versions are used when compiled with __AVX2__ (-march=native). A NEON
// version can be added at the same #ifdef points for other platforms

static bool highbit8(const char *p, size_t n) {
    constexpr uint64_t mask = 0x8080808080808080ULL;

#ifdef __AVX2__
    if (n >= 64) {
	const __m256i zero = _mm256_setzero_si256();

	for (; n >= 128; p += 128, n -= 128) {
	    __m256i v = _mm256_or_si256(
		_mm256_or_si256(_mm256_loadu_si256((const __m256i *)p),
		_mm256_loadu_si256((const __m256i *)(p + 32))),
		_mm256_or_si256(_mm256_loadu_si256((const __m256i *)(p + 64)),
		_mm256_loadu_si256((const __m256i *)(p + 96))));

	    if (_mm256_movemask_epi8(_mm256_cmpgt_epi8(zero, v)))
		return true;
	}
	for (; n >= 32; p += 32, n -= 32) {
	    if (_mm256_movemask_epi8(_mm256_loadu_si256((const __m256i *)p)))
		return true;
	}
	// final partial block - overlap the previous bytes rather than a loop
	return n && _mm256_movemask_epi8(_mm256_loadu_si256(
	    (const __m256i *)(p + n - 32)));
    }
#endif
    for (; n >= 8; p += 8, n -= 8) {
	uint64_t v;

	memcpy(&v, p, 8);
	if (v & mask)
	    return true;
    }
    for (; n; ++p, --n) {
	if ((uchar)*p > 0x7f)
	    return true;
    }
    return false;
}

static bool highbit8(string_view s) { return highbit8(s.data(), s.size()); }

static bool highbit(tstring_view s) {
    if constexpr (sizeof (tchar) == 1)
	return highbit8(string_view((const char *)s.data(), s.size()));
    else
	return ranges::any_of(s, nonascii);
}

// base64 and uuencode characters for 12 bit values
struct Pair {
    char c[2];
};

template<bool UU> static constexpr char codecchar(uint v) {
    if (UU)
	return v ? (char)(' ' + v) : '`';
    return (char)(v < 26 ? 'A' + v : v < 52 ? 'a' + v - 26 : v < 62 ? '0' +
	v - 52 : v == 62 ? '+' : '/');
}

template<bool UU> static constexpr array<Pair, 4096> makepairs() {
    array<Pair, 4096> t {};

    for (uint i = 0; i < 4096; ++i)
	t[i] = { { codecchar<UU>(i >> 6), codecchar<UU>(i & 63) } };
    return t;
}

static constexpr auto b64pairs = makepairs<false>();
static constexpr auto uupairs = makepairs<true>();

// base64 character to 6 bit value, 0xff if invalid
static constexpr array<uchar, 256> b64values = [] {
    array<uchar, 256> t {};

    ranges::fill(t, (uchar)0xff);
    for (uint i = 0; i < 64; ++i)
	t[(uchar)codecchar<false>(i)] = (uchar)i;
    return t;
}();

#ifdef __AVX2__
// 24 bytes to 32 characters
template<bool UU> static inline void encode24(const uchar *in,
    char *out) {
    __m256i v = _mm256_inserti128_si256(_mm256_castsi128_si256(
	_mm_loadu_si128((const __m128i *)in)),
	_mm_loadu_si128((const __m128i *)(in + 12)), 1);

    // six bit values
    v = _mm256_shuffle_epi8(v, _mm256_setr_epi8(1, 0, 2, 1, 4, 3, 5, 4, 7, 6,
	8, 7, 10, 9, 11, 10, 1, 0, 2, 1, 4, 3, 5, 4, 7, 6, 8, 7, 10, 9, 11,
	10));
    v = _mm256_or_si256(_mm256_mulhi_epu16(_mm256_and_si256(v,
	_mm256_set1_epi32(0x0fc0fc00)), _mm256_set1_epi32(0x04000040)),
	_mm256_mullo_epi16(_mm256_and_si256(v, _mm256_set1_epi32(0x003f03f0)),
	_mm256_set1_epi32(0x01000010)));
    if (UU) {
	v = _mm256_blendv_epi8(_mm256_add_epi8(v, _mm256_set1_epi8(' ')),
	    _mm256_set1_epi8('`'), _mm256_cmpeq_epi8(v,
	    _mm256_setzero_si256()));
    } else {
	const __m256i shift = _mm256_setr_epi8('a' - 26, '0' - 52, '0' - 52,
	    '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
	    '0' - 52, '0' - 52, '+' - 62, '/' - 63, 'A', 0, 0, 'a' - 26,
	    '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52, '0' - 52,
	    '0' - 52, '0' - 52, '0' - 52, '0' - 52, '+' - 62, '/' - 63, 'A',
	    0, 0);
	__m256i idx = _mm256_subs_epu8(v, _mm256_set1_epi8(51));

	idx = _mm256_or_si256(idx, _mm256_and_si256(_mm256_cmpgt_epi8(
	    _mm256_set1_epi8(26), v), _mm256_set1_epi8(13)));
	v = _mm256_add_epi8(v, _mm256_shuffle_epi8(shift, idx));
    }
    _mm256_storeu_si256((__m256i *)out, v);
}

#endif

// Encode into out which must have room for the result: UU lines are prefixed
// with a length character, wrap adds a CRLF after every 45 input bytes
template<bool UU> static size_t encode(const uchar *in, size_t len, char *out,
    bool wrap) {
    const auto &tab = UU ? uupairs : b64pairs;
    const char *start = out;
    const char pad = UU ? '`' : '=';

#ifdef __AVX2__
    // whole lines (or blocks without line breaks) of input
    if (!wrap) {
	for (; len >= 28; in += 24, out += 32, len -= 24)
	    encode24<UU>(in, out);
    } else {
	// each 45 byte line is two overlapping 24 byte blocks
	for (; len >= 49; in += 45, len -= 45) {
	    if (UU)
		*out++ = 'M';
	    encode24<UU>(in, out);
	    encode24<UU>(in + 21, out + 28);
	    out += 60;
	    *out++ = '\r';
	    *out++ = '\n';
	}
    }
#endif
    while (len) {
	size_t n = wrap ? min(len, (size_t)45) : len;

	len -= n;
	if (UU)
	    *out++ = codecchar<true>((uint)n);
	for (; n >= 3; n -= 3, in += 3, out += 4) {
	    uint v = (uint)in[0] << 16 | (uint)in[1] << 8 | in[2];

	    memcpy(out, &tab[v >> 12], 2);
	    memcpy(out + 2, &tab[v & 4095], 2);
	}
	if (n) {
	    uint v = (uint)in[0] << 16 | (n == 2 ? (uint)in[1] << 8 : 0);

	    in += n;
	    memcpy(out, &tab[v >> 12], 2);
	    out[2] = n == 2 ? tab[v & 4095].c[0] : pad;
	    out[3] = pad;
	    out += 4;
	}
	if (wrap) {
	    *out++ = '\r';
	    *out++ = '\n';
	}
    }
    return (size_t)(out - start);
}

// base64 without line breaks
static string base64line(string_view in) {
    string s((in.size() + 2) / 3 * 4, '\0');

    encode<false>((const uchar *)in.data(), in.size(), s.data(), false);
    return s;
}

bool base64encode(const void *in, size_t len, char *&out, size_t &outsz) {
    out = new char[(len + 2) / 3 * 4 + (len + 44) / 45 * 2 + 1];
    outsz = encode<false>((const uchar *)in, len, out, true);
    out[outsz] = '\0';
    return true;
}

bool uuencode(const tchar *file, const void *in, size_t len, char *&out,
    size_t &outsz) {
    static constexpr char begin[] = "begin 644 ";
    static constexpr char end[] = "\r\nend\r\n";
    string filestr = tchartoachar(file);

    out = new char[sizeof (begin) + filestr.size() + 2 + (len + 2) / 3 * 4 +
	(len + 44) / 45 * 3 + 1 + sizeof (end) + 32];
    memcpy(out, begin, sizeof (begin) - 1);
    outsz = sizeof (begin) - 1;
    memcpy(out + outsz, filestr.data(), filestr.size());
    outsz += filestr.size();
    out[outsz++] = '\r';
    out[outsz++] = '\n';
    outsz += encode<true>((const uchar *)in, len, out + outsz, true);
    out[outsz++] = '`';
    memcpy(out + outsz, end, sizeof (end));
    outsz += sizeof (end) - 1;
    return true;
}

bool uudecode(const char *in, size_t sz, uint &perm, tstring &file,
    void *&out, size_t &outsz) {
    const uchar *p = (const uchar *)in;
    const uchar *end = p + sz;
    const uchar *name;
    uchar *o;
    auto skipspace = [&] {
	while (p < end && isspace(*p))
	    ++p;
    };
    auto dec = [](uchar c) { return (uint)((c - ' ') & 077); };

    outsz = 0;
    skipspace();
    // cppcheck-suppress knownConditionTrueFalse
    if (end - p < 6 || strnicmp((const char *)p, "begin ", 6) != 0)
	return false;
    p += 5;
    skipspace();
    name = p;
    perm = 0;
    while (p < end && *p >= '0' && *p <= '7')
	perm = perm * 8 + (uint)(*p++ - '0');
    if (p == name || p >= end || !isspace(*p))
	return false;
    skipspace();
    name = p;
    while (p < end && *p && !isspace(*p))
	++p;
    file.assign(name, p);
    if (p >= end)
	return false;
    o = new uchar[(size_t)(end - p) * 3 / 4 + 8];
    out = o;
    for (;;) {
	skipspace();
	if (p == end)
	    break;

	uint n = dec(*p++);

	if (!n)
	    break;
#ifdef __AVX2__
	if (n == 45 && end - p >= 60) {
	    // 60 characters to 45 bytes in two 32 character blocks that overlap
	    for (uint i = 0; i < 2; ++i) {
		__m256i v = _mm256_loadu_si256((const __m256i *)(p + i * 28));

		v = _mm256_and_si256(_mm256_sub_epi8(v, _mm256_set1_epi8(' ')),
		    _mm256_set1_epi8(63));
		v = _mm256_maddubs_epi16(v, _mm256_set1_epi32(0x01400140));
		v = _mm256_madd_epi16(v, _mm256_set1_epi32(0x00011000));
		v = _mm256_shuffle_epi8(v, _mm256_setr_epi8(2, 1, 0, 6, 5, 4,
		    10, 9, 8, 14, 13, 12, -1, -1, -1, -1, 2, 1, 0, 6, 5, 4, 10,
		    9, 8, 14, 13, 12, -1, -1, -1, -1));
		v = _mm256_permutevar8x32_epi32(v, _mm256_setr_epi32(0, 1, 2,
		    4, 5, 6, -1, -1));
		_mm_storeu_si128((__m128i *)(o + i * 21),
		    _mm256_castsi256_si128(v));
		_mm_storel_epi64((__m128i *)(o + i * 21 + 16),
		    _mm256_extracti128_si256(v, 1));
	    }
	    p += 60;
	    o += 45;
	    continue;
	}
#endif
	// full groups of 4 characters
	for (; n >= 3 && end - p >= 4; n -= 3, p += 4, o += 3) {
	    uint v = dec(p[0]) << 18 | dec(p[1]) << 12 | dec(p[2]) << 6 |
		dec(p[3]);

	    o[0] = (uchar)(v >> 16);
	    o[1] = (uchar)(v >> 8);
	    o[2] = (uchar)v;
	}
	if (n) {
	    // final partial group of 1 or 2 bytes needs n + 1 characters
	    if (n >= 3 || end - p < (ptrdiff_t)(n + 1)) {
		delete [] (uchar *)out;
		out = nullptr;
		return false;
	    }

	    uint v = dec(p[0]) << 18 | dec(p[1]) << 12 | (n > 1 ?
		dec(p[2]) << 6 : 0);

	    *o++ = (uchar)(v >> 16);
	    if (n > 1)
		*o++ = (uchar)(v >> 8);
	    // the encoder pads the group to 4 characters
	    p += min((ptrdiff_t)4, end - p);
	}
    }
    outsz = (size_t)(o - (uchar *)out);
    *o = '\0';
    skipspace();
    // cppcheck-suppress knownConditionTrueFalse
    if (end - p < 3 || memcmp(p, "end", 3) != 0) {
	delete [] (uchar *)out;
	out = nullptr;
	return false;
    }
    return true;
}

bool base64decode(const char *in, size_t sz, void *&out, size_t &outsz) {
    const uchar *p = (const uchar *)in;
    const uchar *end = p + sz;
    uchar *o = new uchar[sz * 3 / 4 + 8];
    const uchar *start = o;
    uint acc = 0, bits = 0;

    out = o;
    for (;;) {
	if (!bits) {
	    // whole groups of valid characters
	    while (end - p >= 4) {
		uint a = b64values[p[0]], b = b64values[p[1]];
		uint c = b64values[p[2]], d = b64values[p[3]];

		if ((a | b | c | d) > 63)
		    break;
		a = a << 18 | b << 12 | c << 6 | d;
		o[0] = (uchar)(a >> 16);
		o[1] = (uchar)(a >> 8);
		o[2] = (uchar)a;
		p += 4;
		o += 3;
	    }
	}
	if (p == end)
	    break;

	uint v = b64values[*p++];

	if (v > 63) {
	    // skip anything invalid like whitespace until the pad
	    if (p[-1] == '=')
		break;
	    continue;
	}
	acc = acc << 6 | v;
	if ((bits += 6) == 24) {
	    o[0] = (uchar)(acc >> 16);
	    o[1] = (uchar)(acc >> 8);
	    o[2] = (uchar)acc;
	    o += 3;
	    acc = bits = 0;
	}
    }
    // 12 bits is one byte and 18 bits is two bytes
    if (bits >= 12) {
	if (bits == 12) {
	    *o++ = (uchar)(acc >> 4);
	} else {
	    *o++ = (uchar)(acc >> 10);
	    *o++ = (uchar)(acc >> 2);
	}
    }
    outsz = (size_t)(o - start);
    *o = '\0';
    return true;
}

// quoted-printable characters that need no encoding: tab, space and printable
// ASCII except '='
static constexpr array<bool, 256> qpplain = [] {
    array<bool, 256> t {};

    for (uint i = 0; i < 256; ++i)
	t[i] = i == '\t' || (i >= ' ' && i < 127 && i != '=');
    return t;
}();

// hex digit to 4 bit value, 0xff if invalid
static constexpr array<uchar, 256> hexvalues = [] {
    array<uchar, 256> t {};

    ranges::fill(t, (uchar)0xff);
    for (uint i = 0; i < 10; ++i)
	t['0' + i] = (uchar)i;
    for (uint i = 0; i < 6; ++i)
	t['A' + i] = t['a' + i] = (uchar)(10 + i);
    return t;
}();

// RFC 2045 quoted-printable with CRLF line breaks and lines of at most 76
// characters. CRLF and bare LF are line breaks, a bare CR is encoded and so
// is whitespace that would end a line
bool qpencode(const void *in, size_t len, char *&out, size_t &outsz) {
    static constexpr char hex[] = "0123456789ABCDEF";
    const uchar *p = (const uchar *)in;
    const uchar *end = p + len;
    char *o = out = new char[len * 3 + len / 8 + 8];
    size_t col = 0;

    while (p < end) {
	uchar c = *p;

	if (c == '\n' || (c == '\r' && end - p > 1 && p[1] == '\n')) {
	    p += c == '\r' ? 2 : 1;
	    *o++ = '\r';
	    *o++ = '\n';
	    col = 0;
	    continue;
	}
	if (col == 75) {
	    memcpy(o, "=\r\n", 3);
	    o += 3;
	    col = 0;
	}

	// run of characters that need no encoding and fit on the line
	size_t n = 0, avail = min((size_t)(end - p), 75 - col);

#ifdef __AVX2__
	for (; n + 32 <= avail; n += 32) {
	    __m256i v = _mm256_loadu_si256((const __m256i *)(p + n));
	    __m256i ok = _mm256_andnot_si256(_mm256_cmpeq_epi8(v,
		_mm256_set1_epi8('=')), _mm256_and_si256(_mm256_cmpgt_epi8(v,
		_mm256_set1_epi8(31)), _mm256_cmpgt_epi8(_mm256_set1_epi8(127),
		v)));
	    uint m;

	    _mm256_storeu_si256((__m256i *)(o + n), v);
	    ok = _mm256_or_si256(ok, _mm256_cmpeq_epi8(v, _mm256_set1_epi8('\t')));
	    m = (uint)_mm256_movemask_epi8(ok);
	    if (m != ~0U) {
		// the table loop below stops at this character
		n += (size_t)countr_zero(~m);
		break;
	    }
	}
#endif
	for (; n < avail && qpplain[p[n]]; ++n)
	    o[n] = (char)p[n];
	// trailing whitespace would be lost
	if (n && (p[n - 1] == ' ' || p[n - 1] == '\t') && (p + n == end ||
	    p[n] == '\r' || p[n] == '\n'))
	    --n;
	if (n) {
	    p += n;
	    o += n;
	    col += n;
	    continue;
	}
	if (col > 72) {
	    memcpy(o, "=\r\n", 3);
	    o += 3;
	    col = 0;
	}
	o[0] = '=';
	o[1] = hex[c >> 4];
	o[2] = hex[c & 15];
	o += 3;
	col += 3;
	++p;
    }
    outsz = (size_t)(o - out);
    *o = '\0';
    return true;
}

// Lenient quoted-printable decode: soft line breaks are removed, whitespace
// before a hard line break is dropped unless it was encoded, and an '=' that
// is not part of a valid escape is kept. Line breaks are preserved
bool qpdecode(const char *in, size_t sz, void *&out, size_t &outsz) {
    const uchar *p = (const uchar *)in;
    const uchar *end = p + sz;
    uchar *o = new uchar[sz + 1];
    const uchar *start = o;
    // decoded whitespace that must not be removed
    const uchar *keep = o;

    out = o;
    while (p < end) {
	// copy characters that need no decoding
	size_t n = 0, avail = (size_t)(end - p);

#ifdef __AVX2__
	for (; n + 32 <= avail; n += 32) {
	    __m256i v = _mm256_loadu_si256((const __m256i *)(p + n));
	    uint m = (uint)_mm256_movemask_epi8(_mm256_or_si256(
		_mm256_cmpeq_epi8(v, _mm256_set1_epi8('=')), _mm256_or_si256(
		_mm256_cmpeq_epi8(v, _mm256_set1_epi8('\r')),
		_mm256_cmpeq_epi8(v, _mm256_set1_epi8('\n')))));

	    _mm256_storeu_si256((__m256i *)(o + n), v);
	    if (m) {
		// the loop below stops at this character
		n += (size_t)countr_zero(m);
		break;
	    }
	}
#endif
	for (; n < avail && p[n] != '=' && p[n] != '\r' && p[n] != '\n'; ++n)
	    o[n] = p[n];
	p += n;
	o += n;
	if (p == end)
	    break;

	uchar c = *p++;

	if (c == '=') {
	    uint h = end - p >= 2 ? hexvalues[p[0]] : 0xff;
	    uint l = h < 16 ? hexvalues[p[1]] : 0xff;

	    if ((h | l) < 16) {
		*o++ = (uchar)(h << 4 | l);
		keep = o;
		p += 2;
		continue;
	    }

	    // soft line break after optional whitespace, also at the end
	    const uchar *q = p;

	    while (q < end && (*q == ' ' || *q == '\t'))
		++q;
	    if (q == end || *q == '\n') {
		p = q + (q < end);
	    } else if (*q == '\r' && (q + 1 == end || q[1] == '\n')) {
		p = q + 1 + (q + 1 < end);
	    } else {
		*o++ = '=';
	    }
	} else if (c == '\n' || (p < end && *p == '\n')) {
	    // hard line break
	    while (o > keep && (o[-1] == ' ' || o[-1] == '\t'))
		--o;
	    if (c == '\r') {
		*o++ = '\r';
		++p;
	    }
	    *o++ = '\n';
	} else {
	    // lone CR
	    *o++ = c;
	}
    }
    outsz = (size_t)(o - start);
    *o = '\0';
    return true;
}

// strictly decode UTF-8 into code points
static bool utf8decode(string_view s, vector<char32_t> &cp) {
    for (size_t i = 0; i < s.size();) {
	uchar c = (uchar)s[i];
	char32_t v;
	size_t n;

	if (c < 0x80) {
	    v = c;
	    n = 0;
	} else if ((c & 0xe0) == 0xc0) {
	    v = c & 0x1f;
	    n = 1;
	} else if ((c & 0xf0) == 0xe0) {
	    v = c & 0x0f;
	    n = 2;
	} else if ((c & 0xf8) == 0xf0) {
	    v = c & 0x07;
	    n = 3;
	} else {
	    return false;
	}
	if (i + n >= s.size())
	    return false;
	for (size_t k = 1; k <= n; ++k) {
	    uchar b = (uchar)s[i + k];

	    if ((b & 0xc0) != 0x80)
		return false;
	    v = (v << 6) | (b & 0x3f);
	}
	// reject overlong encodings, surrogates and out of range values
	if ((n == 1 && v < 0x80) || (n == 2 && v < 0x800) ||
	    (n == 3 && v < 0x10000) || v > 0x10ffff ||
	    (v >= 0xd800 && v <= 0xdfff))
	    return false;
	cp.push_back(v);
	i += n + 1;
    }
    return true;
}

// RFC 3492 punycode encoder
static bool punycode(const vector<char32_t> &in, string &out) {
    static constexpr uint32_t base = 36, tmin = 1, tmax = 26, skew = 38;
    static constexpr uint32_t damp = 700, initial_bias = 72, initial_n = 128;
    auto digit = [](uint32_t d) {
	return (char)(d < 26 ? 'a' + d : '0' + d - 26);
    };
    auto adapt = [](uint32_t delta, uint32_t points, bool first) {
	uint32_t k = 0;

	delta = first ? delta / damp : delta / 2;
	delta += delta / points;
	for (; delta > ((base - tmin) * tmax) / 2; k += base)
	    delta /= base - tmin;
	return k + (base - tmin + 1) * delta / (delta + skew);
    };
    uint32_t n = initial_n, delta = 0, bias = initial_bias;
    size_t h = (size_t)ranges::count_if(in, [](char32_t c) {
	return c < 0x80;
    });
    const size_t b = h;

    for (char32_t c : in) {
	if (c < 0x80)
	    out += (char)c;
    }
    if (b)
	out += '-';
    while (h < in.size()) {
	uint32_t m = UINT32_MAX;

	for (char32_t c : in) {
	    if (c >= n && c < m)
		m = c;
	}
	if (m - n > (UINT32_MAX - delta) / (uint32_t)(h + 1))
	    return false;
	delta += (m - n) * (uint32_t)(h + 1);
	n = m;
	for (char32_t c : in) {
	    if (c < n && ++delta == 0)
		return false;
	    if (c != n)
		continue;
	    uint32_t q = delta;

	    for (uint32_t k = base;; k += base) {
		uint32_t t = k <= bias ? tmin : k >= bias + tmax ? tmax :
		    k - bias;

		if (q < t)
		    break;
		out += digit(t + (q - t) % (base - t));
		q = (q - t) / (base - t);
	    }
	    out += digit(q);
	    bias = adapt(delta, (uint32_t)(h + 1), h == b);
	    delta = 0;
	    ++h;
	}
	++delta;
	++n;
    }
    return true;
}

// IDNA encode a UTF-8 domain name label by label. ASCII labels are copied
// as is and ASCII is lower cased within encoded labels, but no Unicode
// normalization or mapping is done (U+00DF stays as is, per IDNA2008) - the
// name must already be normalized
static bool idna(string_view domain, string &out) {
    for (size_t pos = 0; pos <= domain.size();) {
	size_t end = min(domain.find('.', pos), domain.size());
	string_view label = domain.substr(pos, end - pos);
	vector<char32_t> cp;

	if (!utf8decode(label, cp))
	    return false;
	if (ranges::all_of(cp, [](char32_t c) { return c < 0x80; })) {
	    out += label;
	} else {
	    size_t start = out.size();

	    for (char32_t &c : cp) {
		if (c >= 'A' && c <= 'Z')
		    c += 'a' - 'A';
	    }
	    out += "xn--";
	    if (!punycode(cp, out) || out.size() - start > 63)
		return false;
	}
	if (end < domain.size())
	    out += '.';
	pos = end + 1;
    }
    return true;
}

// RFC 2047 encoded-words for UTF-8 text, folded and split on character
// boundaries so that no encoded-word exceeds 75 characters
static void encodedwords(string &out, string_view text) {
    static constexpr size_t maxbytes = 45;	// 60 base64 characters

    for (size_t pos = 0; pos < text.size();) {
	size_t end = min(pos + maxbytes, text.size());

	while (end < text.size() && end > pos + 1 &&
	    ((uchar)text[end] & 0xc0) == 0x80)
	    --end;
	if (pos)
	    out += "\r\n ";
	out += "=?UTF-8?B?";
	out += base64line(text.substr(pos, end - pos));
	out += "?=";
	pos = end;
    }
}

// RFC 2047 encode the words of unstructured header text that contain UTF-8.
// Adjacent encoded words are merged because the whitespace between them
// would be dropped by a decoder
static string encodewords(string_view text) {
    static constexpr const char *ws = " \t\r\n";
    string out;
    auto wordend = [&](size_t p) {
	size_t e = text.find_first_of(ws, p);

	return e == text.npos ? text.size() : e;
    };

    out.reserve(text.size() * 2);
    for (size_t pos = 0; pos < text.size();) {
	size_t start = text.find_first_not_of(ws, pos);

	if (start == text.npos)
	    start = text.size();
	out.append(text, pos, start - pos);
	if (start == text.size())
	    break;

	size_t end = wordend(start);

	if (!highbit8(text.substr(start, end - start))) {
	    out.append(text, start, end - start);
	    pos = end;
	    continue;
	}
	for (;;) {
	    size_t next = text.find_first_not_of(ws, end);

	    if (next == text.npos || text.substr(end, next - end).find_first_of(
		"\r\n") != text.npos)
		break;

	    size_t nend = wordend(next);

	    if (!highbit8(text.substr(next, nend - next)))
		break;
	    end = nend;
	}
	encodedwords(out, text.substr(start, end - start));
	pos = end;
    }
    return out;
}

static tstring numstr(size_t n) {
    return astringtotstring(to_string(n));
}

SMTPClient::SMTPClient(): sstrm(sock), datasent(false), lmtp(false),
    mime(false) {}

bool SMTPClient::add(vector<tstring> &v, const RFC822Addr &addrs) {
    bool ret = true;

    if (!addrs.size())
	return false;
    for (uint u = 0; u < addrs.size(); u++) {
	tstring orig = addrs.address(u), sent = orig;

	ret = rcptcmd(sent) && ret;
	v.push_back(hdraddr(addrs, u, orig, sent));
    }
    return ret;
}

bool SMTPClient::add(vector<tstring> &v, const tchar *id) {
    tstring sent(id);
    bool ret = rcptcmd(sent);

    v.push_back(std::move(sent));
    return ret;
}

void SMTPClient::attribute(const tchar *attr, const tchar *val) {
    tstring s(attr);

    s += T(": ");
    s += val;
    hdrv.emplace_back(std::move(s));
}

static tstring sasl64(const string &in) {
    return astringtotstring(base64line(in));
}

bool SMTPClient::auth(const tchar *id, const tchar *pass) {
    string aid(tchartoachar(id)), apass(tchartoachar(pass));

    if (exts.find(T("AUTH ")) == exts.npos) {
	// return "success" if server is open and does not allow auth
	return true;
    } else if (exts.find(T(" PLAIN")) != exts.npos) {
	// RFC 4616: [authzid] NUL authcid NUL passwd
	return cmd(T("AUTH PLAIN"), sasl64('\0' + aid + '\0' + apass).c_str(),
	    235);
    } else if (exts.find(T(" LOGIN")) != exts.npos) {
	return cmd(T("AUTH LOGIN"), sasl64(aid).c_str(), 334) &&
	    cmd(sasl64(apass).c_str(), nullptr, 235);
    }
    return false;
}

bool SMTPClient::cmd(const tchar *s1, const tchar *s2, int retcode) {
    string asts;

    multi.erase();
    if (fstrm) {
	multi = sts = numstr((size_t)retcode);
	return true;
    }
    if (s1) {
	const char *as1 = tchartoachar(s1);
	size_t s1len = strlen(as1);

	// prevent SMTP command injection via CR/LF in addresses
	if (strpbrk(as1, "\r\n") || (s2 && strpbrk(tchartoachar(s2), "\r\n"))) {
	    sts = T("501 5.5.2 Invalid character in command");
	    return false;
	}
	strm->write(as1, (streamsize)s1len);
	if (s2) {
	    const char *as2 = tchartoachar(s2);
	    bool colon = as1[s1len - 1] == ':';
	    bool addbracket = colon && as2[0] != '<';

	    if (addbracket)
		strm->put('<');
	    else if (!colon)
		strm->put(' ');
	    strm->write(as2, (streamsize)strlen(as2));
	    if (addbracket)
		strm->put('>');
	}
	strm->write(crlf, 2);
    }
    if (pipelined || retcode == CMD_NOREPLY) {
	// do not wait for a reply - PIPELINING, BDAT
	if (!strm->good()) {
	    sock.close();
	    sts = T("000 socket disconnect");
	    dlogd(Log::mod(T("smtp")), Log::kv(T("action"), T("disconnect")));
	    return false;
	}
	if (pipelined && retcode != CMD_NOREPLY)
	    resultsv.push_back(numstr((size_t)retcode));
	return true;
    }
    do {
	sts.erase();
	if (!sstrm) {
	    dlogd(Log::mod(T("smtp")), Log::kv(T("status"), T("closed")));
	    return false;
	} else if (!getline(sstrm, asts)) {
	    sock.close();
	    sts = T("000 socket disconnect");
	    dlogd(Log::mod(T("smtp")), Log::kv(T("action"), T("disconnect")));
	    return false;
	}
	sts = astringtotstring(asts);
	if (sts.length() < 3 || (sts.length() > 3 && sts[3] != '-' && sts[3] !=
	    ' ')) {
	    dlogd(Log::mod(T("smtp")), Log::kv(T("data"), T("invalid")),
		Log::kv(T("reply"), sts.c_str()));
	    return false;
	}
	auto trim = sts.find_last_not_of(T(" \t\r\n"));
	if (trim != sts.npos)
	    sts.erase(trim + 1);
	if (!multi.empty())
	    multi += '\n';
	if (sts.length() > 4)
	    multi += sts.substr(4);
	dlogt(Log::mod(T("smtp")), Log::kv(T("expected"), retcode),
	    Log::kv(T("reply"), sts.c_str()));
    } while (sts[3] == '-');
    return code() == retcode;
}

bool SMTPClient::connect(const Sockaddr &addr, uint to) {
    bool ret;

    if (fstrm)
	return true;
    sock.close();
    if (!addr.port()) {
	Sockaddr tmp(addr);

	tmp.port(25);
	ret = sock.connect(tmp, to);
    } else {
	ret = sock.connect(addr, to);
    }
    if (!ret) {
	sts = T("000 socket connect failed: ") + sock.errstr();
	sock.close();
	return false;
    }
    sock.nodelay(true);
    exts.erase();
    ext_chunking = ext_smtputf8 = false;
    timeout(3 * 60 * 1000, 5 * 60 * 1000);
    sstrm.clear();
    sstrm.rdbuf()->str(nullptr, 4096);
    return cmd(nullptr, nullptr, 220);
}

bool SMTPClient::ehlo(const tchar *domain) {
    if (!domain)
	domain = Sockaddr::hostname().c_str();
    if (cmd(T("EHLO"), domain)) {
	// skip the greeting line (npos + 1 == 0 when there is only one line)
	exts = multi.substr(multi.find('\n') + 1);
	ext_chunking = exts_find(T("CHUNKING"));
	ext_smtputf8 = exts_find(T("SMTPUTF8"));
	dlogd(Log::mod(T("smtp")), Log::cmd(T("ehlo")), Log::kv(T("exts"),
	    exts), Log::kv(T("chunking"), ext_chunking), Log::kv(T("smtputf8"),
	    ext_smtputf8));
	return true;
    } else {
	return false;
    }
}

bool SMTPClient::from(const tchar *id, const tchar *parms) {
    tstring sent(id), s;

    tov.clear();
    ccv.clear();
    bccv.clear();
    hdrv.clear();
    resultsv.clear();
    sub.erase();
    frm.erase();
    strm->flush();
    strm->clear();
    datasent = false;
    mime = false;
    if (!envarg(T("from"), sent, parms, true, true, s))
	return false;
    frm = sent.empty() ? T("<>") : sent;
    return cmd(T("MAIL FROM:"), s.c_str());
}

bool SMTPClient::xclient(const tchar *xclient_cmd) {
    return cmd(T("XCLIENT"), xclient_cmd);
}

bool SMTPClient::from(const RFC822Addr &addr, const tchar *parms) {
    if (!addr.size())
	return false;

    tstring orig = addr.address();
    bool ret = from(orig.c_str(), parms);

    frm = hdraddr(addr, 0, orig, frm.empty() ? orig : frm);
    return ret;
}

bool SMTPClient::helo(const tchar *domain) {
    exts.erase();
    ext_chunking = ext_smtputf8 = false;
    return cmd(T("HELO"), domain ? domain : Sockaddr::hostname().c_str());
}

bool SMTPClient::lhlo(const tchar *domain) {
    if (cmd(T("LHLO"), domain ? domain : Sockaddr::hostname().c_str())) {
	exts = multi;
	ext_chunking = exts_find(T("CHUNKING"));
	ext_smtputf8 = exts_find(T("SMTPUTF8"));
	lmtp = true;
	return true;
    } else {
	return false;
    }
}

bool SMTPClient::quit() {
    bool ret = cmd(T("QUIT"), nullptr, 221);

    sock.close();
    return ret || code() == 421;
}

bool SMTPClient::rcpt(const tchar *id) {
    return rcpt(RFC822Addr(id, true));
}

bool SMTPClient::rcpt(const RFC822Addr &addr) {
    if (!addr.size())
	return false;

    tstring id = addr.address();

    return rcptcmd(id);
}

// id is replaced with the address sent to the server
bool SMTPClient::rcptcmd(tstring &id) {
    return downgrade(T("rcpt"), id) && cmd(T("RCPT TO:"), id.c_str());
}

// Without server SMTPUTF8 support an internationalized domain is IDNA encoded.
// A UTF-8 local part cannot be encoded so the address is rejected
bool SMTPClient::downgrade(const tchar *c, tstring &id) {
    if (canutf8() || !highbit(id))
	return true;

    RFC821Addr a(id.c_str(), true);
    string puny;

    if (!a.error().empty()) {
	sts = T("501 5.1.3 Invalid address");
    } else if (highbit(a.local())) {
	sts = T("550 5.6.7 SMTPUTF8 required but unavailable");
    } else if (!idna(tstringtoastring(a.domain()), puny)) {
	sts = T("501 5.1.2 Invalid internationalized domain name");
    } else {
	bool brkt = id[0] == '<';

	a.setDomain(astringtotstring(puny).c_str());
	id = a.address();
	if (brkt)
	    id = '<' + id + '>';
	dlogt(Log::mod(T("smtp")), Log::cmd(c), Log::kv(T("downgrade"), id));
	return true;
    }
    dlogd(Log::mod(T("smtp")), Log::cmd(c), Log::kv(T("id"), id),
	Log::kv(T("exts"), exts), Log::status(sts));
    return false;
}

// build a MAIL FROM / VRFY argument: [<]id[>] [parms] [SMTPUTF8]
// id is replaced with the address sent to the server. SMTPUTF8 is always
// requested if available when always is set so the headers and body that
// follow do not have to be known in advance
bool SMTPClient::envarg(const tchar *c, tstring &id, const tchar *parms,
    bool brkt, bool always, tstring &arg) {
    static constexpr tstring_view token = T("SMTPUTF8");
    static const auto eq = [](tchar a, tchar b) {
	return totupper(a) == totupper(b);
    };
    bool hasparm = !ranges::search(tstring_view(parms ? parms : T("")), token,
	eq).empty();

    if (hasparm && !canutf8()) {
	sts = T("550 5.6.7 SMTPUTF8 required but unavailable");
	dlogd(Log::mod(T("smtp")), Log::cmd(c), Log::kv(T("exts"), exts),
	    Log::status(sts));
	return false;
    }
    if (!downgrade(c, id))
	return false;
    if (!brkt || (!id.empty() && id[0] == '<')) {
	arg = id;
    } else {
	arg = '<';
	arg += id;
	arg += '>';
    }
    if (parms && *parms) {
	arg += ' ';
	arg += parms;
    }
    // an address is only still UTF-8 if the server supports SMTPUTF8
    if ((always || highbit(id)) && canutf8() && !hasparm)
	arg += T(" SMTPUTF8");
    dlogt(Log::mod(T("smtp")), Log::cmd(c), Log::kv(T("arg"), arg));
    return true;
}

// header text - without SMTPUTF8 any UTF-8 is RFC 2047 encoded
string SMTPClient::hdrtext(const tchar *s) const {
    string a(tchartoachar(s));

    return canutf8() || !highbit8(a) ? a : encodewords(a);
}

// header form of an envelope address: the address matches the (possibly
// downgraded) envelope address and without SMTPUTF8 a UTF-8 display name is
// RFC 2047 encoded
tstring SMTPClient::hdraddr(const RFC822Addr &addr, uint u, const tstring &orig,
    const tstring &sent) const {
    tstring phrase = addr.phrase(u);

    if (!canutf8() && highbit(phrase)) {
	string enc;

	encodedwords(enc, tstringtoastring(phrase));
	return astringtotstring(enc) + ' ' + sent;
    }

    tstring hdr = addr.address(u, true);

    if (sent != orig)
	hdr.replace(hdr.size() - orig.size(), orig.size(), sent);
    return hdr;
}

bool SMTPClient::vrfy(const tchar *id, const tchar *parms) {
    return vrfy(RFC822Addr(id, true), parms);
}

bool SMTPClient::vrfy(const RFC822Addr &addr, const tchar *parms) {
    tstring id, arg;

    pipelined = false;
    if (!addr.size())
	return false;
    id = addr.address(0, false, false);
    return envarg(T("vrfy"), id, parms, false, false, arg) &&
	cmd(T("VRFY"), arg.c_str());
}

bool SMTPClient::data(const void *start, size_t sz, bool dotstuff) {
    if (!datasent) {
	if (!startdata())
	    return false;
	datasent = true;
    }
    if (!start || !sz) {
	return true;
    } else if (dotstuff) {
	return stuff(start, sz);
    } else {
	strm->write((const char *)start, (streamsize)sz);
	strm->write(crlf, 2);
	return strm->good();
    }
}

bool SMTPClient::data(bool m, const tchar *txt) {
    static atomic nextmid(((uint64_t)seconds() << 18) ^ uticks());
    char buf[64];
    char *encbuf;
    size_t encbufsz;
    uint64_t mid = nextmid++;
    time_t now = seconds();
    pid_t pid = getpid();
    tm tmbuf{};

    mime = m;
    if (!startdata())
	return false;
    memcpy(buf, &pid, 4);
    memcpy(buf + 4, &mid, 8);
    if (!base64encode(buf, 12, encbuf, encbufsz))
	return false;
    encbuf[encbufsz - 2] = '\0';
    *strm << "Message-ID: <" << encbuf << '@' <<
	tstringtoastring(Sockaddr::hostname()) << '>' << crlf;
    delete [] encbuf;
    if (localtime_r(&now, &tmbuf) == nullptr)
	return false;
#ifdef _WIN32
    const long gmtoff = -_timezone + (tmbuf.tm_isdst > 0 ? 3600L : 0L);
#else
    const long gmtoff = tmbuf.tm_gmtoff;
#endif
    const auto off_min = (int)(gmtoff / 60);
    *strm << "Date: " << format("{:%a, %d %b %Y %H:%M:%S}",
	chrono::system_clock::from_time_t(now) +
	chrono::seconds(gmtoff)) << ' ' << format("{:+03d}{:02d}",
	off_min / 60, abs(off_min % 60)) << crlf;
    *strm << "From: " << tstringtoastring(frm) << crlf;
    recip(T("To: "), tov);
    recip(T("Cc: "), ccv);
    *strm << "Subject: " << hdrtext(sub.c_str()) << crlf;
    for (auto it = hdrv.begin(); it != hdrv.end(); ++it)
	*strm << hdrtext(it->c_str()) << crlf;

    // Only this text is scanned - the caller of the raw data() overloads is
    // responsible for content that is valid for the server
    string_view body;
    string enc;
    const char *cte = nullptr;
#ifdef UNICODE
    string as;

    if (txt) {
	as = wchartoastring(txt);
	body = as;
    }
#else
    if (txt)
	body = txt;
#endif

    size_t hicnt = (size_t)ranges::count_if(body, [](char c) {
	return (uchar)c > 0x7f;
    });

    if (hicnt) {
	if (canutf8()) {
	    // SMTPUTF8 implies 8BITMIME
	    cte = "8bit";
	} else if (hicnt * 4 > body.size()) {
	    char *out;
	    size_t outsz;

	    if (!base64encode(body.data(), body.size(), out, outsz))
		return false;
	    enc.assign(out, outsz);
	    delete [] out;
	    cte = "base64";
	} else {
	    char *out;
	    size_t outsz;

	    qpencode(body.data(), body.size(), out, outsz);
	    enc.assign(out, outsz);
	    delete [] out;
	    cte = "quoted-printable";
	}
	if (!enc.empty())
	    body = enc;
    }
    if (mime) {
	thread_local mt19937 rng(random_device {}());
	thread_local uniform_int_distribution<uint> dist;

	sprintf(buf, "--%x%x%x%x", dist(rng), dist(rng), dist(rng), dist(rng));
	boundary = buf;
	*strm << "MIME-Version: 1.0" << crlf;
	*strm << "Content-Type: multipart/mixed; boundary=\"" << boundary <<
	    '"' << crlf << crlf <<
	    "This is a multi-part message in MIME format." << crlf << crlf;
	if (txt) {
	    *strm << "--" << boundary << crlf;
	    *strm << "Content-Type: text/plain" << (cte ? "; charset=utf-8" :
		"") << crlf;
	    if (cte)
		*strm << "Content-Transfer-Encoding: " << cte << crlf;
	    strm->write(crlf, 2);
	}
    } else {
	if (cte) {
	    *strm << "MIME-Version: 1.0" << crlf <<
		"Content-Type: text/plain; charset=utf-8" << crlf <<
		"Content-Transfer-Encoding: " << cte << crlf;
	}
	strm->write(crlf, 2);
    }
    if (txt)
	stuff(body.data(), body.size());
    // enddata() closes the multipart so attachments can follow the text
    return strm->good();
}

bool SMTPClient::data(const void *p, uint sz, const tchar *type,
    const tchar *desc, const tchar *encoding, const tchar *disp,
    const tchar *name) {
    if (mime)
	*strm << "--" << boundary << crlf;
    if (type && *type)
	*strm << "Content-Type: " << tchartoachar(type) << crlf;
    if (desc && *desc)
	*strm << "Content-Description: " << hdrtext(desc) << crlf;
    if (encoding && *encoding)
	*strm << "Content-Transfer-Encoding: " << tchartoachar(encoding) <<
	    crlf;
    *strm << "Content-Disposition: " << tchartoachar(disp && *disp ? disp :
	T("inline"));
    if (name && *name) {
	string aname(tchartoachar(name));

	if (canutf8() || !highbit8(aname)) {
	    *strm << "; filename=" << aname;
	} else {
	    // RFC 2231 extended parameter value
	    static constexpr const char hex[] = "0123456789ABCDEF";

	    *strm << "; filename*=UTF-8''";
	    for (char ch : aname) {
		uchar c = (uchar)ch;

		if (isalnum(c) || strchr("!#$&+-.^_`|~", c)) {
		    strm->put(ch);
		} else {
		    strm->put('%');
		    strm->put(hex[c >> 4]);
		    strm->put(hex[c & 15]);
		}
	    }
	}
    }
    *strm << crlf << crlf;
    stuff(p, sz);
    return strm->good();
}

// send DATA and, if pipelining, validate the queued replies
bool SMTPClient::startdata() {
    if (!cmd(T("DATA"), nullptr, 354))
	return false;
    if (!pipelined)
	return true;
    pipelined = false;
    for (auto &r : resultsv) {
	string asts;

	do {
	    if (!getline(sstrm, asts)) {
		sock.close();
		sts = T("000 socket disconnect");
		dlogd(Log::mod(T("smtp")), Log::kv(T("action"),
		    T("disconnect")));
		return false;
	    }
	    sts = astringtotstring(asts);
	    auto trim = sts.find_last_not_of(T(" \t\r\n"));
	    if (trim != sts.npos)
		sts.erase(trim + 1);
	} while (sts.length() > 3 && sts[3] == '-');
	if (sts.compare(0, 3, r)) {
	    dlogd(Log::mod(T("smtp")), Log::kv(T("expected"), r),
		Log::kv(T("reply"), sts));
	    return false;
	}
	r = sts;
    }
    return code() == 354;
}

bool SMTPClient::bdat(const void *start, size_t sz, bool last) {
    tstring c(T("BDAT ") + numstr(sz));

    if (last)
	c += T(" LAST");
    if (!ext_chunking && !fstrm) {
	sts = T("550 5.6.7 CHUNKING required but unavailable");
	dlogd(Log::mod(T("smtp")), Log::cmd(c), Log::kv(T("exts"), exts),
	    Log::status(sts));
	return false;
    }
    if (!cmd(c.c_str(), nullptr, CMD_NOREPLY))
	return false;
    if (start && sz)
	strm->write((const char *)start, (streamsize)sz);
    return cmd(nullptr, nullptr, 250);
}

bool SMTPClient::enddata() {
    if (mime)
	*strm << "--" << boundary << "--" << crlf;
    return cmd(T("."));
}

void SMTPClient::recip(const tchar *hdr, const vector<tstring> &v) {
    if (v.empty())
	return;
    *strm << tchartoachar(hdr);
    for (auto it = v.begin(); it != v.end(); ++it) {
	const tstring &s = *it;

	if (it != v.begin())
	    *strm << ",\r\n\t";
	*strm << tstringtoachar(s);
    }
    strm->write(crlf, 2);
}

// Next position at or after p that needs fixing: a '.' at the start of a line
// or an LF that does not follow a CR. start is the start of a line
static const char *stuffscan(const char *p, const char *end,
    const char *start) {
#ifdef __AVX2__
    if (p == start && p < end) {
	if (*p == '.' || *p == '\n')
	    return p;
	++p;
    }
    const __m256i cr = _mm256_set1_epi8('\r');
    const __m256i dot = _mm256_set1_epi8('.');
    const __m256i lf = _mm256_set1_epi8('\n');

    for (; end - p >= 32; p += 32) {
	__m256i v = _mm256_loadu_si256((const __m256i *)p);
	__m256i prev = _mm256_loadu_si256((const __m256i *)(p - 1));
	__m256i bare = _mm256_andnot_si256(_mm256_cmpeq_epi8(prev, cr),
	    _mm256_cmpeq_epi8(v, lf));
	__m256i bol = _mm256_and_si256(_mm256_cmpeq_epi8(prev, lf),
	    _mm256_cmpeq_epi8(v, dot));
	uint m = (uint)_mm256_movemask_epi8(_mm256_or_si256(bare, bol));

	if (m)
	    return p + __builtin_ctz(m);
    }
#endif
    while (p < end) {
	if (*p == '.' && (p == start || p[-1] == '\n'))
	    return p;

	const char *nl = (const char *)memchr(p, '\n', (size_t)(end - p));

	if (!nl)
	    break;
	if (nl == start || nl[-1] != '\r')
	    return nl;
	p = nl + 1;
    }
    return end;
}

bool SMTPClient::stuff(const void *data, size_t sz) {
    const char *start = (const char *)data;
    const char *end = start + sz;
    const char *p = start, *pp = start;

    if (!sz)
	return strm->good();
    while ((p = stuffscan(p, end, start)) != end) {
	strm->write(pp, p - pp);
	strm->write(*p == '.' ? ".." : crlf, 2);
	pp = ++p;
    }
    strm->write(pp, end - pp);
    if (end[-1] != '\n')
	strm->write(crlf, 2);
    return strm->good();
}

static constexpr const tchar *NonASCII = T("Non-ASCII character");

// a local part is quoted unless it is dot-atom text: RFC 5322 atext (alnum and
// !#$%&'*+-/=?^_`{|}~) or UTF-8 separated by single interior dots
static void append_local(tstring &out, tstring_view s) {
    static constexpr tstring_view atext = T("!#$%&'*+-/=?^_`{|}~");
    bool quote = false;

    for (size_t i = 0; i < s.size() && !quote; ++i) {
	tchar c = s[i];

	if (c == '.')
	    quote = i == 0 || i + 1 == s.size() || s[i + 1] == '.';
	else
	    quote = !(isalnum((tuchar)c) || nonascii(c) ||
		atext.find(c) != atext.npos);
    }
    if (!quote) {
	out += s;
	return;
    }
    out += '"';
    for (tchar c : s) {
	if (c == '"' || c == '\\')
	    out += '\\';
	out += c;
    }
    out += '"';
}

void RFC821Addr::parseaddr(const tchar *&input, bool smtputf8) {
    addr.clear();
    domain_buf.clear();
    err.clear();
    local_part.clear();
    utf8 = false;
    while (istspace(*input))
	++input;
    addr.reserve(tstrlen(input));
    if (!scan(input, smtputf8) || !split()) {
	addr.clear();
	domain_buf.clear();
	local_part.clear();
    }
}

// pass 1: copy the address into addr, dropping comments and angle brackets
bool RFC821Addr::scan(const tchar *&input, bool smtputf8) {
    uint angledepth = 0;
    size_t anglelast = tstring::npos;
    // high bit characters are only legal with SMTPUTF8
    auto bad = [&](tchar c) {
	if (!nonascii(c) || smtputf8)
	    return false;
	err = NonASCII;
	return true;
    };

    for (;;) {
	tchar c = *input++;

	if (bad(c))
	    return false;
	switch (c) {
	default: {
	    // append the run of ordinary characters at once
	    size_t n = tstrcspn(input, T("\"()<>\\ \t\v\f\r\n"));

	    if (!smtputf8 && highbit(tstring_view(input, n))) {
		err = NonASCII;
		return false;
	    }
	    addr += c;
	    addr.append(input, n);
	    input += n;
	    break;
	}
	case '"':
	    for (;;) {
		addr += c;
		c = *input++;
		if (c == '\\') {
		    addr += c;
		    c = *input++;
		} else if (c == '"') {
		    addr += c;
		    break;
		}
		if (bad(c))
		    return false;
		if (!c) {
		    err = T("Unbalanced '\"'");
		    return false;
		}
		if (c == '\r' || c == '\n') {
		    err = T("Invalid character");
		    return false;
		}
	    }
	    break;
	case '(':
	    for (uint depth = 1; depth;) {
		c = *input++;
		if (c == '(') {
		    ++depth;
		} else if (c == ')') {
		    --depth;
		} else if (c == '\\') {
		    c = *input++;
		}
		if (bad(c))
		    return false;
		if (!c) {
		    err = T("Unbalanced '('");
		    return false;
		}
	    }
	    addr += ' ';
	    break;
	case ')':
	    err = T("Unbalanced ')'");
	    return false;
	case '<':
	    addr.clear();
	    anglelast = tstring::npos;
	    ++angledepth;
	    break;
	case '>':
	    if (!angledepth--) {
		err = T("Unbalanced '>'");
		return false;
	    }
	    if (anglelast == tstring::npos)
		anglelast = addr.length();
	    break;
	case '\\':
	    c = *input++;
	    if (bad(c))
		return false;
	    if (c && !istspace(c)) {
		addr += '\\';
		addr += c;
		break;
	    }
	    [[fallthrough]];
	case ' ':
	case '\t':
	case '\v':
	case '\f':
	case '\r':
	case '\n':
	    if (c && angledepth) {
		addr += ' ';
		break;
	    }
	    [[fallthrough]];
	case '\0':
	    --input;
	    if (angledepth) {
		err = T("Unbalanced '<'");
		return false;
	    }
	    if (anglelast != tstring::npos)
		addr.erase(anglelast);
	    return true;
	}
    }
}

// pass 2: split addr into local part and domain, stripping any source route
bool RFC821Addr::split() {
    bool saw_colon = false;

    for (size_t pos = 0; pos < addr.length();) {
	tchar c = addr[pos++];

	switch (c) {
	case '@':
	    if (!parsedomain(pos))
		return false;
	    if (pos == addr.length())
		continue;
	    switch (addr[pos++]) {
	    case '@':
		err = T("Invalid route address");
		return false;
	    case ',':
		if (!local_part.empty()) {
		    err = T("Invalid route address");
		    return false;
		}
		[[fallthrough]];
	    case ':':
		// Strip route-address
		local_part.clear();
		domain_buf.clear();
		continue;
	    default:
		err = T("Invalid domain");
		return false;
	    }
	case '"':
	    if (pos == addr.length()) {
		err = T("Unbalanced '\"'");
		return false;
	    }
	    while ((c = addr[pos++]) != '"') {
		if (pos != addr.length() && c == '\\')
		    c = addr[pos++];
		if (pos == addr.length()) {
		    err = T("Unbalanced '\"'");
		    return false;
		}
		local_part += c;
	    }
	    continue;
	case '\\':
	    if (pos != addr.length())
		local_part += addr[pos++];
	    continue;
	case ' ':
	case '.': {
	    bool saw_dot = (c == '.');

	    while (pos < addr.length() &&
		((c = addr[pos]) == ' ' || (!saw_dot && c == '.'))) {
		if (c == '.')
		    saw_dot = true;
		++pos;
	    }
	    if (saw_dot || (!local_part.empty() && pos < addr.length() &&
		addr[pos] != '@'))
		local_part += '.';
	    continue;
	}
	case ';':
	    if (saw_colon) {
		err = T("List:; syntax illegal");
		return false;
	    }
	    local_part += c;
	    continue;
	case ',':
	    err = T("Invalid route address");
	    return false;
	case ':':
	    saw_colon = true;
	    local_part.clear();
	    continue;
	default: {
	    // append the run of ordinary characters at once
	    size_t end = addr.find_first_of(T("@\"\\ .;,:"), pos);

	    if (end == tstring::npos)
		end = addr.length();
	    local_part += c;
	    local_part.append(addr, pos, end - pos);
	    pos = end;
	    continue;
	}
	}
    }
    if (local_part.empty()) {
	err = T("User address required");
	return false;
    }
    make_address();
    return true;
}

bool RFC821Addr::parsedomain(size_t &pos) {
    bool sawspace = false;
    size_t esc = 0;			// end of the last escaped character
    auto finish = [&]() {
	while (!domain_buf.empty() && domain_buf.size() > esc &&
	    domain_buf.back() == '.')
	    domain_buf.pop_back();
	if (domain_buf.empty()) {
	    err = T("Invalid domain");
	    return false;
	}
	return true;
    };

    while (pos < addr.length()) {
	tchar c = addr[pos++];

	switch (c) {
	case '.':
	    if (sawspace) {
		sawspace = false;
		continue;
	    }
	    if (domain_buf.empty() || domain_buf.back() == '.')
		return finish();
	    domain_buf += c;
	    continue;
	case ' ':
	    if (!domain_buf.empty() && domain_buf.back() != '.') {
		domain_buf += '.';
		sawspace = true;
	    }
	    continue;
	case '[':
	    sawspace = false;
	    domain_buf += c;
	    for (;;) {
		if (pos == addr.length()) {
		    err = T("Invalid domain");
		    return false;
		}
		c = addr[pos++];
		if (c == ']') {
		    domain_buf += c;
		    break;
		}
		if (c == ' ')		// comment placeholder
		    continue;
		if (c == '\\') {
		    if (pos == addr.length()) {
			err = T("Invalid domain");
			return false;
		    }
		    c = addr[pos++];
		    if (c == '\\' || c == '[' || c == ']')
			domain_buf += '\\';
		}
		domain_buf += c;
	    }
	    continue;
	case '\\':
	    sawspace = false;
	    if (pos == addr.length()) {
		err = T("Invalid domain");
		return false;
	    }
	    domain_buf += '\\';
	    domain_buf += addr[pos++];
	    esc = domain_buf.size();
	    continue;
	case ':':
	case ',':
	case '@':
	case ';':
	    --pos;
	    return finish();
	default: {
	    size_t end = addr.find_first_of(T(".[\\:,@; "), pos);

	    if (end == tstring::npos)
		end = addr.length();
	    sawspace = false;
	    domain_buf += c;
	    domain_buf.append(addr, pos, end - pos);
	    pos = end;
	    continue;
	}
	}
    }
    return finish();
}

void RFC821Addr::setDomain(const tchar *domain) {
    domain_buf = domain;
    make_address();
}

void RFC821Addr::setLocal(const tchar *local) {
    local_part = local;
    make_address();
}

void RFC821Addr::make_address() {
    addr.clear();
    append_local(addr, local_part);
    if (!domain_buf.empty()) {
	addr += '@';
	addr += domain_buf;
    }
    // only the mailbox and domain determine whether SMTPUTF8 is required
    utf8 = highbit(local_part) || highbit(domain_buf);
}

static tstring_view view(const tchar *p) {
    return p ? tstring_view(p) : tstring_view();
}

uint RFC822Addr::parse(const tchar *addrs, bool smtputf8) {
    size_t len = tstrlen(addrs) + 1;
    tchar *s;
    auto append = [this](const tchar *p, const tchar *r, const tchar *l,
	const tchar *d) {
	entries.push_back({ view(d), view(l), view(p), view(r) });
    };
    // flag UTF-8 in a mailbox and, unless allowed, mask it
    auto mailbox = [&](tchar *p, bool hi) {
	if (!hi)
	    return;
	utf8 = true;
	if (!smtputf8) {
	    for (; *p; ++p) {
		if (nonascii(*p))
		    *p = '=';
	    }
	}
    };

    // release the previous parse and copy the input into the arena
    entries = std::pmr::vector<Entry>(&arena);
    arena.release();
    s = (tchar *)arena.allocate(len * sizeof (tchar), alignof(tchar));
    memcpy(s, addrs, len * sizeof (tchar));
    utf8 = false;
    for (int tok = ' '; tok;) {
	tchar *d, *m, *n, *phrase, *r;
	bool hi = false;

	// display names and comments may always contain UTF-8
	tok = parse_phrase(s, phrase, T(",@<;:"), true, hi);
	switch (tok) {			// NOLINT NOSONAR
	case ',':
	case '\0':
	case ';':
	    // include local mbox
	    if (*phrase) {
		mailbox(phrase, hi);
		append(nullptr, nullptr, phrase, nullptr);
	    }
	    continue;
	case ':':
	    // ignore group prefix and only return real addresses
	    continue;
	case '@':
	    mailbox(phrase, hi);
	    tok = parse_domain(s, d, n, smtputf8);
	    append(n, nullptr, phrase, d);
	    continue;
	case '<':
	    hi = false;			// ignore display name
	    tok = parse_phrase(s, m, T("@>"), smtputf8, hi);
	    if (tok == '@') {
		r = nullptr;
		if (!*m) {
		    *--s = '@';
		    tok = parse_route(s, r, smtputf8);
		    if (tok != ':') {
			append(phrase, r, T(""), T(""));
			while (tok && tok != '>')
			    tok = (int)(uchar)*s++;
			continue;
		    }
		    hi = false;
		    tok = parse_phrase(s, m, T("@>"), smtputf8, hi);
		    if (tok != '@') {
			utf8 |= hi;
			append(phrase, r, m, T(""));
			continue;
		    }
		}
		utf8 |= hi;
		tok = parse_domain(s, d, n, smtputf8);
		append(phrase, r, m, d);
		while (tok && tok != '>')
		    tok = (int)(uchar)*s++;
		continue;		// effectively inserts a comma
	    }
	    utf8 |= hi;
	    append(phrase, nullptr, m, T(""));
	}
    }
    return (uint)entries.size();
}

// copy a phrase or mailbox - hi is set if any high bit characters were seen
int RFC822Addr::parse_phrase(tchar *&in, tchar *&phrase, const tchar
    *specials, bool smtputf8, bool &hi) {
    tchar c;
    tchar *dst, *src = in;
    auto put = [&](tchar ch) {
	if (nonascii(ch)) {
	    hi = true;
	    if (!smtputf8)
		ch = '=';
	}
	*dst++ = ch;
    };

    skip_whitespace(src);
    phrase = dst = src;
    for (;;) {
	if (skip_whitespace(src))
	    *dst++ = ' ';
	if (*src == '\n' && src[1] != ' ' && src[1] != '\t')
	    c = '\0';
	else
	    c = *src++;
	if (c == '\"') {
	    while ((c = *src) != 0 && !(c == '\n' && src[1] != ' ' && src[1] !=
		'\t')) {
		src++;
		if (c == '\"')
		    break;
		if (c == '\\') {
		    if ((c = *src) == 0)
			break;
		    src++;
		}
		// bare CR/LF would allow header/command injection
		if (c != '\r' && c != '\n')
		    put(c);
	    }
	} else if (!c || tstrchr(specials, c)) {
	    if (dst > phrase && dst[-1] == ' ')
		dst--;
	    *dst = '\0';
	    in = src;
	    break;
	} else {
	    put(c);
	}
    }
    return (int)(uint)c;
}

int RFC822Addr::parse_domain(tchar *&in, tchar *&dom, tchar *&cmt,
    bool smtputf8) {
    tchar c;
    tchar *dst;
    tchar *src = in;

    cmt = nullptr;
    skip_whitespace(src);
    dom = dst = src;
    for (;;) {
	if (*src == '\n' && src[1] != ' ' && src[1] != '\t')
	    c = '\0';
	else
	    c = *src++;
	if (nonascii(c)) {
	    utf8 = true;
	    *dst++ = smtputf8 ? c : '=';
	    cmt = nullptr;
	} else if (istalnum(c) || c == '-' || c == '_' || c == '[' ||
	    c == ']' || c == ':') {
	    *dst++ = c;
	    cmt = nullptr;
	} else if (c == '.') {
	    if (dst > dom && dst[-1] != '.')
		*dst++ = c;
	    cmt = nullptr;
	} else if (c == '(') {
	    tchar *cdst;
	    uint cnt = 1;

	    cmt = cdst = src;
	    while (cnt && (c = *src) != 0 &&
		!(c == '\n' && src[1] != ' ' && src[1] != '\t')) {
		src++;
		if (c == '(')
		    cnt++;
		else if (c == ')')
		    cnt--;
		else if (c == '\\' && (c = *src) != 0)
		    src++;
		if (cnt)
		    *cdst++ = c;
	    }
	    *cdst = '\0';
	} else if (!istspace(c)) {
	    if (dst > dom && dst[-1] == '.')
		dst--;
	    *dst = '\0';
	    in = src;
	    break;
	}
    }
    return (int)(uint)c;
}

int RFC822Addr::parse_route(tchar *&in, tchar *&rte, bool smtputf8) {
    tchar c;
    tchar *dst, *src = in;

    skip_whitespace(src);
    rte = dst = src;
    for (;;) {
	skip_whitespace(src);
	c = *src++;
	if (nonascii(c)) {
	    utf8 = true;
	    *dst++ = smtputf8 ? c : '=';
	} else if (istalnum(c) || c == '-' || c == '[' || c == ']' ||
	    c == ',' || c == '@') {
	    *dst++ = c;
	} else if (c == '.') {
	    if (dst > rte && dst[-1] != '.')
		*dst++ = c;
	} else {
	    while (dst > rte &&
		(dst[-1] == '.' || dst[-1] == ',' || dst[-1] == '@'))
		dst--;
	    *dst = '\0';
	    in = src;
	    break;
	}
    }
    return (int)(uint)c;
}

bool RFC822Addr::skip_whitespace(tchar *&in) {
    tchar *s = in;

    for (tchar c; (c = *s) != 0; ++s) {
	if (c == '(') {
	    uint cmt = 1;

	    ++s;
	    while (cmt && (c = *s) != 0 && !(c == '\n' && s[1] != ' ' && s[1] !=
		'\t')) {
		++s;
		if (c == '\\' && *s)
		    ++s;
		else if (c == '(')
		    ++cmt;
		else if (c == ')')
		    --cmt;
	    }
	    --s;
	} else if (!istspace(c) || (c == '\n' && s[1] != ' ' && s[1] != '\t')) {
	    break;
	}
    }
    if (s == in)
	return false;
    in = s;
    return true;
}

tstring RFC822Addr::address(uint u, bool n, bool b) const {
    tstring s;

    if (u >= entries.size())
	return s;

    const Entry &e = entries[u];

    s.reserve(e.phrase.size() + e.route.size() + e.local.size() +
	e.domain.size() + 8);
    if (n && !e.phrase.empty()) {
	s += '"';
	for (tchar c : e.phrase) {
	    // phrases may come from comments - never emit bare CR/LF
	    if (c == '\r' || c == '\n')
		continue;
	    if (c == '"' || c == '\\')
		s += '\\';
	    s += c;
	}
	s += T("\" ");
    }
    if (n || b)
	s += '<';
    if (!e.route.empty()) {
	s += e.route;
	s += ':';
    }
    append_local(s, e.local);
    if (!e.domain.empty()) {
	s += '@';
	s += e.domain;
    }
    if (n || b)
	s += '>';
    return s;
}
