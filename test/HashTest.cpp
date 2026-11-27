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
#include <atomic>
#include <chrono>
#include <iomanip>
#include <fstream>
#include <map>
#include <thread>
#include <unordered_map>
#include <vector>
#include "LRUCache.h"
#include "ResourcePool.h"
#include "Streams.h"

// insert and look up through distinct but equal keys so neither a pointer
// compare nor an address hash can pass
struct TestCacheEntry: LRUCacheEntry {
    using LRUCacheEntry::LRUCacheEntry;
};

struct GatedCacheEntry: LRUCacheEntry {	// NOSONAR: copy only gates
    using LRUCacheEntry::LRUCacheEntry;
    GatedCacheEntry(const GatedCacheEntry &other): LRUCacheEntry(other) {
	if (block.exchange(false)) {
	    started.store(true);
	    while (hold.load())
		this_thread::yield();
	}
    }

    static inline atomic block = false;
    static inline atomic hold = false;
    static inline atomic started = false;
};

struct GatedResource {
    GatedResource() {
	started.store(true);
	while (hold.load())
	    this_thread::yield();
    }

    static inline atomic hold = false;
    static inline atomic started = false;
};

struct TestResource {};

template<typename P>
concept CachePutData = requires(LRUCache<TestCacheEntry> &cache,
    TestCacheEntry &entry, P p) { cache.put(entry, p, 1); };

static_assert(CachePutData<::byte *>);
static_assert(!CachePutData<char *>);
static_assert(!CachePutData<void *>);
static_assert(!CachePutData<const ::byte *>);

template<class H, class E>
static int check_hash(const tchar *name, const tchar *key,
    const tchar *lookup, int &tests) {
    const tstring ibuf(key), lbuf(lookup);
    unordered_map<const tchar *, int, H, E> mptr;
    unordered_map<tstring, int, H, E> mstr;
    unordered_map<tstring_view, int, H, E> mview;
    int failures = 0;

    mptr[ibuf.c_str()] = mstr[ibuf] = mview[ibuf] = 1;
    tests += 3;
    if (!mptr.contains(lbuf.c_str())) {
	tcout << T("FAIL: ") << name << T(" tchar* map test\n");
	failures++;
    }
    if (!mstr.contains(lbuf)) {
	tcout << T("FAIL: ") << name << T(" tstring map test\n");
	failures++;
    }
    if (!mview.contains(tstring_view(lbuf))) {
	tcout << T("FAIL: ") << name << T(" tstring_view map test\n");
	failures++;
    }
    return failures;
}

int tmain(int argc, const tchar * const argv[]) {
    if (argc >= 2) {
	tstring arg = argv[1];

	if (arg == T("-b") || arg == T("-r")) {
	    tifstream file;

	    if (argc >= 3) {
		file.open(argv[2], ios::binary);
		if (!file.is_open()) {
		    tcout << T("ERROR: no such file\n");
		    return 2;
		}
	    }

	    tistream &is = argc >= 3 ? file : tcin;
	    vector<tchar> content{istreambuf_iterator<tchar>(is), {}};

	    tcout << (arg == T("-b") ? bernstein_hash(content.data(),
		content.size()) : rapid_hash(content.data(), content.size() *
		sizeof (tchar))) << T("\n");
	    return 0;
	}
    }

    int failures = 0;
    int tests = 0;

#define fail(msg) do { tcout << msg << T("\n"); failures++; } while (0)

    tcout << T("Testing hash and string functors...\n");
    failures += check_hash<strhash, streq>(T("strhash"), T("key"), T("key"),
	tests);
    failures += check_hash<strihash, strieq>(T("strihash"), T("Key"),
	T("kEY"), tests);
    failures += check_hash<striasciihash, strieq>(T("striasciihash"),
	T("Key"), T("kEY"), tests);
    {
	tcout << T("Testing compile-time hashing of string literals...\n");
	constexpr strhash sh;
	constexpr strihash sih;
	constexpr striasciihash sah;

	static_assert(sh(T("abc")) == sh(T("abc")),
	    "strhash must be constexpr-evaluable for string literals");
	static_assert(sih(T("ABC")) == sih(T("abc")),
	    "strihash must be constexpr-evaluable and case-insensitive");
	static_assert(sah(T("ABC")) == sah(T("abc")),
	    "striasciihash must be constexpr-evaluable and case-insensitive");
	static_assert(sh(T("abc")) != sh(T("abcd")),
	    "strhash must distinguish different-length literals");
    }
    {
	tcout << T("Testing strless functor...\n");
	map<tstring, tstring, strless> map_string;
	map_string[T("zebra")] = T("last");
	map_string[T("apple")] = T("first");
	tests++;
	auto it1 = map_string.begin();
	if (it1->first != T("apple") || it1->second != T("first"))
	    fail(T("FAIL: strless map first item test"));
	tests++;
	auto it2 = next(it1);
	if (it2->first != T("zebra") || it2->second != T("last"))
	    fail(T("FAIL: strless map second item test"));
	map<tstring_view, tstring, strless> map_view;
	tstring key1 = T("zebra");
	tstring key2 = T("apple");
	map_view[tstring_view(key1)] = T("last");
	map_view[tstring_view(key2)] = T("first");
	tests++;
	auto it3 = map_view.begin();
	if (it3->first != T("apple") || it3->second != T("first"))
	    fail(T("FAIL: strless string_view map first item test"));
	tests++;
	auto it4 = next(it3);
	if (it4->first != T("zebra") || it4->second != T("last"))
	    fail(T("FAIL: strless string_view map second item test"));
    }
    {
	tcout << T("Testing striless functor...\n");
	map<tstring, tstring, striless> map_string;
	map_string[T("Zebra")] = T("last");
	map_string[T("Apple")] = T("first");
	tests++;
	auto it1 = map_string.begin();
	if (it1->first != T("Apple") || it1->second != T("first"))
	    fail(T("FAIL: striless map first item test"));
	tests++;
	auto it2 = next(it1);
	if (it2->first != T("Zebra") || it2->second != T("last"))
	    fail(T("FAIL: striless map second item test"));
	map<tstring_view, tstring, striless> map_view;
	tstring key1 = T("Zebra");
	tstring key2 = T("Apple");
	map_view[tstring_view(key1)] = T("last");
	map_view[tstring_view(key2)] = T("first");
	tests++;
	auto it3 = map_view.begin();
	if (it3->first != T("Apple") || it3->second != T("first"))
	    fail(T("FAIL: striless string_view map first item test"));
	tests++;
	auto it4 = next(it3);
	if (it4->first != T("Zebra") || it4->second != T("last"))
	    fail(T("FAIL: striless string_view map second item test"));
	// a case-insensitive prefix must sort first
	map<tstring, tstring, striless> map_prefix;
	map_prefix[T("abcd")] = T("longer");
	map_prefix[T("ABC")] = T("shorter");
	tests++;
	auto itp1 = map_prefix.begin();
	if (itp1->first != T("ABC") || itp1->second != T("shorter"))
	    fail(T("FAIL: striless prefix ordering first item test"));
	tests++;
	auto itp2 = next(itp1);
	if (itp2->first != T("abcd") || itp2->second != T("longer"))
	    fail(T("FAIL: striless prefix ordering second item test"));
    }
    {
	tcout << T("Testing heterogeneous lookups...\n");
	unordered_map<tstring, tstring, strhash, streq> map_hetero;
	map_hetero[T("key")] = T("value");
	tests++;
	auto it1 = map_hetero.find(T("key"));
	if (it1 == map_hetero.end() || it1->second != T("value"))
	    fail(T("FAIL: Heterogeneous lookup with const char*"));
	tstring_view sv_key = T("key");
	tests++;
	if (auto it2 = map_hetero.find(sv_key); it2 == map_hetero.end() ||
	    it2->second != T("value"))
	    fail(T("FAIL: Heterogeneous lookup with string_view"));
	tests++;
	if (map_hetero.contains(tstring_view(T("nokey"))))
	    fail(T("FAIL: Negative heterogeneous lookup with string_view"));
	unordered_map<tstring, tstring, strihash, strieq> map_case_hetero;
	map_case_hetero[T("KEY")] = T("value");
	tests++;
	auto it3 = map_case_hetero.find(T("key"));
	if (it3 == map_case_hetero.end() || it3->second != T("value"))
	    fail(T("FAIL: Case-insensitive heterogeneous lookup"));
	// string_view on both sides takes the generic stringieq path
	tests++;
	if (auto it3v = map_case_hetero.find(tstring_view(T("key"))); it3v ==
	    map_case_hetero.end() || it3v->second != T("value"))
	    fail(T("FAIL: Case-insensitive heterogeneous")
		T(" lookup with string_view"));
	tests++;
	if (map_case_hetero.contains(tstring_view(T("nokey"))))
	    fail(T("FAIL: Negative case-insensitive")
		T(" heterogeneous lookup with string_view"));
	map<tstring, tstring, strless> map_ordered_hetero;
	map_ordered_hetero[T("key")] = T("value");
	tests++;
	auto it4 = map_ordered_hetero.find(T("key"));
	if (it4 == map_ordered_hetero.end() || it4->second != T("value"))
	    fail(T("FAIL: Heterogeneous lookup with ordered map"));
	// string_view on both sides takes the generic stringless path
	tests++;
	if (auto it4v = map_ordered_hetero.find(tstring_view(T("key")));
	    it4v == map_ordered_hetero.end() || it4v->second != T("value"))
	    fail(T("FAIL: Heterogeneous lookup with ordered")
		T(" map (string_view)"));
	tests++;
	if (map_ordered_hetero.contains(tstring_view(T("nokey"))))
	    fail(T("FAIL: Negative heterogeneous lookup with ordered map"));
	map<tstring, tstring, striless> map_iordered_hetero;
	map_iordered_hetero[T("Key")] = T("value");
	tests++;
	auto it5 = map_iordered_hetero.find(T("KEY"));
	if (it5 == map_iordered_hetero.end() || it5->second != T("value"))
	    fail(T("FAIL: Case-insensitive heterogeneous")
		T(" lookup with ordered map"));
	tests++;
	if (auto it5v = map_iordered_hetero.find(tstring_view(T("key")));
	    it5v == map_iordered_hetero.end() || it5v->second != T("value"))
	    fail(T("FAIL: Case-insensitive heterogeneous")
		T(" lookup with ordered map (string_view)"));
	tests++;
	if (map_iordered_hetero.contains(tstring_view(T("nokey"))))
	    fail(T("FAIL: Negative case-insensitive")
		T(" heterogeneous lookup with ordered map"));
    }
WARN_PUSH_DISABLE(-Warray-bounds)	// false positive
    // partially filled arrays must hash strlen, not N - 1
    {
	tcout << T("Testing mutable buffer keys...\n");
	tchar buf[32] = T("key");
	const tchar *bufp = buf;

	tests++;
	if (strhash()(buf) != strhash()(T("key")) || strhash()(buf) !=
	    strhash()(bufp))
	    fail(T("FAIL: strhash mutable buffer test"));
	tests++;
	if (strihash()(buf) != strihash()(T("KEY")))
	    fail(T("FAIL: strihash mutable buffer test"));
	tests++;
	if (striasciihash()(buf) != striasciihash()(T("KEY")))
	    fail(T("FAIL: striasciihash mutable buffer test"));
	unordered_map<tstring, tstring, strhash, streq> map_buf;
	map_buf[T("key")] = T("value");
	tests++;
	if (!map_buf.contains(buf))
	    fail(T("FAIL: Heterogeneous lookup with mutable buffer"));
    }
WARN_POP()
    // Every key representation must hash identically across the 4 char
    // unrolled loop boundaries
    {
	tcout << T("Testing hash consistency across key types...\n");
	static const tchar src[] = T("aBcDeFgHi");

	for (size_t len = 0; len < size(src); ++len) {
	    tstring s(src, len);
	    tstring_view sv(s);
	    const tchar *p = s.c_str();

	    tests++;
	    if (stringhash(s) != stringhash(sv) || stringhash(s) !=
		stringhash(p) || stringihash(s) != stringihash(p) ||
		stringiasciihash(sv) != stringiasciihash(p))
		fail(T("FAIL: Hash consistency for length ") << len);
	}
	tests++;
	if (stringhash(T("aBcDe")) != stringhash(tstring(T("aBcDe"))))
	    fail(T("FAIL: Literal vs tstring hash consistency"));
    }
    // ASCII folding must only touch A-Z
    {
	tcout << T("Testing ASCII case folding range...\n");
	tests++;
	if (striasciihash()(T("@")) == striasciihash()(T("`")) ||
	    strihash()(T("[")) == strihash()(T("{")))
	    fail(T("FAIL: ASCII fold outside A-Z test"));
	tests++;
	if (striasciihash()(T("A")) != striasciihash()(T("a")) ||
	    striasciihash()(T("Z")) != striasciihash()(T("z")))
	    fail(T("FAIL: ASCII fold A-Z test"));
    }
    // rapid_hash must be constexpr and match the void * runtime version for
    // every length branch
    {
	tcout << T("Testing rapid_hash...\n");
	static_assert(rapid_hash("abcdefgh", 8) != rapid_hash("abcdefgi", 8),
	    "rapid_hash must be constexpr-evaluable");
	static constexpr char data[] =
	    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	    "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	static constexpr strhash_t ct17 = rapid_hash(data, 17);
	static constexpr strhash_t ct100 = rapid_hash(data, 100);
	// rapidhash V3 Micro reference values pin every length branch
	static_assert(rapid_hash("", 0) == 0x0338dc4be2cecdaeULL &&
	    rapid_hash("abc", 3) == 0xcb475beafa9c0da2ULL &&
	    ct17 == 0x62b040278b0412a6ULL && ct100 == 0x0ffec321561ba50fULL,
	    "rapid_hash must match rapidhash V3 Micro");
	static const size_t lens[] = {
	    0, 1, 3, 4, 7, 8, 15, 16, 17, 47, 48, 49, 100
	};

	for (size_t len : lens) {
	    tests++;
	    if (rapid_hash(data, len) != rapid_hash((const void *)data, len))
		fail(T("FAIL: rapid_hash consistency for length ") << len);
	}
	tests++;
	if (ct17 != rapid_hash((const void *)data, 17) || ct100 !=
	    rapid_hash((const void *)data, 100))
	    fail(T("FAIL: rapid_hash compile-time vs runtime test"));
    }
    // bounded parsing must stop at the first non-digit like atou
    {
	tcout << T("Testing bounded integer parsing...\n");
	static const tchar *nums[] = {
	    T("0"), T("30"), T("30s"), T("1.5"), T("12345678x"),
	    T("1234567890123456789"), T(" 12"), T("-5"), T("-123456789")
	};

	for (const tchar *n : nums) {
	    size_t len = tstrlen(n);

	    tests++;
	    if (atoun<ulong>(n, len) != atou<ulong>(n) || atoin<long>(n, len) !=
		atoi<long>(n))
		fail(T("FAIL: Bounded integer parse of ") << n);
	}
    }
    // every pointer / array / string / string_view pairing must agree with
    // the std::string result for both char types
    {
	tcout << T("Testing string compare type matrix...\n");
	static const char *words[] = {
	    "", "a", "A", "abc", "ABC", "abd", "abcd", "ABCD", "Zebra", "zebra"
	};
	int bad = 0;

	auto check = [&]<typename C>(C) {
	    using S = basic_string<C>;

	    for (const char *wa : words) {
		for (const char *wb : words) {
		    S sa(wa, wa + strlen(wa)), sb(wb, wb + strlen(wb));
		    S la(sa), lb(sb);
		    C ma[16] = {}, mb[16] = {};
		    C *pa = ma, *pb = mb;
		    const C *ca = sa.c_str(), *cb = sb.c_str();
		    basic_string_view<C> va(sa), vb(sb);

		    ranges::copy(sa, ma);
		    ranges::copy(sb, mb);
		    for (auto &c : la)
			c = (C)(c >= 'A' && c <= 'Z' ? c + 32 : c);
		    for (auto &c : lb)
			c = (C)(c >= 'A' && c <= 'Z' ? c + 32 : c);

		    int rc = sa.compare(sb), ric = la.compare(lb);
		    auto sgn = [](int v) { return clamp(v, -1, 1); };
		    auto miss = [&](const auto &a, const auto &b) {
			return stringeq(a, b) == (rc == 0) &&
			    stringieq(a, b) == (ric == 0) &&
			    stringless(a, b) == (rc < 0) &&
			    sgn(stringcmp(a, b)) == sgn(rc) &&
			    sgn(stringicmp(a, b)) == sgn(ric) ? 0 : 1;
		    };

		    bad += miss(pa, pb) + miss(pa, cb) + miss(ca, pb) +
			miss(ca, cb) + miss(ma, mb) + miss(ma, cb) +
			miss(pa, mb) + miss(sa, pb) + miss(sa, mb) +
			miss(sa, cb) + miss(ca, sb) + miss(ma, sb) +
			miss(sa, sb) + miss(va, vb) + miss(sa, vb) +
			miss(va, sb) + miss(ca, vb) + miss(va, cb) +
			miss(ma, vb) + miss(va, mb) + miss(pa, vb) +
			miss(va, pb);
		}
	    }
	};

	check(char {});
	check(wchar_t {});
	tests++;
	if (bad)
	    fail(T("FAIL: string compare type matrix, ") << bad << T(" bad"));
    }
    {
	tcout << T("Testing LRU cache ownership and expiration...\n");
	static constexpr char key[] = "cache key";
	LRUCache<TestCacheEntry> cache(64, 0);
	TestCacheEntry entry(key, sizeof (key) - 1);
	::byte *data = new ::byte[4] { 1, 2, 3, 4 };

	tests++;
	if (!cache.put(entry, data, 4) ||
	    cache.get(key, sizeof (key) - 1).value().get() != data)
	    fail(T("FAIL: LRU cache byte ownership"));
	cache.resize(64, 60000);
	tests++;
	if (!cache.get(key, sizeof (key) - 1))
	    fail(T("FAIL: LRU cache enable expiration"));
    }
    {
	tcout << T("Testing concurrent LRU expiration changes...\n");
	static constexpr char key[] = "racing key";
	LRUCache<GatedCacheEntry> cache(64, 0);
	GatedCacheEntry entry(key, sizeof (key) - 1);
	::byte *data = new ::byte[1] {};

	GatedCacheEntry::hold.store(true);
	GatedCacheEntry::started.store(false);
	GatedCacheEntry::block.store(true);
	jthread inserter([&cache, &entry, data] { cache.put(entry, data, 1); });
	while (!GatedCacheEntry::started.load())
	    this_thread::yield();
	cache.resize(64, 60000);
	GatedCacheEntry::hold.store(false);
	inserter.join();
	tests++;
	if (!cache.get(key, sizeof (key) - 1))
	    fail(T("FAIL: LRU cache concurrent expiration change"));
    }
    {
	tcout << T("Testing resource pool shrink synchronization...\n");
	ResourcePool<GatedResource> pool(1);
	const GatedResource *resource;
	atomic limited = false;

	GatedResource::started.store(false);
	GatedResource::hold.store(true);
	jthread creator([&pool, &resource] { resource = pool.get(); });
	while (!GatedResource::started.load())
	    this_thread::yield();
	jthread limiter([&pool, &limited] {
	    pool.limit(0);
	    limited.store(true);
	});
	this_thread::sleep_for(chrono::milliseconds(20));
	bool waited = !limited.load();

	GatedResource::hold.store(false);
	creator.join();
	this_thread::sleep_for(chrono::milliseconds(20));
	waited = waited && !limited.load();
	pool.release(resource);
	limiter.join();
	tests++;
	if (!waited || pool.size())
	    fail(T("FAIL: ResourcePool pending creation shrink"));
    }
    {
	ResourcePool<TestResource> pool(2, 2);
	const TestResource *first = pool.get();
	const TestResource *second = pool.allocate();
	const TestResource *acquired = nullptr;
	atomic limited = false;
	atomic got = false;

	jthread limiter([&pool, &limited] {
	    pool.limit(1);
	    limited.store(true);
	});
	this_thread::sleep_for(chrono::milliseconds(20));
	jthread getter([&pool, &acquired, &got] {
	    acquired = pool.get();
	    got.store(true);
	});
	this_thread::sleep_for(chrono::milliseconds(20));
	bool blocked = !limited.load() && !got.load();

	pool.release(second);
	limiter.join();
	getter.join();
	pool.release(first);
	pool.release(acquired);
	tests++;
	if (!blocked || pool.size() != 1)
	    fail(T("FAIL: ResourcePool acquisition during shrink"));
    }
    {
	tcout << T("Testing empty string views...\n");
	const tstring_view empty;

	tests++;
	if (!stringeq(T(""), empty) || stringcmp(T(""), empty) ||
	    !stringieq(empty, empty) || stringicmp(empty, empty) ||
	    cstrncmp<tchar>(nullptr, nullptr, 0) ||
	    cstrnicmp<tchar>(nullptr, nullptr, 0))
	    fail(T("FAIL: Empty string_view comparison"));
    }
    {
	tcout << T("Testing wide to_chars capacity...\n");
	char narrow[512];
	wchar_t wide[512];
	auto nr = to_chars(narrow, narrow + size(narrow), 1e300,
	    chars_format::fixed, 6);
	auto wr = to_chars(wide, wide + size(wide), 1e300,
	    chars_format::fixed, 6);
	bool same = nr.ec == errc() && wr.ec == errc() &&
	    nr.ptr - narrow == wr.ptr - wide;

	for (ptrdiff_t i = 0; same && i < nr.ptr - narrow; ++i)
	    same = wide[i] == (wchar_t)(uchar)narrow[i];
	tests++;
	if (!same)
	    fail(T("FAIL: Wide to_chars output over 128 characters"));
    }
    {
	tcout << T("Testing bufferstream numeric writes...\n");
	int bad = 0;
	auto check = [&]<typename C>(C) {
	    static constexpr char expected[] = "-123 1.5";
	    bufferstream<C> strm;

	    strm.write(-123).write(C(' ')).write(1.5);
	    const auto out = strm.view();
	    if (out.size() != size(expected) - 1)
		return 1;
	    for (size_t i = 0; i < out.size(); ++i)
		if (out[i] != (C)expected[i])
		    return 1;
	    return 0;
	};

	bad += check(char {});
	bad += check(wchar_t {});
	bad += check(char16_t {});
	bad += check(char32_t {});
	tests++;
	if (bad)
	    fail(T("FAIL: bufferstream numeric character conversion"));
    }
    {
	tcout << T("Testing bufferstream reset and aliasing...\n");
	bufferstream<char> strm;
	const char *nullstr = nullptr;

	strm << nullstr;
	strm << hex << setw(8) << setprecision(2);
	strm.reset();
	strm << 255 << ' ' << 1.5;
	tests++;
	if (!strm.good() || strm.view() != "255 1.5" || strm.width() ||
	    strm.precision() != 6 || strm.tie())
	    fail(T("FAIL: bufferstream reset state"));
	strm.str("abcdefghij");
	strm.str(strm.view().substr(3));
	tests++;
	if (strm.view() != "defghij")
	    fail(T("FAIL: bufferstream aliased str"));
	strm << hex;
	strm.str("0x");
	strm << 255;
	tests++;
	if (strm.view() != "0xff")
	    fail(T("FAIL: bufferstream str preserves formatting"));
    }
    {
	class MockStream {
	public:
	    int read(void *buf, uint) const {
		if (readone)
		    return 0;
		*(char *)buf = 'x';
		readone = true;
		return 1;
	    }
	    int write(const void *, uint) const { return 0; }
	    ssize_t writev(iovec *, int) const { return 0; }

	private:
	    mutable bool readone = false;
	};

	tcout << T("Testing unbuffered faststreambuf fill...\n");
	MockStream mock;
	faststreambuf strm(mock, 0);
	bool okay = strm.sgetc() == 'x' && strm.fill() < 0 &&
	    strm.avail() == "x";

	tests++;
	if (!okay)
	    fail(T("FAIL: Unbuffered faststreambuf fill"));
    }
    // aligned addresses must not leave the low hash bits constant
    {
	tcout << T("Testing ptrhash functor...\n");
	static const char objs[1000][16] = {};
	bool seen[64] = {};
	int distinct = 0;

	for (const auto &o : objs) {
	    size_t slot = ptrhash<char>()(o) & 63;

	    if (!seen[slot]) {
		seen[slot] = true;
		++distinct;
	    }
	}
	tests++;
	if (distinct < 48)
	    fail(T("FAIL: ptrhash low bits cover ") << distinct << T("/64"));
    }
    tcout << T("Test Results: ") << (tests - failures) << T("/") << tests <<
	T(" tests passed\n");
    if (failures > 0)
	tcout << T("Failed tests: ") << failures << T("\n");
    else
	tcout << T("All hash and string functor tests passed\n");
    return failures;
}
