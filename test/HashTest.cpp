/*
 * Test program for hash and string functors
 * Tests all variations of hash and string functors with different string types
 */

#include "stdapi.h"
#include <map>
#include <unordered_map>
#include <fstream>
#include <vector>
#include <string>

vector<tchar> read_file_content(const tstring& filename) {
    tifstream file(filename.c_str(), ios::binary | ios::ate);

    if (!file.is_open()) {
	tcout << T("ERROR: no such file\n");
	exit(2);
    }

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    vector<tchar> buffer((size_t)size);
    if (!file.read(buffer.data(), size))
	return {};
    return buffer;
}

vector<tchar> read_stdin_content() {
    vector<tchar> buffer;
    constexpr size_t block_size = 8192;
    tchar block[block_size];

    while (tcin.read(block, block_size))
	buffer.insert(buffer.end(), block, block + tcin.gcount());
    if (tcin.gcount() > 0)
	buffer.insert(buffer.end(), block, block + tcin.gcount());
    return buffer;
}

int tmain(int argc, const tchar * const argv[]) {
    if (argc >= 2) {
	tstring arg = argv[1];

	if (arg == T("-b") || arg == T("-r")) {
	    tstring filename;
	    if (argc >= 3)
		filename = argv[2];
	    vector<tchar> content;
	    if (filename.empty()) {
		content = read_stdin_content();
	    } else {
		content = read_file_content(filename);
		if (content.empty()) {
		    return 1;
		}
	    }
	    if (content.empty())
		return 1;
	    strhash_t hash;
	    if (arg == T("-b"))
		hash = bernstein_hash(content.data(), content.size());
	    else
		hash = rapid_hash(content.data(), content.size() * sizeof (tchar));
	    tcout << hash << T("\n");
	    return 0;
	}
    }

    // Run the test suite if no hash arguments provided
    int failures = 0;
    int tests = 0;

#define fail(msg) do { tcout << msg << T("\n"); failures++; } while (0)

    tcout << T("Testing hash and string functors...\n");
    // Test strhash functor
    {
	tcout << T("Testing strhash functor...\n");
	// tchar* key (use mutable array for pointer test)
	static tchar key_array[] = T("key");
	tchar *key_ptr = key_array;
	unordered_map<tchar *, tstring, strhash> map_ptr;
	map_ptr[key_ptr] = T("value");
	tests++;
	if (map_ptr[key_ptr] != T("value"))
	    fail(T("FAIL: tchar* map test"));
	unordered_map<tstring, tstring, strhash, streq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, strhash> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
	unordered_map<const tchar *, tstring, strhash> map_literal;
	map_literal[T("literal_key")] = T("literal_value");
	tests++;
	if (map_literal[T("literal_key")] != T("literal_value"))
	    fail(T("FAIL: String literal map test"));
    }
    // Test strihash functor
    {
	tcout << T("Testing strihash functor...\n");
	static tchar key_array[] = T("key");
	tchar *key_ptr = key_array;
	unordered_map<tchar *, tstring, strihash> map_ptr;
	map_ptr[key_ptr] = T("value");
	tests++;
	if (map_ptr[key_ptr] != T("value"))
	    fail(T("FAIL: tchar* map test"));
	unordered_map<tstring, tstring, strihash, streq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, strihash> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
	// string literal keys with case-insensitive equality
	unordered_map<const tchar *, tstring, strihash, strieq> map_iliteral;
	map_iliteral[T("ILITERAL_KEY")] = T("iliteral_value");
	tests++;
	if (map_iliteral[T("ILITERAL_KEY")] != T("iliteral_value"))
	    fail(T("FAIL: Case-insensitive literal map test"));
	tests++;
	if (map_iliteral[T("iliteral_key")] != T("iliteral_value"))
	    fail(T("FAIL: Case-insensitive literal map (lowercase) test"));
    }
    // Test striasciihash functor
    {
	tcout << T("Testing striasciihash functor...\n");
	static tchar key_array[] = T("key");
	tchar *key_ptr = key_array;
	unordered_map<tchar *, tstring, striasciihash> map_ptr;
	map_ptr[key_ptr] = T("value");
	tests++;
	if (map_ptr[key_ptr] != T("value"))
	    fail(T("FAIL: tchar* map test"));
	unordered_map<tstring, tstring, striasciihash, streq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, striasciihash> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
	// string literal keys with ASCII case-insensitive equality
	unordered_map<const tchar *, tstring, striasciihash, strieq>
	map_asciiliteral;
	map_asciiliteral[T("ASCIILITERAL_KEY")] = T("asciiliteral_value");
	tests++;
	if (map_asciiliteral[T("ASCIILITERAL_KEY")] != T("asciiliteral_value"))
	    fail(T("FAIL: ASCII case-insensitive literal map test"));
	tests++;
	if (map_asciiliteral[T("asciiliteral_key")] != T("asciiliteral_value"))
	    fail(T("FAIL: ASCII case-insensitive literal map (lowercase) test"));
    }
    // Test compile-time (constexpr) hashing of string literals -- regression
    // test for the bernstein_hash overload ambiguity fix, which previously
    // made stringhash/stringihash/striasciihash fail to compile at all when
    // called directly with a string literal
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
	    "strhash must distinguish different-length literals at compile time");
	tests++;
    }
    // Test streq functor
    {
	tcout << T("Testing streq functor...\n");
	unordered_map<tstring, tstring, strhash, streq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, strhash, streq> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
    }
    // Test strieq functor
    {
	tcout << T("Testing strieq functor...\n");
	unordered_map<tstring, tstring, strihash, strieq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, strihash, strieq> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
    }
    // Test strless functor with std::map
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
    // Test striless functor with std::map
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
	// Prefix ordering edge case (case-insensitive): a string that is a
	// case-insensitive prefix of another must sort first, regardless of
	// case -- regression test for stringicmp's length tiebreak
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
    // Test different string literal lengths
    {
	tcout << T("Testing different string literal lengths...\n");
	unordered_map<const tchar *, int, strhash> map_lengths;
	map_lengths[T("a")] = 1;
	map_lengths[T("abcde")] = 5;
	tests++;
	if (map_lengths[T("a")] != 1)
	    fail(T("FAIL: Length test for 'a' (1 char)"));
	tests++;
	if (map_lengths[T("abcde")] != 5) // cppcheck-suppress knownConditionTrueFalse
	    fail(T("FAIL: Length test for 'abcde' (5 chars)"));
    }
    // Test hash consistency with string literals through unordered_map usage
    {
	tcout << T("Testing hash consistency with string literals...\n");
	// Test that the same string literal produces the same hash
	unordered_map<const tchar *, int, strhash> hash_consistency;
	hash_consistency[T("same")] = 1;
	hash_consistency[T("same")] = 2;  // Should overwrite, proving same hash
	tests++;
	if (hash_consistency[T("same")] != 2) // cppcheck-suppress knownConditionTrueFalse
	    fail(T("FAIL: Hash consistency test"));
	// Test case-insensitive hash consistency
	unordered_map<const tchar *, int, strihash, strieq> ihash_consistency;
	ihash_consistency[T("CASE")] = 1;
	ihash_consistency[T("case")] = 2;	// Should overwrite, proving
						// case-insensitive hash
	tests++;
	if (ihash_consistency[T("CASE")] != 2)
	    fail(T("FAIL: Case-insensitive hash consistency test"));
	tests++;
	if (ihash_consistency[T("case")] != 2)
	    fail(T("FAIL: Case-insensitive hash consistency (lowercase) test"));
	// Test ASCII case-insensitive hash consistency
	unordered_map<const tchar *, int, striasciihash, strieq>
	ahash_consistency;
	ahash_consistency[T("ASCII")] = 1;
	// Should overwrite, proving ASCII case-insensitive hash
	ahash_consistency[T("ascii")] = 2;
	tests++;
	if (ahash_consistency[T("ASCII")] != 2)
	    fail(T("FAIL: ASCII case-insensitive hash consistency test"));
	tests++;
	if (ahash_consistency[T("ascii")] != 2)
	    fail(T("FAIL: ASCII case-insensitive hash consistency (lowercase) test"));
    }
    // Test heterogeneous lookups with transparent function objects
    {
	tcout << T("Testing heterogeneous lookups...\n");
	unordered_map<tstring, tstring, strhash, streq> map_hetero;
	map_hetero[T("key")] = T("value");
	// Test heterogeneous lookup with const char* key
	tests++;
	auto it1 = map_hetero.find(T("key"));
	if (it1 == map_hetero.end() || it1->second != T("value"))
	    fail(T("FAIL: Heterogeneous lookup with const char*"));
	// Test heterogeneous lookup with string_view key
	tstring_view sv_key = T("key");
	tests++;
	if (auto it2 = map_hetero.find(sv_key); it2 == map_hetero.end() ||
	    it2->second != T("value"))
	    fail(T("FAIL: Heterogeneous lookup with string_view"));
	// Negative heterogeneous lookup: key not present
	tests++;
	if (map_hetero.contains(tstring_view(T("nokey"))))
	    fail(T("FAIL: Negative heterogeneous lookup with string_view"));
	// Test case-insensitive heterogeneous lookup
	unordered_map<tstring, tstring, strihash, strieq> map_case_hetero;
	map_case_hetero[T("KEY")] = T("value");
	tests++;
	auto it3 = map_case_hetero.find(T("key"));  // Different case
	if (it3 == map_case_hetero.end() || it3->second != T("value"))
	    fail(T("FAIL: Case-insensitive heterogeneous lookup"));
	// Case-insensitive heterogeneous lookup with string_view (neither
	// side a pointer) -- regression test for the stringieq generic
	// fallback, which previously failed to compile for this combination
	tests++;
	if (auto it3v = map_case_hetero.find(tstring_view(T("key"))); it3v ==
	    map_case_hetero.end() || it3v->second != T("value"))
	    fail(T("FAIL: Case-insensitive heterogeneous lookup with string_view"));
	tests++;
	if (map_case_hetero.contains(tstring_view(T("nokey"))))
	    fail(T("FAIL: Negative case-insensitive heterogeneous lookup with string_view"));
	// Test heterogeneous lookup with map (ordered container)
	map<tstring, tstring, strless> map_ordered_hetero;
	map_ordered_hetero[T("key")] = T("value");
	tests++;
	auto it4 = map_ordered_hetero.find(T("key"));
	if (it4 == map_ordered_hetero.end() || it4->second != T("value"))
	    fail(T("FAIL: Heterogeneous lookup with ordered map"));
	// Heterogeneous lookup with string_view (neither side a pointer) --
	// regression test for the stringless generic fallback, which
	// previously failed to compile for this combination
	tests++;
	if (auto it4v = map_ordered_hetero.find(tstring_view(T("key")));
	    it4v == map_ordered_hetero.end() || it4v->second != T("value"))
	    fail(T("FAIL: Heterogeneous lookup with ordered map (string_view)"));
	tests++;
	if (map_ordered_hetero.contains(tstring_view(T("nokey"))))
	    fail(T("FAIL: Negative heterogeneous lookup with ordered map"));
	// Case-insensitive ordered map heterogeneous lookup (striless) --
	// regression test: striless was completely broken for ANY
	// heterogeneous lookup before the stringicmp overload fix
	map<tstring, tstring, striless> map_iordered_hetero;
	map_iordered_hetero[T("Key")] = T("value");
	tests++;
	auto it5 = map_iordered_hetero.find(T("KEY"));
	if (it5 == map_iordered_hetero.end() || it5->second != T("value"))
	    fail(T("FAIL: Case-insensitive heterogeneous lookup with ordered map"));
	tests++;
	if (auto it5v = map_iordered_hetero.find(tstring_view(T("key")));
	    it5v == map_iordered_hetero.end() || it5v->second != T("value"))
	    fail(T("FAIL: Case-insensitive heterogeneous lookup with ordered map (string_view)"));
	tests++;
	if (map_iordered_hetero.contains(tstring_view(T("nokey"))))
	    fail(T("FAIL: Negative case-insensitive heterogeneous lookup with ordered map"));
    }
    // Partially filled arrays bind to the array overloads -- regression test
    // for hashing N - 1 chars instead of the actual string length
    {
	tcout << T("Testing mutable buffer keys...\n");
	tchar buf[32] = T("key");
	const tchar *bufp = buf;

	tests++;
	if (strhash{}(buf) != strhash{}(T("key")) || strhash{}(buf) !=
	    strhash{}(bufp))
	    fail(T("FAIL: strhash mutable buffer test"));
	tests++;
	if (strihash{}(buf) != strihash{}(T("KEY")))
	    fail(T("FAIL: strihash mutable buffer test"));
	tests++;
	if (striasciihash{}(buf) != striasciihash{}(T("KEY")))
	    fail(T("FAIL: striasciihash mutable buffer test"));
	unordered_map<tstring, tstring, strhash, streq> map_buf;
	map_buf[T("key")] = T("value");
	tests++;
	if (!map_buf.contains(buf))
	    fail(T("FAIL: Heterogeneous lookup with mutable buffer"));
    }
    // Every key representation must hash identically across the 4 char
    // unrolled loop boundaries
    {
	tcout << T("Testing hash consistency across key types...\n");
	static const tchar src[] = T("aBcDeFgHi");

	for (size_t len = 0; len < std::size(src); ++len) {
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
	if (striasciihash{}(T("@")) == striasciihash{}(T("`")) ||
	    strihash{}(T("[")) == strihash{}(T("{")))
	    fail(T("FAIL: ASCII fold outside A-Z test"));
	tests++;
	if (striasciihash{}(T("A")) != striasciihash{}(T("a")) ||
	    striasciihash{}(T("Z")) != striasciihash{}(T("z")))
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
    // Length-bounded integer parsing must stop at the first non-digit like
    // atou -- regression test for SWAR parsing of trailing garbage
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

	auto check = [&](auto tag) {
	    using C = decltype(tag);
	    using S = basic_string<C>;

	    for (const char *wa : words) {
		for (const char *wb : words) {
		    S sa(wa, wa + strlen(wa)), sb(wb, wb + strlen(wb));
		    S la(sa), lb(sb);
		    C ma[16] = {}, mb[16] = {};
		    C *pa = ma, *pb = mb;
		    const C *ca = sa.c_str(), *cb = sb.c_str();
		    basic_string_view<C> va(sa), vb(sb);

		    copy(sa.begin(), sa.end(), ma);
		    copy(sb.begin(), sb.end(), mb);
		    for (auto &c : la)
			c = (C)(c >= 'A' && c <= 'Z' ? c + 32 : c);
		    for (auto &c : lb)
			c = (C)(c >= 'A' && c <= 'Z' ? c + 32 : c);

		    int rc = sa.compare(sb), ric = la.compare(lb);
		    auto sgn = [](int v) { return (v > 0) - (v < 0); };
		    auto ok = [&](const auto &a, const auto &b) {
			return stringeq(a, b) == (rc == 0) &&
			    stringieq(a, b) == (ric == 0) &&
			    stringless(a, b) == (rc < 0) &&
			    sgn(stringcmp(a, b)) == sgn(rc) &&
			    sgn(stringicmp(a, b)) == sgn(ric);
		    };

		    bad += !ok(pa, pb) + !ok(pa, cb) + !ok(ca, pb) +
			!ok(ca, cb) + !ok(ma, mb) + !ok(ma, cb) + !ok(pa, mb) +
			!ok(sa, pb) + !ok(sa, mb) + !ok(sa, cb) + !ok(ca, sb) +
			!ok(ma, sb) + !ok(sa, sb) + !ok(va, vb) + !ok(sa, vb) +
			!ok(va, sb) + !ok(ca, vb) + !ok(va, cb) + !ok(ma, vb) +
			!ok(va, mb) + !ok(pa, vb) + !ok(va, pb);
		}
	    }
	};

	check(char {});
	check(wchar_t {});
	tests++;
	if (bad)
	    fail(T("FAIL: string compare type matrix, ") << bad << T(" bad"));
    }
    // aligned addresses must not leave the low hash bits constant
    {
	tcout << T("Testing ptrhash functor...\n");
	static char objs[1000][16];
	bool seen[64] = {};
	int distinct = 0;

	for (auto &o : objs) {
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
	tcout << T("All hash and string functor tests completed successfully!\n");
    return failures;
}
