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

vector<char> read_file_content(const tstring& filename) {
    ifstream file(filename, ios::binary | ios::ate);

    if (!file.is_open()) {
	tcout << "ERROR: no such file\n";
	exit(2);
    }

    streamsize size = file.tellg();
    file.seekg(0, ios::beg);

    vector<char> buffer(static_cast<size_t>(size));
    if (!file.read(buffer.data(), size))
	return {};
    return buffer;
}

vector<char> read_stdin_content() {
    vector<char> buffer;
    constexpr size_t block_size = 8192;
    char block[block_size];

    while (tcin.read(block, block_size))
	buffer.insert(buffer.end(), block, block + tcin.gcount());
    if (tcin.gcount() > 0)
	buffer.insert(buffer.end(), block, block + tcin.gcount());
    return buffer;
}

int tmain(int argc, const tchar * const argv[]) {
    if (argc >= 2) {
	tstring arg = argv[1];

	if (arg == "-b" || arg == "-r") {
	    tstring filename;
	    if (argc >= 3)
		filename = argv[2];
	    vector<char> content;
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
	    if (arg == "-b")
		hash = bernstein_hash(content.data(), content.size());
	    else
		hash = rapidhash(content.data(), content.size());
	    tcout << hash << "\n";
	    return 0;
	}
    }

    // Run the test suite if no hash arguments provided
    int failures = 0;
    int tests = 0;

#define fail(msg) do { tcout << msg << "\n"; failures++; } while(0)

    tcout << "Testing hash and string functors...\n";
    // Test strhash functor
    {
	tcout << "Testing strhash functor...\n";
	// tchar* key (use mutable array for pointer test)
	static tchar key_array[] = T("key");
	tchar* key_ptr = key_array;
	unordered_map<tchar*, tstring, strhash<tchar>> map_ptr;
	map_ptr[key_ptr] = T("value");
	tests++;
	if (map_ptr[key_ptr] != T("value"))
	    fail(T("FAIL: tchar* map test"));
	unordered_map<tstring, tstring, strhash<tchar>, streq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, strhash<tchar>> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
	unordered_map<const tchar*, tstring, strhash<tchar>> map_literal;
	map_literal[T("literal_key")] = T("literal_value");
	tests++;
	if (map_literal[T("literal_key")] != T("literal_value"))
	    fail(T("FAIL: String literal map test"));
    }
    // Test strihash functor
    {
	tcout << "Testing strihash functor...\n";
	static tchar key_array[] = T("key");
	tchar* key_ptr = key_array;
	unordered_map<tchar*, tstring, strihash<tchar>> map_ptr;
	map_ptr[key_ptr] = T("value");
	tests++;
	if (map_ptr[key_ptr] != T("value"))
	    fail(T("FAIL: tchar* map test"));
	unordered_map<tstring, tstring, strihash<tchar>, streq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, strihash<tchar>> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
	// string literal keys with case-insensitive equality
	unordered_map<const tchar*, tstring, strihash<tchar>, strieq>
	    map_iliteral;
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
	tcout << "Testing striasciihash functor...\n";
	static tchar key_array[] = T("key");
	tchar* key_ptr = key_array;
	unordered_map<tchar*, tstring, striasciihash<tchar>> map_ptr;
	map_ptr[key_ptr] = T("value");
	tests++;
	if (map_ptr[key_ptr] != T("value"))
	    fail(T("FAIL: tchar* map test"));
	unordered_map<tstring, tstring, striasciihash<tchar>, streq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, striasciihash<tchar>> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
	// string literal keys with ASCII case-insensitive equality
	unordered_map<const tchar*, tstring, striasciihash<tchar>, strieq>
	map_asciiliteral;
	map_asciiliteral[T("ASCIILITERAL_KEY")] = T("asciiliteral_value");
	tests++;
	if (map_asciiliteral[T("ASCIILITERAL_KEY")] != T("asciiliteral_value"))
	    fail(T("FAIL: ASCII case-insensitive literal map test"));
	tests++;
	if (map_asciiliteral[T("asciiliteral_key")] != T("asciiliteral_value"))
	    fail(T("FAIL: ASCII case-insensitive literal map (lowercase) test"));
    }
    // Test streq functor
    {
	tcout << "Testing streq functor...\n";
	unordered_map<tstring, tstring, strhash<tchar>, streq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, strhash<tchar>, streq> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
    }
    // Test strieq functor
    {
	tcout << "Testing strieq functor...\n";
	unordered_map<tstring, tstring, strihash<tchar>, strieq> map_string;
	map_string[T("key")] = T("value");
	tests++;
	if (map_string[T("key")] != T("value"))
	    fail(T("FAIL: tstring map test"));
	unordered_map<tstring_view, tstring, strihash<tchar>, strieq> map_view;
	tstring key_str = T("key");
	map_view[tstring_view(key_str)] = T("value");
	tests++;
	if (map_view[tstring_view(key_str)] != T("value"))
	    fail(T("FAIL: tstring_view map test"));
    }
    // Test strless functor with std::map
    {
	tcout << "Testing strless functor...\n";
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
	tcout << "Testing striless functor...\n";
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
    }
    // Test different string literal lengths
    {
	tcout << "Testing different string literal lengths...\n";
	unordered_map<const tchar*, int, strhash<tchar>> map_lengths;
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
	tcout << "Testing hash consistency with string literals...\n";
	// Test that the same string literal produces the same hash
	unordered_map<const tchar*, int, strhash<tchar>> hash_consistency;
	hash_consistency[T("same")] = 1;
	hash_consistency[T("same")] = 2;  // Should overwrite, proving same hash
	tests++;
	if (hash_consistency[T("same")] != 2) // cppcheck-suppress knownConditionTrueFalse
	    fail(T("FAIL: Hash consistency test"));
	// Test case-insensitive hash consistency
	unordered_map<const tchar*, int, strihash<tchar>, strieq> ihash_consistency;
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
	unordered_map<const tchar*, int, striasciihash<tchar>, strieq>
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
	tcout << "Testing heterogeneous lookups...\n";
	unordered_map<tstring, tstring, strhash<tchar>, streq> map_hetero;
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
	// Test case-insensitive heterogeneous lookup
	unordered_map<tstring, tstring, strihash<tchar>, strieq> map_case_hetero;
	map_case_hetero[T("KEY")] = T("value");
	tests++;
	auto it3 = map_case_hetero.find(T("key"));  // Different case
	if (it3 == map_case_hetero.end() || it3->second != T("value"))
	    fail(T("FAIL: Case-insensitive heterogeneous lookup"));
	// Test heterogeneous lookup with map (ordered container)
	map<tstring, tstring, strless> map_ordered_hetero;
	map_ordered_hetero[T("key")] = T("value");
	tests++;
	auto it4 = map_ordered_hetero.find(T("key"));
	if (it4 == map_ordered_hetero.end() || it4->second != T("value"))
	    fail(T("FAIL: Heterogeneous lookup with ordered map"));
    }
    tcout << "Test Results: " << (tests - failures) << "/" << tests <<
	" tests passed\n";
    if (failures > 0)
	tcout << "Failed tests: " << failures << "\n";
    else
	tcout << "All hash and string functor tests completed successfully!\n";
    return failures;
}
