# lib/ notes

## Invariants
- No embedded NULs: tchar*/tstring/tstring_view are C strings.
- Shared lib + glibc 2.28: no thread_local dtors, gettid(), clockjoin.
- glibc < 2.34 takes static TLS from each thread's stack (Dispatcher master: 8K + 32K pad): no large thread_local arrays.

## String literal fast paths (stdapi.h)
- `strkey`/`strikey`: const array → consteval len+hash; runtime → hash 0, hashed on lookup. Used by Config get/exists/erase, Timing add/erase/record/start, TimingFrame, HTTPServer `attrkey` (`char`).
- `strlit`: literal only; for APIs keeping the pointer or trusting content (TimingEntry, SMTPClient::cmd skips CR/LF check).
- consteval rejects `tbl[i]` and non-static local const arrays: pass `+tbl[i]`.
- Log: const array len = `N-1` if `val[N-2]` else strlen, unescaped; not consteval.
- `rapid_hash`/`bernstein_hash` inline only if `CONSTANT_P(len) && CONSTANT_P(*p)` (not -Os, false on MSVC); else out-of-line `rapidcall`/`bernsteincall`.
- Keep `charhash`/`string*hash` `__forceinline`.
- `charhash`: rapid for 1-byte and case-sensitive wide; bernstein for wide icase (towlower per char, matching wcsicmp). Wide non-ASCII `strikey` → 0.
- Wide literals via runtime `stringhash` fold only at -O3 (wide strview length loop).

## Overload pitfalls
- Non-template `f(const T *)` beats `template<size_t N> f(const T (&)[N])`: use `template<cstr_ptr P> f(P &&)`.
- `const T &` drops array const (literal == mutable buffer): use `T &&` + `const_array`/`cstr_ptr`; mutable `char buf[N]` takes the runtime path.
- Requires-clause isn't complete-class context: forward-declare nested types used there.

## Verifying
- Asm probe: `extern "C"` funcs, `g++ -S` at -O0/-O1/-O2/-O3/-Os, count `call`/`imul`; probe in a realistic TU.
- Flags: `jq -r '.[]|select(.file|endswith("lib/X.cpp")).command' compile_commands.json`.
- Tests: `-fsanitize=address,undefined`; -O0 needs `-U_FORTIFY_SOURCE`; raise `-Wstack-usage`; link `lib/libblister.a -lpthread -ldl`.
- `static_assert` literal key hash == runtime `stringhash`/`stringihash`.
