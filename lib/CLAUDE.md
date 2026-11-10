# lib/ notes

## Invariants
- No embedded NULs: tchar*/tstring/tstring_view are C-string equivalent.
- Shared lib + glibc 2.28: no thread_local dtors, gettid(), clockjoin.

## String literal fast paths (stdapi.h)
- `strkey`/`strikey`: const array → consteval len+hash; runtime string → hash 0, computed on lookup. Lookup param for Config get/exists/erase, Timing add/erase/record, HTTPServer `attrkey` (always `char`).
- `strlit`: literal-only, for APIs keeping the pointer or trusting content (Timing start/TimingEntry/TimingFrame, SMTPClient::cmd skips CR/LF check).
- consteval rejects `tbl[i]` and non-static local const arrays; pass `+tbl[i]`.
- Wide non-ASCII `strikey` → hash 0 (towupper not constexpr).
- Log: const array len = `N-1` if `val[N-2]` else strlen, written unescaped; no consteval (runtime tables).
- `rapid_hash` inlines only when `CONSTANT_P(len) && CONSTANT_P(*p)` (not -Os) so literals fold at -O1+. Keep `charhash`/`string*hash` `__forceinline`. `CONSTANT_P` false on MSVC.

## Overload pitfalls
- Non-template `f(const T *)` beats `template<size_t N> f(const T (&)[N])`: use `template<cstr_ptr P> f(P &&)`.
- `const T &` drops array const (literal == mutable buffer); use `T &&` + `const_array`/`cstr_ptr`. Mutable `char buf[N]` must take the runtime path.
- Requires-clause isn't complete-class context: forward-declare nested types used there.

## Verifying
- Probe: `extern "C"` funcs, `g++ -S` at -O0/-O1/-O2/-O3/-Os, count `call`/`imul`. GCC -O2 folding depends on inlining budget — probe in a realistic TU.
- Flags: `jq -r '.[]|select(.file|endswith("lib/X.cpp")).command' compile_commands.json`. Tests: `-fsanitize=address,undefined`; -O0 needs `-U_FORTIFY_SOURCE`; raise `-Wstack-usage`; link `lib/libblister.a -lpthread -ldl`.
- `static_assert` literal key hash == runtime `stringhash`/`stringihash`.
