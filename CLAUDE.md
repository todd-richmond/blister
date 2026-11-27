# CLAUDE.md

Blister: cross-platform C++ async I/O library. Class/API index: `lib/README.md`; test CLIs: `test/README.md`.

## Build and test
- Configured in-source CMake build: `make -j4 && ctest --output-on-failure`.
- Strict C++23/C23: `-Werror`, `-Wshadow` (including stdapi names such as `next`), `-Wsign-conversion`, `-fno-exceptions -fno-rtti` for C++.
- `build/build` distcleans before configuring. Use it only for build configuration changes; clean-build when switching PGO modes.
- Use `cmake -S . -B "$TMPDIR/<build>"`; `cmake <repo>` from elsewhere can pick up the in-source cache.
- Use separate scratch builds for `-DCHECK_TSAN=thread` and `-DCHECK_TSAN=address,undefined`. Do not enable static analysis unless asked.
- If a build fails with intermittent `.gch: Permission denied` or jobserver errors, rerun `make -j4`.
- Use `compile_commands.json` and `CMakeCache.txt` for exact compiler, flags, and OpenSSL paths. OpenSSL ≥3.5 is optional on Unix. Windows 11+ uses SChannel; don't claim native verification from Linux.

## Simplicity
Prefer the simplest complete implementation.

Avoid:
- unnecessary abstractions or indirection
- speculative extensibility not required by current requirements
- helpers or wrappers that add complexity without improving clarity
- comments that restate obvious code
- redundant defensive code for states excluded by established invariants
- unrelated refactoring or scope expansion
- unnecessary caching or premature optimization

Prefer:
- reusing stdapi helpers/concepts (`strview`, `strkey`/`strlit`, `const_array`/`cstr_ptr`, `string*` functors); merge duplicate types, don't add parallel ones
- one parameter type with implicit conversions over per-type overload sets
- trusting code-controlled input (literals, internally built commands); validate only caller/external data

## Performance
- Hot paths matter; verify with asm probes at -O0/-O2/-Os, not assumptions (see `lib/CLAUDE.md`).
- Prefer compile-time guarantees (consteval) over optimizer heuristics.
- String literals: no runtime strlen/hash/escape.
- Avoid copies/temporaries (`string_view` over `std::string`); one hash per insert (`try_emplace`).
- Inline only constant-data paths; don't bloat runtime callers. `LIKELY`/`UNLIKELY`; `__forceinline` for tiny hot wrappers.
- This VM has no HW perf counters: A/B by client or server CPU time with the server in a separate process.

## Source layout
- Update the terse `lib/README.md` entry when public API or config keys change.
- `stdapi.h` is the PCH and portability base. Use `T()`/`tstring` for root text that supports `_UNICODE`; keep protocol bytes narrow. Windows POSIX shims live in `lib/Windows.cpp`.
- `Dispatcher` lives in `lib/Dispatch.cpp`; see `test/EchoTest.cpp` for an end-to-end example.
- For source-list changes, check CMake, Autotools, Visual Studio projects, and `build/Blister.xcodeproj`.

## Conventions
- Assume full C++23 (concepts, ranges, `to_chars`, `format_to`); never add fallbacks.
- Public API marked `BLISTER`; internal-only helpers are not.
- No exceptions or RTTI in `lib/`: no `throw`/`try`/`dynamic_cast`.
- Tabs (width 8), 80-column soft limit. Wrapped lines +4 cols; short functions, early returns.
- Declarations at block top, blank line, then code. `f(void)`, `sizeof (x)`, `operator ()`, `T *p`.
- Members sorted alphabetically per access section; no `[[nodiscard]]` on getters.
- Class-related helpers: private static members, not file-static functions.
- Don't prune unused overloads from stdapi.h utility families; keep sets complete.
- Comments: default is none. Each one must state a non-obvious why, constraint or gotcha the code can't show; delete it if the names already say it.
  - Never: restate code, describe what a function/member does when its name says it, narrate changes or history, list parameters, section banners.
  - Length: one short line; 2 `//` lines max above a block. Prefer a trailing `//` when it fits 80 cols.
  - Multi-line `/* * */` only for class docs, kept to a few lines.
  - Before finishing, reread every comment you added and cut or shorten it.
  - Lint suppressions: trailing `// NOLINT(...)`; `NOLINTNEXTLINE` only when that would exceed 80 cols.
- Docs, comments, replies terse; no narration.

## Working in this repo
- Scope searches to sources; skip generated CMake, PCH, cache, `Testing/`, and backup directories. Use `rg` or offset reads for `lib/` files over 24 KB.
- Put scratch files in `$TMPDIR` (fallback `/tmp/claude-$UID`); avoid names that shadow system tools (`.` in PATH).
- HTTP: `test/uhttpd` + `curl` for static files, metrics, and MPHTTP; `test/httptest` for plain/TLS POST. SMTP: `test/smtpsink` + `test/smtpload`; use a scripted local peer for reply fragmentation and EOF cases.
- For local network probes, start server and client in the same sandbox command. When binding port 0, connect to the actual address from `sockname()`. Bound probes with `timeout`, not `pkill -f`.
- Don't run downloaded package code (pip, toolchains); verify output by hand.
- Don't `git stash -- <path>` with staged changes.
