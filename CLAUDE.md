# CLAUDE.md

Blister: C++ async I/O library (reactor, config, logging, sockets, threads, HTTP/SMTP/TLS client/server) for Linux, Solaris, macOS, BSD and Windows (POSIX emulation).

## Build
- Root: in-source CMake, already configured: `make -j4`, then `ctest` (~15s: HashFunctors, echotest/httptest plain and `-ssl`). No unit test framework; `test/` holds samples/load tests (`test/README.md`).
- `-Werror` with `-Wshadow` (incl. stdapi names such as `next`) and `-Wsign-conversion`; C++23/C23, `-fno-exceptions -fno-rtti`.
- `build/build [check|tsan] [BuildType]`: distclean + reconfigure; only when `CMakeLists.txt`/options change.
- Static analysis (`CHECK_CLANG_TIDY`/`CPPCHECK`/`CPPLINT`/`IWYU`/`ALL`) is slow; only when asked.
- PGO: `build/build Release -DPGO=generate`, run `test/echotest -h 127.0.0.1:8765 -l 200000 -e 50 -p 10 x`, `build/build Release -DPGO=use`; clean-build when switching flags.
- Alternate configs: `cmake -S . -B <scratch>`; never `cmake <repo>` from elsewhere (pollutes the root cache).
- Intermittent `.gch: Permission denied`/jobserver errors: rerun `make -j4`.

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

## Architecture
Per-class docs in `lib/README.md`: update its terse entry when public API or config keys change.
- `lib/stdapi.h`: portability base (PCH), Windows POSIX emulation, `tchar` layer (`T()`, `tstring`, `tstrcmp`...) for text that must work under `_UNICODE`, `BLISTER` export macro.
- `lib/Dispatch`: reactor, `Dispatcher : ThreadGroup`. `DispatchObj` → `DispatchTimer` → `DispatchSocket`/`DispatchIOSocket` → client/server/listen sockets; `SimpleDispatchListenSocket<D,C>` spawns `C` per accept. `test/echotest` is the canonical example.
- Runs as a shared library: no `thread_local` destructors.

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
- Skip build output: `build/` (except `build/build`), `CMakeFiles/`, `.cache/`, `.lto/`, `Testing/`, `autom4te.cache/`, `bak/`, `*.pch`. No vendored code.
- `lib/` files over 24KB: grep or offset reads.
- Scratch files in `$TMPDIR` (if unset, `/tmp/claude-$UID`), not named like system tools (`.` in PATH). Compile scratch tests with flags from `compile_commands.json` (`jq`), `-fsanitize=thread` or `address,undefined`, linking `lib/libblister.a -lpthread -ldl`.
- HTTP: `cd test && ./uhttpd [-p port] [-s]` (default 8080, serves `test/htdocs`) + `curl`; stop with `timeout`, not `pkill -f`.
- SMTP: `test/smtpsink -p <port>` or a byte-logging fake server.
- Don't run downloaded package code (pip, toolchains); verify output by hand.
- Don't `git stash -- <path>` with staged changes.
