# CLAUDE.md

Blister: C++ async I/O library — epoll/kqueue/poll reactor, config, logging, sockets, threads, HTTP/SMTP client/server. Linux, Solaris, macOS, BSD, Windows (POSIX emulation).

## Build
In-source CMake at repo root, usually already configured: `make -j4`. `ctest` runs only `HashFunctors`; no unit test framework (`test/` is samples/load tests, see `test/README.md`). Autotools/MSVC files unmaintained.
- `build/build [check|tsan] [BuildType]`: distclean + reconfigure; only when `CMakeLists.txt`/options change. `check`=`CHECK_ALL`, `tsan`=`CHECK_TSAN`.
- Static analysis (`CHECK_CLANG_TIDY`/`CPPCHECK`/`CPPLINT`/`IWYU`/`ALL`) is slow; only when asked.
- PGO: `build/build Release -DPGO=generate`, run a workload (`test/echotest -h 127.0.0.1:8765 -l 200000 -e 50 -p 10 x`), `build/build Release -DPGO=use`. Flag changes don't recompile objects: clean-build when switching.
- C++23/C23, `-fno-exceptions -fno-rtti`, `-Werror`: warnings break the build.
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

## Architecture
Per-class detail in `lib/README.md`.
- `lib/stdapi.h`: portability base (PCH), Windows POSIX emulation, `tchar` layer (`T()`, `tstring`, `tstrcmp`...) for text that must work under `_UNICODE`, `BLISTER` export macro for public API.
- `lib/Dispatch`: reactor, `Dispatcher : ThreadGroup`. `DispatchObj` → `DispatchTimer` → `DispatchSocket`/`DispatchIOSocket` → client/server/listen sockets; `SimpleDispatchListenSocket<D,C>` spawns `C` per accept. Extend this hierarchy for new reactor types. `test/echotest` is the canonical example.

## Conventions
- Prefer C++23 (concepts, ranges, `to_chars`) over older idioms in new/modified code.
- Public API marked `BLISTER`; internal-only helpers are not.
- No exceptions or RTTI in `lib/`: no `throw`/`try`/`dynamic_cast`.
- Tabs (width 8), 80-column soft limit. Wrapped lines +4 cols; short functions, early returns.
- Declarations at block top, blank line, then code. `f(void)`, `sizeof (x)`, `operator ()`, `T *p`.
- Members sorted alphabetically per access section; no `[[nodiscard]]` on getters.
- Comments: fewest possible, only non-obvious why. Prefer short trailing `//` when the line fits 80 cols, else 1-2 `//` lines above; multi-line class docs `/* * */`. Lint suppressions: trailing `// NOLINT(...)`; `NOLINTNEXTLINE` only when that would exceed 80 cols.
- Docs, comments, replies terse; no narration.

## Working in this repo
- Skip build output: `build/` (except the `build/build` script), `CMakeFiles/`, `.cache/`, `.lto/`, `Testing/`, `autom4te.cache/`, `bak/`, `*.pch`. No vendored code.
- `lib/` files over 24KB: grep or offset reads.
- Scratch tests in `$TMPDIR`, not named like system tools (`.` in PATH).
- HTTP: `cd test && ./uhttpd console` (port 8080, serves `test/`) + `curl`; stop with `timeout`, not `pkill -f`.
- SMTP: `test/smtpsink -p <port>` or a byte-logging fake server.
- Don't `git stash -- <path>` with staged changes.
