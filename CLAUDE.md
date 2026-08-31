# CLAUDE.md

Guidance for Claude Code working in this repo.

## Project overview

Blister: C++ library for async I/O servers/clients — epoll/kqueue/poll reactor, config parsing, logging, sockets, threading primitives, HTTP/SMTP client-server support. Targets Linux, Solaris, macOS, BSD, Windows (POSIX emulation layer).

## Build

CMake (>= 3.10), built in-source at repo root (not a separate `build/` dir). Autotools/MSVC project files also exist but are unmaintained.

```sh
cmake -DCMAKE_BUILD_TYPE=Debug .   # or: build/build [check|tsan] [Debug|Release|...]
make -j4                           # rebuild after initial cmake/build/build
ctest                              # only test: HashFunctors
```

- `build/build [check|tsan] [BuildType]`: `make distclean` + reconfigure + `make -j8`. `check`→`-DCHECK_ALL=ON`, `tsan`→`-DCHECK_TSAN=ON`. Only re-run when `CMakeLists.txt`/build options change — otherwise just `make -j4`.
- CMake options (default off): `CHECK_CLANG_TIDY`, `CHECK_CPPCHECK`, `CHECK_CPPLINT`, `CHECK_IWYU`/`CHECK_ALL`, `CHECK_TSAN=<sanitizer>`. `COMPILE_PCH` (default ON) auto-disables under static analysis.
- C++23/C23, `-fno-exceptions -fno-rtti`, `-Werror`/`/WX` on GCC/Clang/MSVC — new warnings are build breaks.
- No unit test framework. Only `test/HashTest.cpp` (`HashFunctors` ctest target, `EXCLUDE_FROM_ALL`) is automated; rest of `test/` is sample/load-test programs — see `test/README.md`.
- Static analysis config at repo root: `.clang-tidy`, `.cppcheck-suppressions`, `CPPLINT.cfg`. CI runs CodeQL, MSVC Code Analysis, SonarQube on push/PR to `master`.

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

## Code architecture

See `lib/README.md` for full per-class detail; summary below.

- `lib/stdapi.h` — portability foundation, included via PCH by everything: POSIX-on-Windows emulation; `tchar` generic-text layer (`T()`, `tstring`, `tstrcmp` etc. — use these, not raw `char`/`std::string`, for text that must work in `_UNICODE` builds); `BLISTER` export macro; fast hash/int-parse/string-compare functors; intrusive `ObjectList<C>`/`SizedObjectList`.
- `lib/Dispatch.h/.cpp` — reactor core. `Dispatcher : ThreadGroup` runs the event loop (`DSP_EPOLL`/`DSP_KQUEUE`/`DSP_DEVPOLL`/`DSP_POLL` per platform). Object hierarchy: `DispatchObj` (base, groupable) → `DispatchTimer` (timeouts) → `DispatchSocket`/`DispatchIOSocket` → `DispatchClientSocket`/`DispatchServerSocket`/`DispatchListenSocket`. `SimpleDispatchListenSocket<D,C>` is the template most servers use to auto-spawn connection handler `C` per accept. New reactor object types should extend this hierarchy, not invent a parallel mechanism.
- `lib/Config.h/.cpp` — thread-safe config parser (`key = value` or ini `[section]`); prefix scoping; `${key}` expansion; `+=` append; typed `get<T>()`/`set<T>()`.
- `lib/Log.h/.cpp` — logging: rollover, multi-process-safe writes, syslog/mail alerts.
- `lib/Socket.h/.cpp` — cross-platform socket layer. `Sockaddr` (IPv4/IPv6/UNIX), `SockaddrList`, `CIDR`. `Socket` = refcounted fd handle, non-blocking-safe I/O with EINTR retry. `SocketSet` abstracts poll/select. `isockstream`/`osockstream`/`sockstream` adapt `Socket` to `std::iostream`.
- `lib/Thread.h/.cpp` — threading primitives. `Thread`, `ThreadGroup` (base of `Dispatcher`). Lock types: `SpinLock`/`SpinRWLock`, `TicketLock`, `UnfairLock`, `Lock`/`RWLock`, all with RAII `*Locker`. Also `LifoSemaphore`, `ThreadLocal`, `RefCount`, `DLLibrary`, `Processor`.
- `lib/Service.h/.cpp` — unified Windows SCM / Unix signal daemon control.
- `lib/Timing.h/.cpp` — call-duration profiling; `TimingEntry`/`TimingFrame` are RAII scope timers; global `dtiming` instance.
- `lib/HTTPClient`/`HTTPServer`/`SMTPClient` — protocol implementations on `Dispatch`. `lib/MPHTTPServer` layers multi-process worker management (prefork, rolling restarts, health/metrics endpoints) on top of `HTTPServer`.
- `lib/LRUCache.h` — header-only size/time-bounded LRU cache.
- `test/` — sample/load-test programs, not unit tests (`cfg`, `dlog`, `dtiming`, `hashtest`, `daemonize`, `echotest`, `uvechotest`, `uhttpd`, `httpload`, `smtpload` — see `test/README.md`). `echotest` is the canonical Dispatch client+server example.

### Conventions
- Prefer C++23 (concepts, ranges, `to_chars`, etc.) over older idioms in new/modified code.
- Public API surface is marked `BLISTER`; internal-only helpers are not.
- Tabs (width 8), 80-column soft limit.
- No exceptions or RTTI in `lib/` — don't introduce `throw`/`try`/`dynamic_cast`.

## Working efficiently in this repo

- Never read/search `build/`, `CMakeFiles/` (root or per-subdir), `.cache/`, `.lto/`, `Testing/`, `autom4te.cache/`, `bak/` — gitignored build output/backups, not source. Never open `*.pch` files — compiled binary blobs.
- Several `lib/` files exceed 24KB — check size first (`wc -l`/`ls -la`) and prefer `Grep`/offset `Read` over a full read above ~24KB.
- Build is usually already configured — default to `make -j4`; only re-run `cmake`/`build/build` when `CMakeLists.txt`/build options change.
- `ctest` runs only `HashFunctors` — don't search for a broader unit-test suite; there isn't one.
- Static analysis (`CHECK_CLANG_TIDY`/`CHECK_CPPCHECK`/`CHECK_CPPLINT`/`CHECK_IWYU`/`CHECK_ALL`) is off by default and slow — don't enable proactively, only when asked.
- No vendored/third-party code — a symbol's definition is in `lib/` or a system/standard header.
