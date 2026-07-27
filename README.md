# Blister

Blister is a lightweight, high-performance C++ library for building async I/O servers and clients: an epoll/kqueue/poll-based reactor, config parsing, logging, sockets, threading primitives, and HTTP/SMTP client-server protocol support. It targets Linux, Solaris, macOS, BSD and Windows (with a POSIX emulation layer for the latter).

## Build

Primary build system is CMake (>= 3.20); autotools (`configure.ac`/`Makefile.am`) and MSVC `.vcxproj` files also exist but CMake is what's actively maintained. The tree is configured and built in place at the repo root (in-source), not into a separate out-of-source `build/` directory:

```sh
cmake -DCMAKE_BUILD_TYPE=Debug .   # or: build/build [check|tsan] [Debug|Release|...]
make -j4                           # after the initial cmake/build/build, rebuild with just this
ctest                              # runs the one automated test (HashFunctors)
```

`build/build` is a convenience wrapper around the same steps: it runs `make distclean` if a Makefile already exists, reconfigures with `cmake -DCMAKE_BUILD_TYPE=<type> .`, and does an initial `make -j8`. Pass `check` for `-DCHECK_ALL=ON` or `tsan` for `-DCHECK_TSAN=ON`. Either way, once the tree is configured, subsequent changes only need `make -j4` (or `-j8`) — no need to re-run cmake/`build/build` unless `CMakeLists.txt` or build options change.

Useful CMake options (all off by default): `CHECK_CLANG_TIDY`, `CHECK_CPPCHECK`, `CHECK_CPPLINT`, `CHECK_IWYU` (or `CHECK_ALL` for all four), `CHECK_TSAN=<sanitizer>` (e.g. `thread`). `COMPILE_PCH` (default ON) controls precompiled-header use — it's auto-disabled when a static analyzer is active since they conflict with PCH.

Standard is C++23 / C23, built with `-fno-exceptions -fno-rtti`. All warnings are errors (`-Werror`/`/WX`) on both GCC/Clang and MSVC, so treat new warnings as build breaks.

There is no top-level test framework (no gtest/catch2). The only automated test is `test/HashTest.cpp`, exercising the hash functors in `stdapi.h` (`bernstein_hash`, `rapid_hash`, `ptrhash`, etc.); it's built on demand by the `HashFunctors` ctest target (`EXCLUDE_FROM_ALL`, not part of the default `all` build). Everything else in `test/` (`cfg`, `daemonize`, `dlog`, `dtiming`, `echotest`, `httpload`, `smtpload`, `uhttpd`) is a sample program / load-testing tool, not a unit test — see `test/README` for what each does.

Static analysis config lives at repo root: `.clang-tidy`, `.cppcheck-suppressions`, `CPPLINT.cfg`. CI (`.github/workflows/`) runs CodeQL, MSVC Code Analysis, and SonarQube on push/PR to `master`.

## Code architecture

### `lib/stdapi.h` — the portability foundation
Included (usually via precompiled header) by everything. It:
- Provides POSIX-on-Windows emulation (`open`, `stat`, `readdir`, `writev`, etc., declared `extern BLISTER` and implemented in `Windows.c`/`WindowsCPP.cpp`; the Unix equivalents live in `Unix.c`).
- Defines the `tchar` generic-text layer (à la Windows `TCHAR`, but cross-platform): `T("literal")`, `tstring`, `tstrcmp`/`tstricmp`/`tstrlen`/etc. Code that needs to work in both narrow and `_UNICODE` (wide) builds must go through these macros rather than raw `char`/`std::string` — this is an actively-maintained convention (recent history includes wide-char fixes), so match it in new lib/test code.
- Defines `BLISTER` (`DLL_EXPORT`/`DLL_IMPORT` depending on `BUILD_BLISTER`), used to annotate every publicly-exported class/function.
- Supplies fast hashing (`bernstein_hash`, `rapid_hash`, `stringhash`/`stringihash`, `ptrhash`), fast int parsing (`atou`/`atoi`/`atoin` templates using SWAR tricks), and string compare/eq functors (`streq`, `strless`, etc., all `is_transparent` for heterogeneous lookup).
- Implements a zero-allocation intrusive singly-linked list, `ObjectList<C>` (elements derive from `ObjectList<C>::Node`) and its size-tracked variant `SizedObjectList`, used throughout the Dispatch object hierarchy to avoid heap churn.

### `lib/Dispatch.h/.cpp` — the reactor core
`Dispatcher` (extends `ThreadGroup` from `Thread.h`) is the event loop; its backend is chosen at compile time per platform: `DSP_EPOLL` (Linux), `DSP_KQUEUE` (BSD), `DSP_DEVPOLL` (Solaris), `DSP_POLL`/`DSP_WIN32_ASYNC` (Windows/fallback). One or more worker threads run `Dispatcher::exec()`.

Object hierarchy (all under `DispatchObj`, an `ObjectList<DispatchObj>::Node`):
- `DispatchObj` — base event object with a callback (`DispatchObjCB`), can be "grouped" as a child of a parent object (refcounted `Group`) so child lifetimes track the parent.
- `DispatchTimer` — adds timeout scheduling; timers are tracked in `Dispatcher::TimerSet`, a hybrid sorted/unsorted structure (`sorted` `std::set` for near-term timers, `unsorted` hash set for the rest) that's periodically re-split to avoid re-sorting far-future timers on every insert.
- `DispatchSocket` / `DispatchIOSocket` — socket + timer combined; `acceptable()`/`readable()`/`writeable()`/`rwable()`/`closeable()` register interest with the reactor.
- `DispatchClientSocket`, `DispatchServerSocket`, `DispatchListenSocket` — connect/accept lifecycles; `SimpleDispatchListenSocket<D, C>` is the template most servers instantiate to auto-spawn a connection handler `C` per accepted socket, reading listen config (`host`, `socket.backlog`, `socket.reuse`, `enable`) from a `Config` section named by `C::section()`.

`AsyncCondvar` provides condition-variable-like semantics without blocking a thread — `wait()` queues a callback to be invoked later instead of parking the thread.

### Other core headers in `lib/`
- `Config.h/.cpp` — thread-safe property (`key = value`, dotted subsections) or ini-style (`[section]`) config parser backed by a `SpinRWLock`-guarded hash map of variable-length `KV` entries. Supports prefix scoping so multiple programs share one file (a `*` prefix shares a value across all of them), `${key}`/`$(key)` recursive expansion, quoted values, `\`-continued lines, `#include`, and `+=` append; typed `get<T>()`/`set<T>()` overloads parse/format straight to/from text via `atoin`/`atoun`/`to_chars` rather than going through `sstream`. `ConfigFile` layers path-based load/save convenience over the istream/ostream-based `Config` base.
- `Log.h/.cpp` — logging with rollover, multi-process-safe writes, syslog/mail alerting; the `test/dlog` utility is a CLI wrapper around it.
- `Socket.h/.cpp` — cross-platform Berkeley/WinSock socket layer underpinning `DispatchSocket`. `Sockaddr` unifies IPv4/IPv6/UNIX-domain addressing (resolution, comparison, string formatting) behind one API; `SockaddrList` holds multi-address DNS results; `CIDR` does fast IP-range membership checks. `Socket` is a small refcounted, copyable handle around a `SocketBuf`/fd, providing non-blocking-safe accept/connect/read/write/readv/writev with automatic EINTR retry and blocked-vs-hard-error classification (`blocked()`/`interrupted()`). `SocketSet` abstracts `poll()`/`select()` differences for large fd sets, and `isockstream`/`osockstream`/`sockstream` adapt a `Socket` to `std::istream`/`ostream`/`iostream` via the `faststreambuf` from `Streams.h`.
- `Thread.h/.cpp` — cross-platform threading primitives underpinning `Dispatcher`. `Thread` wraps a native OS thread (`onStart`/`onStop` hooks, suspend/terminate/wait); `ThreadGroup` (base of `Dispatcher`) manages a pool of threads as a unit, with group-wide start/stop/terminate and a `master` thread. A range of lock types trade off fairness vs. speed — `SpinLock`/`SpinRWLock` (spinning), `TicketLock` (fair spinning), `UnfairLock` (futex-backed fast path), plus `Lock`/`RWLock` (`std::mutex`/`shared_mutex` aliases) — all paired with RAII `*Locker`/`FastLocker` templates. `LifoSemaphore` is a lock-free, LIFO-ordered semaphore built on a tagged Treiber stack, used by `Dispatcher` to wake worker threads. Also provides `ThreadLocal`/`ThreadLocalClass` (TLS wrappers with destruction on thread exit), `RefCount`, `DLLibrary` (dynamic library loading), and `Processor` (CPU count/affinity).
- `Service.h/.cpp` — unifies Windows Service Control Manager and Unix signal-based daemon control behind one API.
- `Timing.h/.cpp` — low-overhead call-duration profiling: per-key stats (count/total/bucketed histogram) accumulated in a lock-free hashed cache, with thread-local call-stack tracking for nested/"stack" mode timing. `TimingEntry`/`TimingFrame` are RAII helpers for timing a scope; the global `dtiming` instance is what the `test/dtiming` utility parses and pretty-prints.
- `HTTPClient`/`HTTPServer`/`SMTPClient` — protocol implementations built on top of `Dispatch`.
- `LRUCache.h` — header-only, size- and time-bounded LRU cache (`LRUCache<C>`, `C` deriving from `LRUCacheEntry`): entries are hashed with `rapid_hash`, held via `shared_ptr<const void>` with a custom deleter, and tracked in a splice-friendly `list` + `unordered_map` (list order = recency) under a single `SpinLock`. `get()`/`put()` opportunistically purge expired/oversized entries inline rather than using a background thread.
- `MD5.c/.h` — supporting utility.

### `test/` — sample and load-test programs
None of these are unit tests (see Build above for the one automated test); each is a small, complete program demonstrating a slice of the library end to end. Programs that don't define their own classes drive a single core class directly:
- `Cfg.cpp` (`cfg`) — `Config`/`ConfigFile` only: parses a file and prints a key's value or returns it as an exit code.
- `DLog.cpp` (`dlog`) — `Log` only: stdin/CLI-driven logging utility (rollover, syslog, mail alerts).
- `DTiming.cpp` (`dtiming`) — `Timing` only: parses and pretty-prints timing data produced via `dtiming`/`TimingEntry`/`TimingFrame`.
- `HashTest.cpp` (`hashtest`) — `stdapi.h` hash functors only; this is the one program run as an automated test.

The rest define their own classes on top of the framework:
- `Daemonize.cpp` (`daemonize`) — `WatchDaemon : Daemon` (`Service.h`); wraps an arbitrary child process as a watched, auto-restarting daemon/service.
- `EchoTest.cpp` (`echotest`) — `EchoTest : Dispatcher` containing `EchoClientSocket : DispatchClientSocket`, `EchoServerSocket : DispatchServerSocket`, and `EchoListenSocket : SimpleDispatchListenSocket<EchoTest, EchoServerSocket>`; the canonical example of a scalable client+server pair built directly on `Dispatch`.
- `HTTPd.cpp` (`uhttpd`) — `HTTPDaemonSocket : HTTPServerSocket` and `HTTPDaemon : Daemon`; a minimal static-file HTTP server combining `HTTPServer` with `Service`.
- `HTTPLoad.cpp` (`httpload`) — `HTTPLoad : Thread` (with nested `LoadCmd`); scriptable multithreaded HTTP load generator built on `HTTPClient`.
- `SMTPLoad.cpp` (`smtpload`) — `SMTPLoad : Thread` (with nested `LoadCmd`); scriptable multithreaded SMTP load generator built on `SMTPClient`.
