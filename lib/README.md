# lib/

The Blister library. Link against `libblister`.

## `stdapi.h` — portability foundation

Included by everything; must be the first include in every `.cpp` file (directly, or via the precompiled header). Provides:
- POSIX-on-Windows emulation (`open`, `stat`, `readdir`, `writev`, etc. — declared `extern BLISTER`, implemented in `Windows.c`/`WindowsCPP.cpp`; Unix equivalents in `Unix.c`).
- The `tchar` generic-text layer (à la Windows `TCHAR`, but cross-platform): `T("literal")`, `tstring`, `tstrcmp`/`tstricmp`/`tstrlen`/etc. Code that must work in both narrow and `_UNICODE` (wide) builds should go through these rather than raw `char`/`std::string`.
- `BLISTER` (`DLL_EXPORT`/`DLL_IMPORT`), used to annotate every publicly-exported class/function.
- Fast hashing (`bernstein_hash`, `rapid_hash`, `stringhash`/`stringihash`, `ptrhash`), fast int parsing (`atou`/`atoi`/`atoin`), and string compare/eq functors (`streq`, `strless`, etc.).
- A zero-allocation intrusive singly-linked list, `ObjectList<C>` (elements derive from `ObjectList<C>::Node`) and its size-tracked variant `SizedObjectList`, used throughout the `Dispatch` object hierarchy to avoid heap churn.

## `Dispatch.h/.cpp` — the reactor core

- `Dispatcher : ThreadGroup` — the event loop; backend chosen at compile time per platform (`DSP_EPOLL` Linux, `DSP_KQUEUE` BSD, `DSP_DEVPOLL` Solaris, `DSP_POLL`/`DSP_WIN32_ASYNC` Windows/fallback). One or more worker threads run `Dispatcher::exec()`.
- `DispatchObj` — base event object with a callback (`DispatchObjCB`); can be "grouped" as a child of a parent object (refcounted `Group`) so child lifetimes track the parent.
- `DispatchTimer` — adds timeout scheduling, tracked in a hybrid sorted/unsorted structure (near-term timers sorted, far-future ones not) that's periodically re-split to avoid re-sorting on every insert.
- `DispatchSocket`/`DispatchIOSocket` — socket + timer combined; `acceptable()`/`readable()`/`writeable()`/`rwable()`/`closeable()` register interest with the reactor.
- `DispatchClientSocket`/`DispatchServerSocket`/`DispatchListenSocket` — connect/accept lifecycles.
- `SimpleDispatchListenSocket<D, C>` — the template most servers instantiate to auto-spawn a connection handler `C` per accepted socket, reading listen config (`host`, `socket.backlog`, `socket.reuse`, `enable`) from a `Config` section named by `C::section()`.
- `AsyncCondvar` — condition-variable-like semantics without blocking a thread; `wait()` queues a callback to run later instead of parking the thread.

New reactor object types should extend this hierarchy rather than invent a parallel mechanism.

## `Config.h/.cpp`

- `Config` — thread-safe parser for property style (`key = value`, dotted subsections) or ini style (`[section]`), backed by a `SpinRWLock`-guarded hash map.
- Prefix scoping — a `*` prefix shares a value across programs sharing one file.
- `${key}`/`$(key)` recursive expansion, quoted values, `\`-continued lines, `#include`, `+=` append.
- Typed `get<T>()`/`set<T>()` — parse/format straight to/from text.
- `ConfigFile` — layers path-based load/save over the istream/ostream-based `Config` base.

## `Log.h/.cpp`

- Rollover, multi-process-safe writes, syslog/mail alerting.
- `test/dlog` is a CLI wrapper around it.

## `Socket.h/.cpp`

Cross-platform Berkeley/WinSock socket layer underpinning `DispatchSocket`:
- `Sockaddr` — unifies IPv4/IPv6/UNIX-domain addressing (resolution, comparison, formatting).
- `SockaddrList` — holds multi-address DNS results.
- `CIDR` — fast IP-range membership checks.
- `Socket` — small refcounted, copyable fd handle; non-blocking-safe accept/connect/read/write/readv/writev with automatic EINTR retry and blocked-vs-hard-error classification (`blocked()`/`interrupted()`).
- `SocketSet` — abstracts `poll()`/`select()` differences for large fd sets.
- `isockstream`/`osockstream`/`sockstream` — adapt a `Socket` to `std::istream`/`ostream`/`iostream` via `faststreambuf` (see `Streams.h`).

## `Thread.h/.cpp`

Cross-platform threading primitives underpinning `Dispatcher`:
- `Thread` — wraps a native OS thread (`onStart`/`onStop` hooks, suspend/terminate/wait).
- `ThreadGroup` — (base of `Dispatcher`) manages a pool of threads as a unit.
- Lock types trading fairness vs. speed: `SpinLock`/`SpinRWLock` (spinning), `TicketLock` (fair spinning), `UnfairLock` (futex-backed fast path), `Lock`/`RWLock` (`std::mutex`/`shared_mutex` aliases) — all paired with RAII `*Locker`/`FastLocker`.
- `LifoSemaphore` — lock-free, LIFO-ordered semaphore used by `Dispatcher` to wake worker threads.
- `ThreadLocal`/`ThreadLocalClass` — TLS wrappers with destruction on thread exit.
- `RefCount`, `DLLibrary` (dynamic library loading), `Processor` (CPU count/affinity).

## `Service.h/.cpp`

- `Daemon` — unifies Windows Service Control Manager and Unix signal-based daemon control behind one API.
- `onStart`/`onStop`/`onPause`/`onResume`/`onRefresh` hooks for a program that installs as a service on Windows or daemonizes on Unix.

## `Timing.h/.cpp`

- Low-overhead call-duration profiling: per-key stats (count/total/bucketed histogram) accumulated in a lock-free hashed cache.
- Thread-local call-stack tracking for nested/"stack" mode timing.
- `TimingEntry`/`TimingFrame` — RAII helpers for timing a scope.
- Global `dtiming` instance — what `test/dtiming` parses and pretty-prints.

## `HTTPClient.h/.cpp`

- `URL` — small `tchar` URL parser/formatter (host/path/prot/query/port).
- `HTTPClient` — synchronous HTTP/1.x client: `connect()` to a `Sockaddr` or host:port, build headers with `header()`, then `get()`/`post()`/`put()`/`head()`/`del()`/`cmd()` send the request.
- `status()`/`responses()`/`data()`/`size()` — expose the parsed response.
- Not built on `Dispatch` — for scripted/blocking use (`test/httpload` runs many of these across `Thread`s).

## `HTTPServer.h/.cpp`

- `HTTPServerSocket : DispatchServerSocket` — HTTP/1.x server built directly on the reactor.
- Parses the request line/headers into `arguments()`/`attributes()`/`postarguments()` maps.
- Streams the response body via `operator<<`, dispatching to virtual `get()`/`post()`/`put()`/`del()` for the application to override (default `501 Not Implemented`).
- Handles keep-alive, chunked transfer encoding, MIME lookup (`mimetype()`), and sending files (`reply(fd, sz)`).
- `section()` (`"http"`) names the `Config` section read via `SimpleDispatchListenSocket`.

## `MPHTTPServer.h/.cpp`

Multi-process hardening on top of `HTTPServer` for production services:
- `MPHTTPDispatcher : Dispatcher` — tracks per-worker request count/duration/average; drives graceful worker recycling (max requests per worker, staggered relisten/stop for rolling restarts, container-aware SIGTERM handling).
- `MPHTTPSocket : HTTPSocket` — adds built-in endpoints (`/check`, `/inrotation.txt`, `/metrics` in Prometheus format, `/timing`, `/version`) and per-connection timing.
- `MPHTTPServerSocket : DispatchServerSocket` — the listener.
- `MPHTTPDaemon : Daemon` — forks and supervises a pool of worker processes (`worker.count`); handles crash-loop detection, signal propagation to children, and coordinated shutdown/restart.

## `SMTPClient.h/.cpp`

- `RFC821Addr`/`RFC822Addr` — mailbox address parsers for envelope vs. header address syntax (including phrase/route/comment parsing).
- `SMTPClient` — synchronous SMTP client: `connect()`, `ehlo()`/`helo()`/`lhlo()`, `auth()`, `from()`/`to()`/`cc()`/`bcc()`, `header()`/`subject()`.
- `data()` — raw or MIME body, with `attribute()`/an overload taking type/encoding/disposition for attachments; plus `enddata()`, `quit()`.
- Also exports `base64encode`/`decode`, `uuencode`/`uudecode`, and `mkgmtime`/`parse_date` helpers used by MIME/date handling.

## `LRUCache.h`

- `LRUCache<C>` (`C` deriving from `LRUCacheEntry`) — header-only, size- and time-bounded LRU cache.
- Entries hashed with `rapid_hash`, held via `shared_ptr<const void>` with a custom deleter.
- Tracked in a splice-friendly `list` + `unordered_map` (list order = recency) under a single `SpinLock`.
- `get()`/`put()` opportunistically purge expired/oversized entries inline rather than using a background thread.

## `Streams.h`

Stream utilities filling gaps around `std::iostream` for performance and portability:
- `faststreambuf<C>` — a `streambuf` that reads directly into caller buffers and coalesces writes via `writev`, avoiding copies; backs the `Socket` stream adapters.
- `bufferstream<C>` — a fast in-memory `ostream` replacing `sstream`/`strstream` (works around a leaking MSVC `seekp()`), with an optimized `write<T>()` for integers and floats. `tbufferstream` is the `tchar`-specialized alias, used to build HTTP/SMTP protocol lines.
- `memstream` — a zero-copy `istream` view over an existing memory buffer, with seek support.
- `nullstream` — a `tchar` `ostream` that discards everything written to it.

## `MD5.c/.h`

- MD5 digest implementation; supporting utility (e.g. for MIME/auth code in `SMTPClient`).

## Platform layer

- `Unix.c`, `Windows.c`, `WindowsCPP.cpp`, `Version.rc` — the POSIX-emulation and platform-specific implementations backing `stdapi.h` and Windows service/versioning. Not meant to be included directly.
