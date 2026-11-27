# Blister library

Link `libblister`; add `libblistertls` for TLS or MPHTTP (SChannel on Windows, OpenSSL 3.5+ elsewhere). Explicit TLS fails if unavailable.

## I/O

- [Dispatch.h](Dispatch.h): `Dispatcher` runs callbacks. `DispatchObj` is the callback base; `DispatchTimer` adds deadlines; `DispatchSocket` registers sockets; `DispatchIOSocket` waits for readiness. `DispatchClientSocket` connects; `DispatchServerSocket` serves peers; `DispatchListenSocket` accepts; `SimpleDispatchListenSocket` constructs handlers. `AsyncCondvar` and `AsyncCondvar::Waiter` wait via callbacks.
- Use `erase()` for registered sockets. `Dispatcher::stop()` requests shutdown in callbacks and waits externally.
- [Socket.h](Socket.h): `Socket` shares a descriptor via `Socket::SocketBuf`; `SocketLayer` transforms I/O; `Sockaddr` holds endpoints; `SockaddrList` holds resolution results; `CIDR` matches networks; `SocketSet` polls sockets. `isockstream`, `osockstream`, and `sockstream` adapt socket I/O.
- Use `Socket::fd()` and explicit `Sockaddr` pointer casts for native APIs. Use `[IPv6]:port` and trusted `reqhost` for pre-resolved TLS names (`requestedhost()`). Remove stale Unix socket paths yourself. Layered `sendmsg()` accepts only iovecs.
- [Streams.h](Streams.h): `faststreambuf` buffers device I/O; `bufferstream` builds strings; `memstream` reads memory; `nullstream` discards output.

## HTTP, mail, and TLS

- [HTTPClient.h](HTTPClient.h): `URL` parses and escapes URLs; `HTTPResponse` exposes results. `HTTPClient` blocks; `AsyncHTTPClient` pipelines idempotent requests; `AsyncHTTPClient::Request` holds an async request and response. Internally, `HTTPHeaders` stores headers; `HTTPParser` decodes responses.
- [HTTPServer.h](HTTPServer.h): `HTTPServerSocket` serves HTTP and `http.docroot` (default `${installdir}/htdocs`); replace mapped files atomically. `PrometheusWriter` formats `/metrics`; `PrometheusMetrics` tracks series. `PrometheusFamily` describes families; `PrometheusStr`, `PrometheusLabel`, and `PrometheusLabels` represent names and labels. Scrapes support `timing=N`, `name[]=`, and `prometheus.label.*`.
- [MPHTTPServer.h](MPHTTPServer.h): `MPHTTPDaemon` supervises workers; `MPHTTPDispatcher` dispatches; `MPHTTPSocket` handles requests; `MPHTTPListenSocket` accepts; `SimpleMPHTTPListenSocket` constructs handlers. `worker.maxrequests` controls recycling; `worker.acceptmany` is startup-only. `ShMemHTTPSocket` requires `http.post.local=true` and a local peer for file/shared-memory POSTs. Proxies must strip these headers from untrusted requests.
- [SMTPClient.h](SMTPClient.h): `RFC821Addr` parses envelope addresses; `RFC822Addr` parses header addresses. `SMTPClient` sends SMTP/LMTP mail; `AsyncSMTPClient` waits asynchronously for recipient and final replies.
- [TLSSocket.h](TLSSocket.h): `TLSContext` attaches TLS and exposes `TLSContext::Info` for session details. Clients verify by default (`tls.verify`). `HTTPTLSServer`, `HTTPTLSClient`, and `AsyncHTTPTLSClient` add HTTPS. `SMTPTLSClientT` backs `SMTPTLSClient` and `AsyncSMTPTLSClient`. Configure `<section>.tls.enable` or `<section>.starttls.enable` (SMTP).

## Threads and utilities

- [Thread.h](Thread.h): `Thread` manages native threads; `ThreadGroup` coordinates and must outlive attached threads. `ThreadLocal` stores values; `ThreadLocalClass` owns per-thread objects. `DLLibrary` loads libraries; `Processor` manages CPU affinity; `RefCount` tracks references.
- `SpinLock`, `SpinRWLock`, `TicketLock`, and `UnfairLock` provide spin, read/write, FIFO, and unfair locks. `FastLockerTemplate`, `FastUnlockerTemplate`, and `LockerTemplate` provide scoped lock operations; `Condvar` waits on a mutex. `TimedSemaphore`, `CountedSemaphore`, `LifoSemaphore`, and `SharedSemaphore` add millisecond waits, waiter counts, LIFO wakeups, and cross-process waits, respectively. `Event` and `Process` wrap Windows events and processes.
- [Service.h](Service.h): `Service` controls service lifecycle; `Service::Timer` handles POSIX service timeouts; `Daemon` watches `worker.count` workers; `ServiceData` exposes Windows performance counters.
- [Config.h](Config.h): `Config` parses and expands settings; `ConfigFile` reads and writes configuration files. Use `readunscoped()` to retain literal keys, including `*.` prefixes, for rewrites. In-place saves preserve Unix permissions; Windows replacements inherit default permissions.
- [Log.h](Log.h): `Log` rolls process-safe logs; `Log::Escalator` adjusts repeated-message severity; `Log::KV` represents fields. Pruning uses the log basename and a numbered or numeric timestamp suffix. Keep other files out of that archive namespace.
- [Timing.h](Timing.h): `Timing` collects keyed durations (`Timing::Row` snapshots); CSV totals and averages are in microseconds. Cleared keys retain reusable storage until destruction; use a bounded set of keys. `TimingEntry` times scopes; `TimingFrame` tracks nested calls. [TimeAverage.h](TimeAverage.h): `TimeAverage` tracks rolling averages (`TimeAverage::Averages`); callers serialize access.
- [LRUCache.h](LRUCache.h): `LRUCache` evicts by age, size, or count; `LRUCacheEntry` holds hashed keys and exposes cached data via `value()` and `size()`. [ResourcePool.h](ResourcePool.h): `ResourcePool` blocks for resources; `AsyncResourcePool` uses `AsyncResourcePool::Waiter` callbacks.
- [stdapi.h](stdapi.h): portability helpers, `nocopy` to disable copying, intrusive `ObjectList`/`SizedObjectList` with `ObjectList::Node`, `ObjectListNode`, and `ObjectListSize`; hashed `basic_strkey`/`strlit`; string comparators (`streq`, `strieq`, `strless`, `striless`), hash functors (`strhash`, `strihash`, `striasciihash`, `ptrhash`, `llonghash`, `ullonghash`), and process usage (`pidstat`). Windows record locks are mandatory. On synchronous Windows descriptors, serialize `pread()`/`pwrite()` with ordinary cursor-based I/O.
