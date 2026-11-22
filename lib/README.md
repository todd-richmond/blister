# lib/

The Blister library. Link against `libblister`.

- `stdapi.h` — portability base included first: Windows POSIX emulation, `tchar` layer, `BLISTER` export macro, hash/parse/compare helpers, intrusive lists.
- `utf8.manifest` — add to Windows executables so narrow CRT and `-A` APIs take UTF-8; the POSIX emulation always treats `char` paths as UTF-8.
- `Dispatch` — epoll/kqueue/devpoll/poll reactor of event, timer and socket objects; `SimpleDispatchListenSocket<D, C>` spawns a `C` per connection.
- `Thread` — threads, thread groups, locks, semaphores and thread-local storage.
- `Socket` — sockets, addresses, CIDR matching, poll sets and iostream adapters; `SocketLayer` is an optional stream transform such as TLS.
- `Streams.h` — fast stream buffers and in-memory streams.
- `Config` — thread-safe property/ini parser with prefixes, `${key}` expansion and typed get/set.
- `Log` — rolling, multi-process-safe logging with syslog and mail alerts.
- `Timing` — low-overhead call-duration profiling.
- `Service` — Windows services and Unix daemons. A watcher runs `worker.count` workers and restarts them on exit, hang, memory limits or a failed `check()`; Unix forks them, Windows 11+ spawns processes that rerun `onInit()` and inherit `onSpawn()` handles.
- `HTTPClient` — blocking and pipelining async HTTP clients, URL and date parsing.
- `HTTPServer` — HTTP/1.x server with keep-alive, chunking and file replies from `http.docroot` (default `${installdir}/htdocs`). `GET /metrics` serves Prometheus/OpenMetrics: HTTP stats, top `timing=N` Timing keys, `name[]=` filter and `prometheus.label.*` default labels; extend via `metrics()` or the `cntrstats`, `gaugestats`, `gdstats`, `sumstats` and `tdstats` registries.
- `MPHTTPServer` — prefork HTTP/HTTPS server (`libblistertls`): workers recycle after `worker.maxrequests`; `/check`, `/metrics`, `/timing` and `/version`; `ShMemHTTPSocket` takes POST data from a file, SysV shared memory or a Windows file mapping (loopback/UNIX peers only).
- `SMTPClient` — blocking and async SMTP/LMTP clients (SMTPUTF8, pipelining, BDAT), address parsers and MIME codecs.
- `LRUCache.h` — size, count and time-bounded LRU cache.
- `ResourcePool.h` — blocking and `Dispatcher`-integrated pools of lazily created resources.
- `Unix.c`, `Windows.cpp`, `Version.rc` — platform implementations.

`libblistertls` (SChannel on Windows, else OpenSSL 3) depends on `libblister`. Without either, enabling TLS fails instead of running in plaintext.
- `TLSSocket` — `TLSContext` loads `tls.*` keys and adds a TLS `SocketLayer` to any socket; `handshake()` also runs a blocking client handshake. Servers without a cert self-sign; clients verify unless `tls.verify` is false; `tls.ktls` enables kernel TLS. On Windows `tls.certfile` is PKCS#12 or a `MY` store subject and OpenSSL-only keys fail `init()`.
- `HTTPTLSServer`, `HTTPTLSClient`, `AsyncHTTPTLSClient`, `SMTPTLSClient` and `AsyncSMTPTLSClient` enable TLS per config section: `<sect>.tls.enable`, or `<sect>.starttls.enable` for SMTP.
