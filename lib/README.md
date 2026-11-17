# lib/

The Blister library. Link against `libblister`.

- `stdapi.h` — portability foundation, included first by every source file. POSIX emulation on Windows, the `tchar` generic-text layer, the `BLISTER` export macro, fast hash/parse/compare helpers and intrusive lists.
- `Dispatch` — epoll/kqueue/devpoll/poll reactor. A hierarchy of event, timer and socket objects; `SimpleDispatchListenSocket<D, C>` spawns a handler per accepted connection. New reactor types should extend it.
- `Thread` — threads, thread groups, spin/ticket/unfair/standard locks, semaphores and thread-local storage.
- `Socket` — cross-platform sockets, addresses, CIDR matching, poll sets and iostream adapters.
- `Streams.h` — fast stream buffers and in-memory streams.
- `Config` — thread-safe property/ini parser with prefix scoping, `${key}` expansion and typed get/set.
- `Log` — rolling, multi-process-safe logging with syslog and mail alerts.
- `Timing` — low-overhead call-duration profiling.
- `Service` — one API for Windows services and Unix daemons.
- `HTTPClient` — blocking HTTP client, non-blocking pipelining `AsyncHTTPClient`, URL parser and HTTP date parsing.
- `HTTPServer` — HTTP/1.x server on the reactor with keep-alive, chunking and file replies.
- `SMTPClient` — blocking SMTP/LMTP client with SMTPUTF8, pipelining and BDAT, RFC 821/822 address parsers, and base64, quoted-printable, uuencode and xxencode codecs with AVX2 paths. `AsyncSMTPClient` waits for RCPT and end-of-message replies in a `Dispatcher` instead of a thread.
- `LRUCache.h` — size, count and time-bounded LRU cache.
- `ResourcePool.h` — header-only `ResourcePool<C>` (blocking) and `AsyncResourcePool<C>` (`Dispatcher`-integrated) pools of lazily created, shareable resources.
- `Socket` `SocketLayer` — optional stream transform (TLS) owned by a socket: `Socket` I/O and `DispatchSocket` polls go through it, `handshake()` starts it.
- `Unix.c`, `Windows.cpp`, `Version.rc` — platform implementations behind `stdapi.h`.

`libblistertls` (SChannel on Windows, else OpenSSL 3 when found) depends on `libblister`. It is always built: without SChannel or OpenSSL the same API exists but a server `init()` with `tls.enable` and every `layer()` fail, so clients and servers that enable TLS fail instead of running in plaintext:
- `TLSSocket` — `TLSContext` loads `tls.*` keys and installs an OpenSSL `SocketLayer` on any socket. A server without a cert self-signs a PEM `~/.ssh/id_*` or ephemeral key. Clients verify the server chain and name or IP unless `tls.verify` is false (the test programs turn it off) and resume sessions per host and peer address. `tls.groups` sets key exchange groups. `tls.ktls` (default false; it slows small writes) moves record crypto into the kernel when libssl is built with `enable-ktls` and the `tls` module is loaded, else falls back. On Windows `tls.certfile` is a PKCS#12 file (`tls.password`) or a subject in the user's `MY` store, the default server key is a persisted `Blister TLS` CNG key, and OpenSSL-only keys (`tls.cacertpath`, `tls.cipherlist`, `tls.ciphersuites`, `tls.crlpath`, `tls.groups`, `tls.keyfile`, `tls.options`) fail `init()`.
  Also `HTTPTLSServer` (HTTPS when its `tlsctx` has `http.tls.enable`), `HTTPTLSClient` and `AsyncHTTPTLSClient` (TLS at connect for `tls(true)` or `configure(cfg, sect)` with `sect.tls.enable`; `starttls()` upgrades an open connection), and `SMTPTLSClient` / `AsyncSMTPTLSClient` (`SMTPTLSClientT<B>`): SMTPS at connect for `sect.tls.enable`, and with `sect.starttls.enable` `ehlo()`/`lhlo()` run STARTTLS and greet again, failing if the server doesn't offer it. Clients stay plain until configured, so a process can mix TLS and plain clients by section.
