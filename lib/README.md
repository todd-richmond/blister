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
- `HTTPClient` — blocking HTTP client, URL parser and HTTP date parsing.
- `HTTPServer` — HTTP/1.x server on the reactor with keep-alive, chunking and file replies.
- `MPHTTPServer` — multi-process supervision for `HTTPServer`: prefork workers, rolling restarts, health and metrics endpoints.
- `SMTPClient` — blocking SMTP/LMTP client with SMTPUTF8, pipelining and BDAT, RFC 821/822 address parsers, and base64, quoted-printable and uuencode codecs with AVX2 paths.
- `LRUCache.h` — size, count and time-bounded LRU cache.
- `MD5` — MD5 digest.
- `Unix.c`, `Windows.c`, `WindowsCPP.cpp`, `Version.rc` — platform implementations behind `stdapi.h`.
