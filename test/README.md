# test/

Sample and load-test programs built on top of `lib/` — not unit tests. The only automated test is `HashTest.cpp` (the `HashFunctors` ctest target); everything else here is a small, complete program demonstrating a slice of the library end to end.

## Single-class demos

- **`cfg`** (`Cfg.cpp`) — `Config`/`ConfigFile` only: parses a file and prints a key's value, or returns it as an exit code.
- **`dlog`** (`DLog.cpp`) — `Log` only: stdin/CLI-driven logging utility exercising file rollover, multi-process safety, prefix format, syslog and mail notifications.
- **`dtiming`** (`DTiming.cpp`) — `Timing` only: parses and pretty-prints timing data produced via `TimingEntry`/`TimingFrame`/the global `dtiming` instance.
- **`hashtest`** (`HashTest.cpp`) — `stdapi.h` hash functors only (`bernstein_hash`, `rapid_hash`, `ptrhash`, etc.); the one program run as an automated test.

## Programs with their own classes

- **`daemonize`** (`Daemonize.cpp`) — `WatchDaemon : Daemon`; wraps an arbitrary child process as a watched, auto-restarting daemon/service.
- **`echotest`** (`EchoTest.cpp`) — `EchoTest : Dispatcher` with `EchoClientSocket : DispatchClientSocket`, `EchoServerSocket : DispatchServerSocket`, `EchoListenSocket : SimpleDispatchListenSocket<EchoTest, EchoServerSocket>`. The canonical scalable client+server example built directly on `Dispatch`; also demonstrates `Config`, `Log`, `Service`, and `Timing`.
- **`uvechotest`** (`UVEchoTest.cpp`) — libuv-based echo client/server with the same CLI as `echotest` (one `uv_loop_t` per worker thread, `SO_REUSEPORT` for multi-worker accept), for comparing `Dispatcher`'s shared-reactor model against libuv's one-loop-per-thread model on identical workloads. Only built when libuv is available.
- **`uhttpd`** (`HTTPd.cpp`) — `HTTPDaemonSocket : HTTPServerSocket` + `HTTPDaemon : Daemon`; a minimal static-file HTTP server combining `HTTPServer` with `Service`.
- **`httpload`** (`HTTPLoad.cpp`) — `HTTPLoad : Thread` (with nested `LoadCmd`); scriptable multithreaded HTTP load generator built on `HTTPClient`. Supports GET (optional keep-alive) and POST with data from a file or directory.
- **`smtpload`** (`SMTPLoad.cpp`) — `SMTPLoad : Thread` (with nested `LoadCmd`); scriptable multithreaded SMTP load generator built on `SMTPClient`. Supports random RCPT TO addresses and DATA from a file or directory.
