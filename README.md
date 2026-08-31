# Blister

Lightweight, high-performance C++ library for building async I/O servers and clients.

- epoll/kqueue/poll-based reactor (`Dispatch`)
- config parsing (property or ini style)
- logging (rollover, syslog/mail alerts, multi-process safe)
- cross-platform sockets (IPv4/IPv6/UNIX, non-blocking I/O)
- threading primitives (thread pools, spin/ticket/futex locks, lock-free semaphore)
- HTTP and SMTP client/server protocol support

Targets Linux, Solaris, macOS, BSD, and Windows (via a POSIX emulation layer).

## Build

Requires CMake >= 3.20 and a C++23 compiler.

```sh
cmake -DCMAKE_BUILD_TYPE=Release .
make -j4
ctest
```

`build/build [check|tsan] [BuildType]` wraps the same steps (reconfigure + build); pass `check` to enable static analysis or `tsan` for ThreadSanitizer.

## Layout

- `lib/` — the library; see [lib/README.md](lib/README.md) for what each header/class provides.
- `test/` — sample programs and load-test tools built on top of it (not unit tests); see [test/README.md](test/README.md). `echotest` is the canonical client+server example.

## License

Apache License 2.0 — see [LICENSE](LICENSE).
