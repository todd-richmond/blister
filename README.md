# Blister

[![CodeQL](https://github.com/todd-richmond/blister/actions/workflows/codeql.yml/badge.svg)](https://github.com/todd-richmond/blister/actions/workflows/codeql.yml)
[![MSVC](https://github.com/todd-richmond/blister/actions/workflows/msvc.yml/badge.svg)](https://github.com/todd-richmond/blister/actions/workflows/msvc.yml)

Lightweight, high-performance C++ library for building async I/O servers and clients.

| Area | What you get |
| --- | --- |
| **Reactor** | epoll/kqueue/devpoll/poll event loop (`Dispatch`) with timers and per-connection handlers |
| **Config** | property or ini style parsing, prefix scoping, `${key}` expansion, typed get/set |
| **Logging** | rollover, syslog/mail alerts, multi-process safe |
| **Sockets** | IPv4/IPv6/UNIX, CIDR matching, non-blocking I/O, iostream adapters |
| **Threading** | thread pools, spin/ticket/futex locks, lock-free semaphore |
| **Protocols** | HTTP and SMTP/LMTP client and server |

Targets Linux, Solaris, macOS, BSD, and Windows (via a POSIX emulation layer).

## Build

Requires CMake >= 3.20 and a C++23 compiler.

```sh
cmake -DCMAKE_BUILD_TYPE=Release .
make -j4
ctest
```

`build/build [check|tsan] [BuildType]` wraps the same steps (reconfigure + build); pass `check` to enable static analysis or `tsan` for ThreadSanitizer.

Other build systems:

| Platform | How |
| --- | --- |
| UNIX with automake | `./configure && make` |
| macOS with Xcode | open `build/Blister.xcodeproj` |
| Windows with Visual Studio | open `build/Blister.sln` |

### CMake options

| Option | Effect |
| --- | --- |
| `CHECK_CLANG_TIDY`, `CHECK_CPPCHECK`, `CHECK_CPPLINT`, `CHECK_IWYU` | run that static analyzer during the build; `CHECK_ALL` enables clang-tidy, cppcheck and cpplint |
| `CHECK_TSAN=<sanitizer>` | sanitizer build (`ON` means thread) |
| `PGO=generate\|use` | profile-guided optimization; profiles live in `.pgo/` |
| `COMPILE_PCH` | precompiled headers (default on) |

`configure` has equivalents for the sanitizer and PGO builds: `--enable-tsan` and `--with-pgo=generate|use`.

## Try it

`echotest` is an echo server and load-generating client built on the reactor. By default one process runs both, so this runs 200,000 loops using 20 sockets and up to 20 threads:

```sh
test/echotest -l 2000000
```

Add `-s` to run only the server, or `-c` to run only the client against a server started elsewhere.

See [test/README.md](test/README.md) for the other sample programs, including HTTP and SMTP servers and load generators.

## Layout

- `lib/` — the library; see [lib/README.md](lib/README.md) for what each header/class provides.
- `test/` — sample programs and load-test tools built on top of it (not unit tests); see [test/README.md](test/README.md). `echotest` is the canonical client+server example.
- `build/` — Xcode and Visual Studio projects, helper scripts and IDE settings.

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
