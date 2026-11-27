# lib/ notes

## Portability constraints
- No embedded NULs in project text (`tchar *`, `tstring`, `tstring_view`); binary I/O still uses explicit lengths.
- Shared library on glibc 2.28: no libc `gettid()` or `pthread_clockjoin_np()`, `thread_local` destructors, or large `thread_local` objects (static TLS eats small thread stacks on older glibc).
- Use `Thread::current()` for managed-thread identity; `THREAD_ID()` can be a syscall. Preserve `movehigh()` where stdio needs low descriptors; Linux doesn't need it after `accept4(..., SOCK_CLOEXEC)`.
- Windows `iovec` is `WSABUF` (length first): assign fields by name. Cast vector counts to `decltype(msgh.msg_iovlen)` on POSIX; signedness varies.

## Lifecycle and I/O
- Dispatcher: `olock` protects flags/ready groups, `tlock` protects timers/poll arming. Portable code needing both `slock` and `olock` takes `slock` first. Keep the shutdown/ready recheck after waiter registration; wakes before registration can be dropped.
- Epoll registrations persist and are edge-triggered. Preserve cached interest/drain fast paths; `EPOLLEXCLUSIVE` accept loops drain the backlog. Deferred reclamation protects `erase()` against an already-returned event batch, not direct destruction or concurrent close/reopen.
- `Socket` copies share `SocketBuf`; `close()` closes the underlying descriptor for all aliases. Assign `SOCK_INVALID` to detach without closing another owner's descriptor.
- TLS uses `Sockaddr::requestedhost()` for DNS identity, otherwise the peer IP; never use the display/reverse name. Endpoint equality omits DNS identity, so check it separately on reuse. OpenSSL connections retain `SSL_CTX`; callback state must live with that context.
- For EINTR retries on a finite deadline, capture the start/deadline before blocking; skip clocks for zero/infinite waits and avoid rereading after success or final timeout.
- Automatic HTTP retries must not replay non-idempotent requests after known or uncertain write progress; a TLS write can send data without reporting plaintext bytes.
- Async SMTP only makes recipient/final reply waits asynchronous. Parse incrementally without blocking on the dispatcher or requiring the whole reply batch to fit in the stream buffer.
- Server reply iovecs borrow their buffers until send completion. Keep mapped POST data alive through completion/destruction; use `bufferstream::view()` for length-delimited output.

## String literal fast paths (`stdapi.h`)
- `strkey`/`strikey`: const array → consteval length/hash; runtime → hash 0, hashed on lookup. Use `basic_strkey<char, true>` for narrow HTTP headers in the root.
- `strlit`: literal only for APIs retaining the pointer or trusting the content (e.g. `TimingEntry`, `SMTPClient::cmd`). `consteval` rejects `tbl[i]` and non-static local const arrays: pass `+tbl[i]` when intended as runtime data.
- Non-template `f(const T *)` beats `template<size_t N> f(const T (&)[N])`: use `template<cstr_ptr P> f(P &&)` for the pointer path.
- `const T &` loses array element const for deduction; use `T &&` with `const_array`/`cstr_ptr` to keep mutable buffers on the runtime path.
- Log `wraparg` normalizes literal, pointer/buffer, and scalar arguments to share `_log` instantiations. Don't replace it with per-literal templates in the runtime sink.
- Keep `charhash`/`string*hash` `__forceinline`; `rapid_hash`/`bernstein_hash` inline constant data only, not at `-Os`. Case-insensitive wide hashing uses Unicode folding; non-ASCII wide literal keys defer hashing to runtime.
- A requires-clause is not complete-class context: forward-declare nested types used there.

## Verification
- Extract the TU command: `jq -r '.[] | select(.file | endswith("/lib/X.cpp")) | .command' compile_commands.json`. For one-off compile/asm, remove PCH and LTO flags but include `stdapi.h` first; use `-U_FORTIFY_SOURCE` at `-O0`. On this VM, point Clang at the configured GCC toolchain if it picks an older libstdc++.
- Assembly: compile a realistic TU with `extern "C"` probe functions at `-O0/-O2/-Os`; inspect calls, loads, and branches rather than inferring speedups from syntax.
- Scratch probes can link `lib/libblister.a` with `-pthread -ldl` and `-lrt` where needed. Use headers and binaries from the same build revision. Instrumenting one TU is not a whole-library sanitizer build.
- For string changes, assert compile-time hashes and compare against runtime `stringhash`/`stringihash` on equivalent data.
