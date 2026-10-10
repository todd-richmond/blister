# test/

Sample and load-test programs for `lib/`. Only `hashtest` (the `HashFunctors` ctest target) is an automated test.

- `cfg` — `Config`: file lookup.
- `dlog` — `Log`: rollover, multi-process writes, syslog and mail.
- `dtiming` — `Timing`: pretty-prints timing data.
- `hashtest` — `stdapi.h` hash functors.
- `daemonize` — `Daemon`: wraps a child process as a watched, auto-restarting daemon.
- `echotest` — `Dispatcher`: canonical reactor client and server.
- `uvechotest` — `Dispatcher` comparison: libuv echo with the same CLI as `echotest`; built only if libuv is found.
- `uhttpd` — `HTTPServer`: minimal static-file server.
- `httpload` — `HTTPClient`: scriptable multithreaded load generator.
- `smtpload` — `SMTPClient`: scriptable multithreaded load generator.
