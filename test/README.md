# test/

Sample and load-test programs for `lib/`. Only `hashtest` (the `HashFunctors` ctest target) is an automated test.

- `cfg` — `Config`: file lookup.
- `dlog` — `Log`: rollover, multi-process writes, syslog and mail.
- `dtiming` — `Timing`: pretty-prints timing data.
- `hashtest` — `stdapi.h` hash functors.
- `daemonize` — `Daemon`: wraps a child process as a watched, auto-restarting daemon.
- `echotest` — `Dispatcher`: canonical reactor client and server.
- `httptest` — `HTTPServer` + `AsyncHTTPClient`/`HTTPClient`: POST echo stress test with the same CLI as `echotest`
- `httpload` — `HTTPClient`: scriptable multithreaded HTTP load generator.
- `smtpload` — `SMTPClient`: scriptable multithreaded SMTP load generator.
- `smtpsink` — `Dispatcher`: SMTP/LMTP server that discards mail.
- `uhttpd` — `HTTPServer`: minimal static-file server.
- `uvechotest` — `Dispatcher` comparison: libuv echo with the same CLI as `echotest`; built only if libuv is found.
