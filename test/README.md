# test/

Sample and load-test programs for `lib/`. `ctest` runs `hashtest` (`HashFunctors`), `echotest` and `httptest` (`EchoTest`, `HTTPTest`: 1000000 loops) and, when built with TLS, their `-ssl` runs (`EchoTestTLS`, `HTTPTestTLS`: 500000 loops); a non-zero exit fails the test. The network programs link `libblistertls`; their TLS options fail when it was built without TLS. They exit non-zero when they cannot run their test: a failed start, listen, connect or TLS setup, or any failed operation.

- `cfg` — `Config`: look up, check, update or erase keys from the shell.
- `dlog` — `Log`: rollover, multi-process writes, syslog and mail.
- `dtiming` — `Timing`: pretty-prints timing data.
- `hashtest` — `stdapi.h` hash functors.
- `daemonize` — `Daemon`: wraps a child process as a watched, auto-restarting daemon.
- `echotest` — `Dispatcher`: canonical reactor client and server. `-ssl` uses TLS.
- `httptest` — `HTTPServer` + `AsyncHTTPClient`/`HTTPClient`: POST echo stress test with the same CLI as `echotest`. `-ssl` uses HTTPS.
- `httpload` — `HTTPClient`: scriptable multithreaded HTTP load generator. Accepts `https://` URLs.
- `smtpload` — `SMTPClient`: scriptable multithreaded SMTP load generator. Script commands `starttls` and `connect tls` (SMTPS).
- `smtpsink` — `Dispatcher`: SMTP/LMTP server that discards mail. Offers STARTTLS with a self-signed cert when built with TLS.
- `uhttpd` — `HTTPServer`: minimal static-file server for `htdocs/`. `./uhttpd console start -s` serves HTTPS with a self-signed cert, or set `httpd.http.tls.*` keys. On Unix it is an `MPHTTPServer`: `httpd.worker.count` > 1 forks prefork workers, and HTTP or HTTPS adds `/check`, `/metrics`, `/timing`, `/version`, `GET /pid` and POST replies with the body size and checksum.
- `uvechotest` — `Dispatcher` comparison: libuv echo with the same CLI as `echotest`; built only if libuv is found.
