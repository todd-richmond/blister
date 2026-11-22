/*
 * Copyright 2001-2026 Todd Richmond
 *
 * This file is part of Blister - a light weight, scalable, high performance
 * C++ server framework.
 *
 * Licensed under the Apache License, Version 2.0 (the "License").
 * You may not use this file except in compliance with the License. You may
 * obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef TLSSocket_h
#define TLSSocket_h

#include <unordered_map>
#include "Config.h"
#include "HTTPClient.h"
#include "HTTPServer.h"
#include "SMTPClient.h"
#include "Socket.h"
#include "Thread.h"

#ifdef _WIN32
struct SChannelCreds;
#else
struct ssl_ctx_st;
struct ssl_session_st;
struct ssl_st;
#endif

/*
 * OpenSSL (Windows: SChannel) context configured by "tls.*" keys. layer()
 * makes a connected Socket TLS: run Socket::handshake() or
 * DispatchIOSocket::handshake() next. A server without tls.certfile
 * self-signs tls.keyfile, a PEM ~/.ssh/id_* key or an ephemeral EC key
 * (Windows: a persisted "Blister TLS" CNG key). Clients verify the peer's
 * chain against the system or tls.cacert* CAs and its host name or IP unless
 * tls.verify is false and resume sessions per host and peer address. init()
 * may be called again to reload. Built without TLS, a server init() with
 * tls.enable and every layer() fail
 */
class BLISTERTLS TLSContext: nocopy {
public:
    struct Info {
	int bits = 0;
	tstring cipher, cn, group, issuer, subject, verify, verifyerr, version;
    };

    explicit TLSContext(bool server = true): srv(server) {}
    ~TLSContext();

    bool enabled(void) const {
	return ctx.load(memory_order_relaxed) != nullptr;
    }
    // layer() with the peer's SNI, then a blocking handshake
    bool handshake(Socket &s, const Sockaddr &peer) const;
    bool init(const Config &cfg, const tchar *sect, tstring &err);
    // host is the client SNI and verified name
    bool layer(Socket &s, const tchar *host = nullptr) const;
    bool server(void) const { return srv; }

    // shared client context: verifies unless reloaded with tls.verify false
    static TLSContext &client(void);
    static Info info(const Socket &s);
    // host name for SNI, empty for an address without one
    static tstring sni(const Sockaddr &sa);

private:
#ifdef _WIN32
    atomic<SChannelCreds *> ctx = nullptr;
#else
    void clear(void);
    static int onsession(ssl_st *ssl, ssl_session_st *sess);

    atomic<ssl_ctx_st *> ctx = nullptr;
    unordered_map<string, ssl_session_st *, strhash, streq> sessions;
#endif
    mutable RWLock lock;
    const bool srv;
};

// HTTPS when tlsctx is enabled, else plain HTTP
class BLISTERTLS HTTPTLSServer: public HTTPServerSocket {
public:
    using HTTPServerSocket::HTTPServerSocket;

    void start(void) override {
	if (tlsctx.enabled())
	    starttls();
	else
	    HTTPServerSocket::start();
    }
    // TLS over the connection, then serve requests
    void starttls(void);
    // GET /check expecting "OK", with TLS when tlsctx is enabled
    static bool check(const Sockaddr &addr, uint msec, tstring &err);

    static TLSContext tlsctx;

private:
    DSP_DECLARE(HTTPTLSServer, shake);
};

/*
 * HTTPClient that connects with TLS when tls(true) or sect.tls.enable is set
 * or upgrades a connection with starttls()
 */
class BLISTERTLS HTTPTLSClient: public HTTPClient {
public:
    explicit HTTPTLSClient(TLSContext &ctx = TLSContext::client()):
	tctx(ctx) {}

    void configure(const Config &cfg, const tchar *sect) {
	implicit = cfg.get(T("tls.enable"), false, sect);
    }
    bool secure(void) const { return sock.layer() != nullptr; }
    // TLS over the current connection, such as a shared fd or proxy tunnel
    bool starttls(void);
    // TLS for later connects
    void tls(bool on) { implicit = on; }

protected:
    bool onconnect(void) override { return !implicit || starttls(); }

private:
    TLSContext &tctx;
    bool implicit = false;
};

// AsyncHTTPClient with TLS at connect for tls(true) or sect.tls.enable
class BLISTERTLS AsyncHTTPTLSClient: public AsyncHTTPClient {
public:
    AsyncHTTPTLSClient(Dispatcher &d, const Sockaddr &sa, Timing *tm = nullptr,
	TLSContext &ctx = TLSContext::client()): AsyncHTTPClient(d, sa, tm),
	tctx(ctx) {}
    AsyncHTTPTLSClient(DispatchObj &parent, const Sockaddr &sa, Timing *tm =
	nullptr, TLSContext &ctx = TLSContext::client()):
	AsyncHTTPClient(parent, sa, tm), tctx(ctx) {}

    void configure(const Config &cfg, const tchar *sect) {
	implicit = cfg.get(T("tls.enable"), false, sect);
    }
    // TLS for later connects
    void tls(bool on) { implicit = on; }

protected:
    bool onconnect(Socket &s) override {
	return !implicit || tctx.layer(s, TLSContext::sni(addr).c_str());
    }

private:
    TLSContext &tctx;
    bool implicit = false;
};

/*
 * SMTP client (B is SMTPClient or AsyncSMTPClient) with implicit TLS (SMTPS)
 * when tls(true) or sect.tls.enable is set. ehlo() and lhlo() run STARTTLS
 * and greet again when starttls(true) or sect.starttls.enable is set and
 * fail if the server does not offer it
 */
template<class B>
class SMTPTLSClientT: public B {
public:
    using B::B;

    void configure(const Config &cfg, const tchar *sect) {
	implicit = cfg.get(T("tls.enable"), false, sect);
	upgrade = cfg.get(T("starttls.enable"), false, sect);
    }
    void context(TLSContext &ctx) { tctx = &ctx; }
    bool ehlo(const tchar *domain = nullptr) { return greet(false, domain); }
    bool lhlo(const tchar *domain = nullptr) { return greet(true, domain); }
    bool secure(void) const { return this->sock.layer() != nullptr; }
    // STARTTLS now: send EHLO again for the new extensions
    bool starttls(void);
    // STARTTLS in later ehlo() and lhlo() calls
    void starttls(bool on) { upgrade = on; }
    // implicit TLS for later connects
    void tls(bool on) { implicit = on; }

protected:
    // NOLINTNEXTLINE(portability-template-virtual-member-function)
    bool onconnect(void) override {
	return !implicit || tctx->handshake(this->sock, this->peer);
    }

private:
    bool greet(bool lmtp, const tchar *domain);

    TLSContext *tctx = &TLSContext::client();
    bool implicit = false, upgrade = false;
};

using AsyncSMTPTLSClient = SMTPTLSClientT<AsyncSMTPClient>;
using SMTPTLSClient = SMTPTLSClientT<SMTPClient>;

#ifndef BUILD_BLISTERTLS	// MSVC: dllexport and extern are incompatible
extern template class BLISTERTLS SMTPTLSClientT<AsyncSMTPClient>;
extern template class BLISTERTLS SMTPTLSClientT<SMTPClient>;
#endif

#endif // TLSSocket_h
