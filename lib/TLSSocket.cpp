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

#include "stdapi.h"
#ifndef BLISTER_TLS
#elif defined(_WIN32)
#include <fstream>
#define SCHANNEL_USE_BLACKLISTS
#define SECURITY_WIN32
#include <wincrypt.h>
#include <subauth.h>
#include <schannel.h>
#include <security.h>
#include <ncrypt.h>
#else
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509v3.h>
#endif
#include "Log.h"
#include "TLSSocket.h"

#ifndef BLISTER_TLS
// built without SChannel or OpenSSL: TLS requests fail

TLSContext::~TLSContext() = default;

bool TLSContext::init(const Config &cfg, const tchar *sect, tstring &err) {
    if (srv && cfg.get(T("tls.enable"), false, sect)) {
	err = T("TLS not available");
	return false;
    }
    err.clear();
    return true;
}

TLSContext::Info TLSContext::info(const Socket &) { return {}; }

bool TLSContext::layer(Socket &s, const tchar *) const {
    s.err(EPROTONOSUPPORT);
    return false;
}

#elif defined(_WIN32)
static constexpr ulong INBUF = 32 * 1024; // over one maximum TLS record
static constexpr wchar_t KEYNAME[] = L"Blister TLS";
static constexpr ulong RECORDS = 4; // encrypted per send

static tstring syserr(long code) {
    wchar_t buf[256];
    DWORD n = FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM |
	FORMAT_MESSAGE_IGNORE_INSERTS, nullptr, (DWORD)code, 0, buf,
	sizeof (buf) / sizeof (*buf), nullptr);

    while (n && (buf[n - 1] == L'\n' || buf[n - 1] == L'\r' ||
	buf[n - 1] == L'.'))
	--n;
    if (!n)
	return format(T("error {:#x}"), (ulong)code);
    buf[n] = L'\0';
    return wchartotstring(buf);
}

static bool readfile(const tstring &path, string &data) {
    ifstream in(path.c_str(), ios::binary);

    if (!in)
	return false;
    data.assign(istreambuf_iterator<char>(in), istreambuf_iterator<char>());
    return true;
}

// PEM bundle or one DER certificate
static HCERTSTORE loadcas(const tstring &path) {
    static constexpr char BEGIN[] = "-----BEGIN CERTIFICATE-----";
    static constexpr char END[] = "-----END CERTIFICATE-----";
    string data;
    HCERTSTORE store;
    bool any = false;

    if (!readfile(path, data) || (store = CertOpenStore(
	CERT_STORE_PROV_MEMORY, 0, 0, 0, nullptr)) == nullptr)
	return nullptr;
    for (size_t pos = 0; (pos = data.find(BEGIN, pos)) != data.npos; ) {
	size_t end = data.find(END, pos);
	DWORD len = 0;

	if (end == data.npos)
	    break;
	end += sizeof (END) - 1;
	if (CryptStringToBinaryA(data.data() + pos, (DWORD)(end - pos),
	    CRYPT_STRING_BASE64HEADER, nullptr, &len, nullptr, nullptr)) {
	    vector<BYTE> der(len);

	    if (CryptStringToBinaryA(data.data() + pos, (DWORD)(end - pos),
		CRYPT_STRING_BASE64HEADER, der.data(), &len, nullptr,
		nullptr) && CertAddEncodedCertificateToStore(store,
		X509_ASN_ENCODING, der.data(), len, CERT_STORE_ADD_ALWAYS,
		nullptr))
		any = true;
	}
	pos = end;
    }
    if (!any && !data.empty() && CertAddEncodedCertificateToStore(store,
	X509_ASN_ENCODING, (const BYTE *)data.data(), (DWORD)data.size(),
	CERT_STORE_ADD_ALWAYS, nullptr))
	any = true;
    if (!any) {
	CertCloseStore(store, 0);
	return nullptr;
    }
    return store;
}

// a PKCS#12 file, else a subject in the user's personal store
static PCCERT_CONTEXT loadcert(const tstring &path, const tstring &pass) {
    constexpr DWORD ENC = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
    string data;
    PCCERT_CONTEXT cert = nullptr;
    HCERTSTORE store;

    if (readfile(path, data)) {
	CRYPT_DATA_BLOB blob = { (DWORD)data.size(), (BYTE *)data.data() };

	if (!PFXIsPFXBlob(&blob))
	    return nullptr;
	// SChannel can't use non-persisted keys
	if ((store = PFXImportCertStore(&blob, tstringtowchar(pass),
	    CRYPT_USER_KEYSET)) != nullptr)
	    cert = CertFindCertificateInStore(store, ENC, 0,
		CERT_FIND_HAS_PRIVATE_KEY, nullptr, nullptr);
    } else if ((store = CertOpenStore(CERT_STORE_PROV_SYSTEM_W, 0, 0,
	CERT_SYSTEM_STORE_CURRENT_USER | CERT_STORE_READONLY_FLAG,
	L"MY")) != nullptr) {
	cert = CertFindCertificateInStore(store, ENC, 0,
	    CERT_FIND_SUBJECT_STR_W, tstringtowchar(path), nullptr);
    }
    if (store)
	CertCloseStore(store, 0);
    return cert;
}

static void systime(ULONGLONG off, bool add, SYSTEMTIME &st) {
    FILETIME ft;
    ULARGE_INTEGER t;

    GetSystemTimeAsFileTime(&ft);
    t.LowPart = ft.dwLowDateTime;
    t.HighPart = ft.dwHighDateTime;
    t.QuadPart = add ? t.QuadPart + off * 10000000 : t.QuadPart - off *
	10000000;
    ft.dwLowDateTime = t.LowPart;
    ft.dwHighDateTime = t.HighPart;
    FileTimeToSystemTime(&ft, &st);
}

// self-signed cert for a persisted P-256 key reused across runs
static PCCERT_CONTEXT selfsign(void) {
    char ahost[256] = {};
    BYTE ip4[4] = { 127, 0, 0, 1 }, ip6[16] = {}, name[512];
    CERT_ALT_NAME_ENTRY alt[4] = {};
    CERT_ALT_NAME_INFO altinfo = { 4, alt };
    CRYPT_ALGORITHM_IDENTIFIER alg = {};
    PCCERT_CONTEXT cert = nullptr;
    SYSTEMTIME end, start;
    CERT_EXTENSION ext = {};
    CERT_EXTENSIONS exts = { 1, &ext };
    wstring host;
    NCRYPT_KEY_HANDLE key = 0;
    CRYPT_KEY_PROV_INFO kpi = {};
    wchar_t localhost[] = L"localhost";
    DWORD namelen = sizeof (name), sanlen = 0;
    NCRYPT_PROV_HANDLE prov = 0;
    BYTE *san = nullptr;
    SECURITY_STATUS st;

    if (gethostname(ahost, sizeof (ahost) - 1) || !*ahost)
	strcpy(ahost, "localhost");
    host = achartowstring(ahost);
    if ((st = NCryptOpenStorageProvider(&prov, MS_KEY_STORAGE_PROVIDER, 0)) !=
	ERROR_SUCCESS) {
	SetLastError((DWORD)st);
	return nullptr;
    }
    if (NCryptOpenKey(prov, &key, KEYNAME, 0, 0) != ERROR_SUCCESS) {
	key = 0;
	if ((st = NCryptCreatePersistedKey(prov, &key,
	    BCRYPT_ECDSA_P256_ALGORITHM, KEYNAME, 0, 0)) == ERROR_SUCCESS)
	    st = NCryptFinalizeKey(key, 0);
	if (st != ERROR_SUCCESS) {
	    if (key)
		NCryptFreeObject(key);
	    NCryptFreeObject(prov);
	    SetLastError((DWORD)st);
	    return nullptr;
	}
    }
    ip6[15] = 1;
    alt[0].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
    alt[0].pwszDNSName = host.data();
    alt[1].dwAltNameChoice = CERT_ALT_NAME_DNS_NAME;
    alt[1].pwszDNSName = localhost;
    alt[2].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
    alt[2].IPAddress = { sizeof (ip4), ip4 };
    alt[3].dwAltNameChoice = CERT_ALT_NAME_IP_ADDRESS;
    alt[3].IPAddress = { sizeof (ip6), ip6 };
    if (CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &altinfo,
	CRYPT_ENCODE_ALLOC_FLAG, nullptr, &san, &sanlen) &&
	CertStrToNameW(X509_ASN_ENCODING, (L"CN=" + host).c_str(),
	CERT_X500_NAME_STR, nullptr, name, &namelen, nullptr)) {
	CERT_NAME_BLOB subj = { namelen, name };

	ext.pszObjId = (LPSTR)szOID_SUBJECT_ALT_NAME2;
	ext.Value = { sanlen, san };
	kpi.pwszContainerName = (LPWSTR)KEYNAME;
	kpi.pwszProvName = (LPWSTR)MS_KEY_STORAGE_PROVIDER;
	alg.pszObjId = (LPSTR)szOID_ECDSA_SHA256;
	systime(3600, false, start);
	systime(365ULL * 86400, true, end);
	cert = CertCreateSelfSignCertificate(key, &subj, 0, &kpi, &alg, &start,
	    &end, &exts);
    }
    LocalFree(san);
    NCryptFreeObject(key);
    NCryptFreeObject(prov);
    return cert;
}

struct SChannelCreds: RefCount {
    SChannelCreds() { SecInvalidateHandle(&h); }
    ~SChannelCreds() {
	if (SecIsValidHandle(&h))
	    FreeCredentialsHandle(&h);
	if (cert)
	    CertFreeCertificateContext(cert);
	if (engine)
	    CertFreeCertificateChainEngine(engine);
	if (roots)
	    CertCloseStore(roots, 0);
    }

    PCCERT_CONTEXT cert = nullptr;
    HCERTCHAINENGINE engine = nullptr; // tls.cacertfile roots, else system
    CredHandle h;
    bool mutual = false, verify = false;
    HCERTSTORE roots = nullptr;
};

// 0 or the chain and name policy error
static DWORD verifychain(const SChannelCreds &c, PCCERT_CONTEXT cert,
    const wchar_t *name, bool client) {
    LPSTR usage[] = { (LPSTR)(client ? szOID_PKIX_KP_CLIENT_AUTH :
	szOID_PKIX_KP_SERVER_AUTH) };
    PCCERT_CHAIN_CONTEXT chain = nullptr;
    HTTPSPolicyCallbackData https = {};
    CERT_CHAIN_PARA para = {};
    CERT_CHAIN_POLICY_PARA ppara = {};
    CERT_CHAIN_POLICY_STATUS pstat = {};
    DWORD ret;

    para.cbSize = sizeof (para);
    para.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
    para.RequestedUsage.Usage.cUsageIdentifier = 1;
    para.RequestedUsage.Usage.rgpszUsageIdentifier = usage;
    if (!CertGetCertificateChain(c.engine, cert, nullptr, cert->hCertStore,
	&para, 0, nullptr, &chain))
	return GetLastError();
    https.cbStruct = sizeof (https);
    https.dwAuthType = client ? AUTHTYPE_CLIENT : AUTHTYPE_SERVER;
    https.pwszServerName = (wchar_t *)name;
    ppara.cbSize = sizeof (ppara);
    ppara.pvExtraPolicyPara = &https;
    pstat.cbSize = sizeof (pstat);
    ret = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain,
	&ppara, &pstat) ? pstat.dwError : GetLastError();
    CertFreeCertificateChain(chain);
    return ret;
}

/*
 * SChannel stream installed on a SocketBuf. Records are decrypted in place
 * in ibuf and up to RECORDS are encrypted into obuf per send. A blocked send
 * keeps its records and reports them on the caller's retry of the same data
 */
class DLL_LOCAL TLSLayer: public SocketLayer {
public:
    TLSLayer(SChannelCreds *c, socket_t s, bool server, const tstring &name,
	bool hostname): creds(c), fd(s), ibuf(new char[INBUF]),
	sni(hostname), srv(server), target(tstringtowstring(name)) {
	SecInvalidateHandle(&ctxt);
    }
    ~TLSLayer() override {
	if (SecIsValidHandle(&ctxt))
	    DeleteSecurityContext(&ctxt);
	if (creds->release())
	    delete creds;
    }

    tstring errstr(void) const override { return tlserr; }
    long handshake(const Socket &s) override;
    long read(const Socket &s, void *buf, ulong len) override;
    void shutdown(void) override;
    uint state(void) const override {
	// whole record buffered
	bool rec = ilen >= 5 && ilen >= 5 + ((ulong)(uchar)ibuf[3] << 8 |
	    (uchar)ibuf[4]);

	return flags | (dlen || rec ? (uint)Pending : 0U);
    }
    long write(const Socket &s, const iovec *iov, int count) override;

    CtxtHandle ctxt;
    tstring verify, verifyerr;

private:
    void append(const void *p, ulong len);
    bool checkpeer(void);
    void compact(void);
    SECURITY_STATUS decrypt(void);
    long fail(const Socket &s, const tstring &err);
    long flush(const Socket &s);
    long recvmore(const Socket &s);
    void reserve(ulong cap);
    SECURITY_STATUS step(void);

    SChannelCreds *creds;
    bool done = false, renego = false;
    char *dptr = nullptr;
    ulong dlen = 0, ilen = 0, ocap = 0, olen = 0, ooff = 0, pend = 0;
    socket_t fd;
    uint flags = 0;
    unique_ptr<char[]> ibuf, obuf;
    const bool sni, srv;
    SecPkgContext_StreamSizes sizes = {};
    wstring target;
    tstring tlserr;
    ulong xlen = 0, xoff = 0;
};

void TLSLayer::append(const void *p, ulong len) {
    reserve(olen + len);
    memcpy(obuf.get() + olen, p, len);
    olen += len;
}

// chain and name check that only rejects when verifying
bool TLSLayer::checkpeer(void) {
    PCCERT_CONTEXT cert = nullptr;
    DWORD e;

    if (!srv && !creds->verify) {
	verify = T("NOT");
	return true;
    }
    if (QueryContextAttributesW(&ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT,
	&cert) != SEC_E_OK || !cert) {
	verify = creds->verify || creds->mutual ? T("NO") : T("NOT");
	if (!creds->verify)
	    return true;
	tlserr = T("no peer certificate");
	return false;
    }
    e = verifychain(*creds, cert, srv || target.empty() ? nullptr :
	target.c_str(), srv);
    CertFreeCertificateContext(cert);
    if (!e) {
	verify = T("OK");
	return true;
    }
    verify = T("FAIL");
    verifyerr = syserr((long)e);
    tlserr = T("certificate verify failed: ") + verifyerr;
    return !creds->verify;
}

void TLSLayer::compact(void) {
    if (xlen)
	memmove(ibuf.get(), ibuf.get() + xoff, xlen);
    ilen = xlen;
    xlen = 0;
}

SECURITY_STATUS TLSLayer::decrypt(void) {
    SecBuffer b[4] = {
	{ ilen, SECBUFFER_DATA, ibuf.get() }, { 0, SECBUFFER_EMPTY, nullptr },
	{ 0, SECBUFFER_EMPTY, nullptr }, { 0, SECBUFFER_EMPTY, nullptr }
    };
    SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
    SECURITY_STATUS st = DecryptMessage(&ctxt, &d, 0, nullptr);

    if (st != SEC_E_OK && st != SEC_I_RENEGOTIATE &&
	st != SEC_I_CONTEXT_EXPIRED)
	return st;
    xlen = 0;
    for (const SecBuffer &sb : b) {
	if (sb.BufferType == SECBUFFER_DATA) {
	    dptr = (char *)sb.pvBuffer;
	    dlen = sb.cbBuffer;
	} else if (sb.BufferType == SECBUFFER_EXTRA) {
	    xoff = ilen - sb.cbBuffer;
	    xlen = sb.cbBuffer;
	}
    }
    if (!dlen)
	compact();
    return st;
}

long TLSLayer::fail(const Socket &s, const tstring &err) {
    tlserr = err;
    s.err(EPROTO);
    return -1;
}

long TLSLayer::flush(const Socket &s) {
    while (ooff < olen) {
	int n = ::send(fd, obuf.get() + ooff, (int)(olen - ooff), 0);

	if (n <= 0) {
	    s.err(sockerrno());
	    return -1;
	}
	ooff += (ulong)n;
    }
    olen = ooff = 0;
    return 1;
}

long TLSLayer::handshake(const Socket &s) {
    for (;;) {
	SECURITY_STATUS st;

	if (olen && flush(s) < 0) {
	    flags = 0;
	    return -1;
	}
	if (done) {
	    flags = 0;
	    return 1;
	}
	// a client starts without input
	st = ilen || (!srv && !SecIsValidHandle(&ctxt)) ? step() :
	    SEC_E_INCOMPLETE_MESSAGE;
	if (st == SEC_E_OK) {
	    if ((st = QueryContextAttributesW(&ctxt, SECPKG_ATTR_STREAM_SIZES,
		&sizes)) != SEC_E_OK)
		return fail(s, syserr(st));
	    reserve(RECORDS * (sizes.cbHeader + sizes.cbMaximumMessage +
		sizes.cbTrailer));
	    if (!checkpeer())
		return fail(s, tlserr);
	    done = true;
	} else if (st == SEC_E_INCOMPLETE_MESSAGE) {
	    long ret = recvmore(s);

	    if (ret <= 0) {
		flags = WriteReads;
		return ret;
	    }
	} else if (st != SEC_I_CONTINUE_NEEDED &&
	    st != SEC_I_INCOMPLETE_CREDENTIALS) {
	    if (olen)
		(void)flush(s);
	    return fail(s, syserr(st));
	}
    }
}

long TLSLayer::read(const Socket &s, void *buf, ulong len) {
    for (;;) {
	SECURITY_STATUS st;

	if (dlen) {
	    ulong n = min(len, dlen);

	    memcpy(buf, dptr, n);
	    dptr += n;
	    if (!(dlen -= n))
		compact();
	    flags &= ~ReadWrites;
	    return (long)n;
	}
	// post-handshake reply
	if (olen && flush(s) < 0) {
	    flags |= ReadWrites;
	    return -1;
	}
	if (!ilen)
	    st = SEC_E_INCOMPLETE_MESSAGE;
	else
	    st = renego ? step() : decrypt();
	switch (st) {
	case SEC_E_OK:
	    renego = false;
	    break;
	case SEC_I_CONTINUE_NEEDED:
	    break;
	case SEC_I_CONTEXT_EXPIRED:
	    return 0;
	case SEC_I_RENEGOTIATE:
	    // TLS 1.3 tickets and key updates go to the handshake
	    renego = true;
	    break;
	case SEC_E_INCOMPLETE_MESSAGE:
	    if (long ret = recvmore(s); ret <= 0) {
		flags &= ~ReadWrites;
		return ret;
	    }
	    break;
	default:
	    return fail(s, syserr(st));
	}
    }
}

long TLSLayer::recvmore(const Socket &s) {
    int n;

    if (ilen == INBUF)
	return fail(s, T("TLS record too large"));
    if ((n = ::recv(fd, ibuf.get() + ilen, (int)(INBUF - ilen), 0)) > 0)
	ilen += (ulong)n;
    else if (n < 0)
	s.err(sockerrno());
    return n;
}

void TLSLayer::reserve(ulong cap) {
    char *p;

    if (cap <= ocap)
	return;
    p = new char[cap];
    if (olen)
	memcpy(p, obuf.get(), olen);
    obuf.reset(p);
    ocap = cap;
}

// one-way close_notify: don't wait for the peer's
void TLSLayer::shutdown(void) {
    DWORD type = SCHANNEL_SHUTDOWN;
    SecBuffer b = { sizeof (type), SECBUFFER_TOKEN, &type };
    SecBufferDesc d = { SECBUFFER_VERSION, 1, &b };

    if (!done || ApplyControlToken(&ctxt, &d) != SEC_E_OK)
	return;
    ilen = 0;
    (void)step();
    if (olen > ooff)
	(void)::send(fd, obuf.get() + ooff, (int)(olen - ooff), 0);
    olen = ooff = 0;
}

// one handshake call on ibuf: output is queued and unused input kept
SECURITY_STATUS TLSLayer::step(void) {
    constexpr ULONG ASC = ASC_REQ_ALLOCATE_MEMORY | ASC_REQ_CONFIDENTIALITY |
	ASC_REQ_EXTENDED_ERROR | ASC_REQ_REPLAY_DETECT |
	ASC_REQ_SEQUENCE_DETECT | ASC_REQ_STREAM;
    // checkpeer() verifies the server
    constexpr ULONG ISC = ISC_REQ_ALLOCATE_MEMORY | ISC_REQ_CONFIDENTIALITY |
	ISC_REQ_EXTENDED_ERROR | ISC_REQ_MANUAL_CRED_VALIDATION |
	ISC_REQ_REPLAY_DETECT | ISC_REQ_SEQUENCE_DETECT | ISC_REQ_STREAM;
    ULONG attr;
    SecBuffer ib[2] = {
	{ ilen, SECBUFFER_TOKEN, ibuf.get() }, { 0, SECBUFFER_EMPTY, nullptr }
    };
    SecBufferDesc id = { SECBUFFER_VERSION, 2, ib };
    SecBuffer ob[2] = {
	{ 0, SECBUFFER_TOKEN, nullptr }, { 0, SECBUFFER_ALERT, nullptr }
    };
    SecBufferDesc od = { SECBUFFER_VERSION, 2, ob };
    PCtxtHandle cur = SecIsValidHandle(&ctxt) ? &ctxt : nullptr;
    SECURITY_STATUS st;

    if (srv)
	st = AcceptSecurityContext(&creds->h, cur, ilen ? &id : nullptr, ASC |
	    (creds->mutual ? ASC_REQ_MUTUAL_AUTH : 0), 0, &ctxt, &od, &attr,
	    nullptr);
    else
	st = InitializeSecurityContextW(&creds->h, cur, sni ? target.data() :
	    nullptr, ISC, 0, 0, ilen ? &id : nullptr, 0, &ctxt, &od, &attr,
	    nullptr);
    for (const SecBuffer &b : ob) {
	if (!b.pvBuffer)
	    continue;
	if (b.cbBuffer && (b.BufferType == SECBUFFER_TOKEN || FAILED(st)))
	    append(b.pvBuffer, b.cbBuffer);
	FreeContextBuffer(b.pvBuffer);
    }
    if (st != SEC_E_INCOMPLETE_MESSAGE && ilen) {
	if (ib[1].BufferType == SECBUFFER_EXTRA && ib[1].cbBuffer) {
	    memmove(ibuf.get(), ibuf.get() + ilen - ib[1].cbBuffer,
		ib[1].cbBuffer);
	    ilen = ib[1].cbBuffer;
	} else {
	    ilen = 0;
	}
    }
    return st;
}

long TLSLayer::write(const Socket &s, const iovec *iov, int count) {
    const ulong rec = sizes.cbHeader + sizes.cbMaximumMessage +
	sizes.cbTrailer;
    ulong off = 0;
    long out = 0;
    int i = 0;

    flags &= ~WriteReads;
    if (olen && flush(s) < 0)
	return -1;
    // read() may have sent them
    if (pend) {
	out = (long)pend;
	pend = 0;
	return out;
    }
    for (;;) {
	ulong batch = 0;

	while (i < count && olen + rec <= ocap) {
	    SecBuffer b[4];
	    SecBufferDesc d = { SECBUFFER_VERSION, 4, b };
	    char *hdr = obuf.get() + olen, *data = hdr + sizes.cbHeader;
	    ulong n = 0;
	    SECURITY_STATUS st;

	    while (i < count && n < sizes.cbMaximumMessage) {
		ulong sz = min((ulong)iov[i].iov_len - off,
		    sizes.cbMaximumMessage - n);

		memcpy(data + n, (const char *)iov[i].iov_base + off, sz);
		n += sz;
		if ((off += sz) == (ulong)iov[i].iov_len) {
		    ++i;
		    off = 0;
		}
	    }
	    if (!n)
		break;
	    b[0] = { sizes.cbHeader, SECBUFFER_STREAM_HEADER, hdr };
	    b[1] = { n, SECBUFFER_DATA, data };
	    b[2] = { sizes.cbTrailer, SECBUFFER_STREAM_TRAILER, data + n };
	    b[3] = { 0, SECBUFFER_EMPTY, nullptr };
	    if ((st = EncryptMessage(&ctxt, 0, &d, 0)) != SEC_E_OK) {
		olen = ooff = 0;
		return fail(s, syserr(st));
	    }
	    olen += b[0].cbBuffer + b[1].cbBuffer + b[2].cbBuffer;
	    batch += n;
	}
	if (!batch)
	    return out;
	if (flush(s) < 0) {
	    pend = batch;
	    return out ? out : -1;
	}
	out += (long)batch;
    }
}

static SChannelCreds *newcreds(const Config &cfg, const tchar *sect,
    bool server, bool verify, tstring &err, tstring &keysrc) {
    unique_ptr<SChannelCreds> c(new SChannelCreds);
    tstring cafile = cfg.get(T("tls.cacertfile"), nullptr, sect);
    tstring certfile = cfg.get(T("tls.certfile"), nullptr, sect);
    tstring minver = cfg.get(T("tls.proto_min"), T("TLSv1_2"), sect);
    SCH_CREDENTIALS sc = {};
    SECURITY_STATUS st;
    TLS_PARAMETERS tp = {};
    const auto fail = [&](const tchar *msg, long code) {
	err = msg;
	err += T(": ");
	err += syserr(code);
	return nullptr;
    };

    for (const tchar *key : { T("tls.cacertpath"), T("tls.cipherlist"),
	T("tls.ciphersuites"), T("tls.crlpath"), T("tls.groups"),
	T("tls.keyfile"), T("tls.options") }) {
	if (!cfg.get(key, nullptr, sect).empty()) {
	    err = key;
	    err += T(" is not supported by SChannel");
	    return nullptr;
	}
    }
    tp.grbitDisabledProtocols = SP_PROT_SSL2 | SP_PROT_SSL3;
    if (minver == T("TLSv1_3")) {
	tp.grbitDisabledProtocols |= SP_PROT_TLS1_0 | SP_PROT_TLS1_1 |
	    SP_PROT_TLS1_2;
    } else if (minver == T("TLSv1_2")) {
	tp.grbitDisabledProtocols |= SP_PROT_TLS1_0 | SP_PROT_TLS1_1;
    } else if (minver == T("TLSv1_1")) {
	tp.grbitDisabledProtocols |= SP_PROT_TLS1_0;
    } else if (!minver.empty() && minver != T("TLSv1_0")) {
	err = T("unknown tls.proto_min");
	return nullptr;
    }
    if (!cafile.empty()) {
	CERT_CHAIN_ENGINE_CONFIG ecfg = {};

	if ((c->roots = loadcas(cafile)) == nullptr)
	    return fail(T("cannot load tls.cacertfile"), (long)GetLastError());
	ecfg.cbSize = sizeof (ecfg);
	ecfg.hExclusiveRoot = c->roots;
	if (!CertCreateCertificateChainEngine(&ecfg, &c->engine))
	    return fail(T("cannot load tls.cacertfile"), (long)GetLastError());
    }
    if (!certfile.empty()) {
	if ((c->cert = loadcert(certfile, cfg.get(T("tls.password"), nullptr,
	    sect))) == nullptr)
	    return fail(T("cannot load tls.certfile"), (long)GetLastError());
	keysrc = certfile;
    } else if (server) {
	if ((c->cert = selfsign()) == nullptr)
	    return fail(T("cannot create self-signed certificate"),
		(long)GetLastError());
	keysrc = wchartotstring(KEYNAME);
    }
    c->mutual = server && cfg.get(T("tls.request_cert"), false, sect);
    c->verify = verify;
    sc.dwVersion = SCH_CREDENTIALS_VERSION;
    if (c->cert) {
	sc.cCreds = 1;
	sc.paCred = &c->cert;
    }
    // trusted client cert issuers
    if (server)
	sc.hRootStore = c->roots;
    sc.dwFlags = SCH_USE_STRONG_CRYPTO | (server ? 0 :
	SCH_CRED_MANUAL_CRED_VALIDATION | SCH_CRED_NO_DEFAULT_CREDS);
    sc.cTlsParameters = 1;
    sc.pTlsParameters = &tp;
    if ((st = AcquireCredentialsHandleW(nullptr, (LPWSTR)UNISP_NAME_W,
	server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND, nullptr, &sc,
	nullptr, nullptr, &c->h, nullptr)) != SEC_E_OK)
	return fail(T("cannot create TLS credentials"), st);
    return c.release();
}

TLSContext::~TLSContext() {
    if (SChannelCreds *c = ctx.load(memory_order_relaxed); c && c->release())
	delete c;
}

bool TLSContext::init(const Config &cfg, const tchar *sect, tstring &err) {
    SChannelCreds *c = nullptr, *old;
    tstring keysrc;

    err.clear();
    verify = !srv && cfg.get(T("tls.verify"), true, sect);
    if (!srv || cfg.get(T("tls.enable"), false, sect)) {
	if ((c = newcreds(cfg, sect, srv, verify, err, keysrc)) == nullptr)
	    return false;
	if (srv)
	    dlogi(Log::mod(sect ? sect : T("tls")), Log::cmd(T("tls")),
		Log::kv(T("key"), keysrc));
    }
    // live layers hold their own reference
    lock.lock();
    old = ctx.exchange(c, memory_order_relaxed);
    lock.unlock();
    if (old && old->release())
	delete old;
    return true;
}

TLSContext::Info TLSContext::info(const Socket &s) {
    wchar_t buf[256];
    PCCERT_CONTEXT cert = nullptr;
    SecPkgContext_CipherInfo ci = {};
    SecPkgContext_ConnectionInfo conn = {};
    Info i;
    TLSLayer *l = static_cast<TLSLayer *>(s.layer());

    if (!l)
	return i;
    if (QueryContextAttributesW(&l->ctxt, SECPKG_ATTR_CONNECTION_INFO,
	&conn) == SEC_E_OK) {
	i.bits = (int)conn.dwCipherStrength;
	i.version = conn.dwProtocol & SP_PROT_TLS1_3 ? T("TLSv1.3") :
	    conn.dwProtocol & SP_PROT_TLS1_2 ? T("TLSv1.2") :
	    conn.dwProtocol & SP_PROT_TLS1_1 ? T("TLSv1.1") :
	    conn.dwProtocol & SP_PROT_TLS1_0 ? T("TLSv1") : T("unknown");
    }
    if (QueryContextAttributesW(&l->ctxt, SECPKG_ATTR_CIPHER_INFO, &ci) ==
	SEC_E_OK) {
	i.cipher = wchartotstring(ci.szCipherSuite);
	i.group = wchartotstring(ci.szExchange);
    }
    i.verify = l->verify;
    i.verifyerr = l->verifyerr;
    if (QueryContextAttributesW(&l->ctxt, SECPKG_ATTR_REMOTE_CERT_CONTEXT,
	&cert) != SEC_E_OK || !cert)
	return i;
    CertNameToStrW(X509_ASN_ENCODING, &cert->pCertInfo->Subject,
	CERT_X500_NAME_STR, buf, sizeof (buf) / sizeof (*buf));
    i.subject = wchartotstring(buf);
    CertNameToStrW(X509_ASN_ENCODING, &cert->pCertInfo->Issuer,
	CERT_X500_NAME_STR, buf, sizeof (buf) / sizeof (*buf));
    i.issuer = wchartotstring(buf);
    if (CertGetNameStringW(cert, CERT_NAME_ATTR_TYPE, 0,
	(void *)szOID_COMMON_NAME, buf, sizeof (buf) / sizeof (*buf)) > 1)
	i.cn = wchartotstring(buf);
    CertFreeCertificateContext(cert);
    return i;
}

bool TLSContext::layer(Socket &s, const tchar *host) const {
    SChannelCreds *c;
    tstring name(host ? host : T(""));
    Sockaddr sa;

    lock.lock_shared();
    if ((c = ctx.load(memory_order_relaxed)) != nullptr)
	c->reference();
    lock.unlock_shared();
    if (!c) {
	s.err(EPROTO);
	return false;
    }
    // no name: the cert must list the peer IP
    if (!srv && name.empty() && verify && s.peername(sa))
	name = sa.ip();
    s.layer(new TLSLayer(c, s.fd(), srv, name, host && *host));
    return true;
}

#else

template<class T, void (*F)(T *)> struct sslfree {
    void operator ()(T *p) const { F(p); }
};
using ctx_ptr = unique_ptr<SSL_CTX, sslfree<SSL_CTX, SSL_CTX_free>>;
using key_ptr = unique_ptr<EVP_PKEY, sslfree<EVP_PKEY, EVP_PKEY_free>>;
using x509_ptr = unique_ptr<X509, sslfree<X509, X509_free>>;

// drain the thread's OpenSSL error queue
static tstring sslerrors(void) {
    char buf[256];
    tstring s;

    while (ulong e = ERR_get_error()) {
	const char *r = ERR_reason_error_string(e);

	if (!r) {
	    ERR_error_string_n(e, buf, sizeof (buf));
	    r = buf;
	}
	if (!s.empty())
	    s += T(": ");
	s += achartotstring(r);
    }
    return s;
}

static string confstr(const Config &cfg, const strkey &key, const tchar *sect) {
    return tstringtoastring(cfg.get(key, nullptr, sect));
}

static EVP_PKEY *readkey(const char *path) {
    BIO *bio = BIO_new_file(path, "r");
    EVP_PKEY *key;

    if (!bio)
	return nullptr;
    // never prompt: encrypted keys fail
    key = PEM_read_bio_PrivateKey(bio, nullptr, [](char *, int, int,
	void *) { return 0; }, nullptr);
    BIO_free(bio);
    return key;
}

// PEM ~/.ssh keys, else ephemeral: OpenSSL can't parse OPENSSH format keys
static EVP_PKEY *defaultkey(tstring &src) {
    const char *home = getenv("HOME");

    if (home) {
	for (const char *name : { "id_ed25519", "id_ecdsa", "id_rsa" }) {
	    string path = format("{}/.ssh/{}", home, name);

	    if (EVP_PKEY *key = readkey(path.c_str())) {
		src = achartotstring(path.c_str());
		return key;
	    }
	}
    }
    ERR_clear_error();
    src = T("ephemeral");
    return EVP_EC_gen("P-256");
}

static X509 *selfsign(EVP_PKEY *key) {
    char host[256] = {};
    x509_ptr x(X509_new());
    BIGNUM *bn = BN_new();
    X509_EXTENSION *ext;
    X509_NAME *name;
    X509V3_CTX v3;

    if (gethostname(host, sizeof (host) - 1) || !*host)
	strcpy(host, "localhost");
    if (!x || !bn || !BN_rand(bn, 63, BN_RAND_TOP_ANY, BN_RAND_BOTTOM_ANY) ||
	!BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x.get()))) {
	BN_free(bn);
	return nullptr;
    }
    BN_free(bn);
    name = X509_get_subject_name(x.get());
    if (!X509_set_version(x.get(), X509_VERSION_3) ||
	!X509_gmtime_adj(X509_getm_notBefore(x.get()), -3600) ||
	!X509_gmtime_adj(X509_getm_notAfter(x.get()), 365L * 86400) ||
	!X509_set_pubkey(x.get(), key) || !X509_NAME_add_entry_by_txt(name,
	"CN", MBSTRING_ASC, (const uchar *)host, -1, -1, 0) ||
	!X509_set_issuer_name(x.get(), name))
	return nullptr;
    X509V3_set_ctx(&v3, x.get(), x.get(), nullptr, nullptr, 0);
    ext = X509V3_EXT_conf_nid(nullptr, &v3, NID_subject_alt_name, format(
	"DNS:{},DNS:localhost,IP:127.0.0.1,IP:::1", host).c_str());
    if (!ext)
	return nullptr;
    X509_add_ext(x.get(), ext, -1);
    X509_EXTENSION_free(ext);
    // EdDSA signs without a separate digest
    if (!X509_sign(x.get(), key, EVP_PKEY_is_a(key, "ED25519") ||
	EVP_PKEY_is_a(key, "ED448") ? nullptr : EVP_sha256()))
	return nullptr;
    return x.release();
}

/*
 * SSL wrapper installed on a SocketBuf. Each blocked op records the
 * opposite event it waits for so DispatchSocket polls for that instead
 */
class DLL_LOCAL TLSLayer: public SocketLayer {
public:
    explicit TLSLayer(SSL *s): ssl(s) {}
    ~TLSLayer() override { SSL_free(ssl); }

    tstring errstr(void) const override { return tlserr; }
    long handshake(const Socket &s) override;
    long read(const Socket &s, void *buf, ulong len) override;
    void shutdown(void) override;
    uint state(void) const override {
	return flags | (SSL_has_pending(ssl) ? (uint)Pending : 0U);
    }
    long write(const Socket &s, const iovec *iov, int count) override;

    string key; // client session cache key
    SSL *const ssl;

private:
    enum class Op: uchar { Handshake, Read, Write };

    long fail(const Socket &s, int ret, Op op);
    long send(const Socket &s, const void *buf, ulong len);

    uint flags = 0;
    tstring tlserr;
};

long TLSLayer::fail(const Socket &s, int ret, Op op) {
    switch (SSL_get_error(ssl, ret)) {
    case SSL_ERROR_WANT_READ:
	flags = op == Op::Read ? flags & ~ReadWrites : op == Op::Write ?
	    flags | WriteReads : WriteReads;
	s.err(EAGAIN);
	return -1;
    case SSL_ERROR_WANT_WRITE:
	flags = op == Op::Read ? flags | ReadWrites : op == Op::Write ?
	    flags & ~WriteReads : 0;
	s.err(EAGAIN);
	return -1;
    case SSL_ERROR_ZERO_RETURN:
	return 0;
    case SSL_ERROR_SYSCALL:
	ERR_clear_error();
	if (!sockerrno())
	    return 0;
	s.err(sockerrno());
	return -1;
    default:
	tlserr = sslerrors();
	s.err(EPROTO);
	return -1;
    }
}

long TLSLayer::handshake(const Socket &s) {
    int ret;

    ERR_clear_error();
    if ((ret = SSL_do_handshake(ssl)) == 1) {
	flags = 0;
	return 1;
    }
    return fail(s, ret, Op::Handshake);
}

long TLSLayer::read(const Socket &s, void *buf, ulong len) {
    size_t in;

    ERR_clear_error();
    if (LIKELY(SSL_read_ex(ssl, buf, len, &in))) {
	flags &= ~ReadWrites;
	return (long)in;
    }
    return fail(s, 0, Op::Read);
}

long TLSLayer::send(const Socket &s, const void *buf, ulong len) {
    size_t out;

    ERR_clear_error();
    if (LIKELY(SSL_write_ex(ssl, buf, len, &out))) {
	flags &= ~WriteReads;
	return (long)out;
    }
    return fail(s, 0, Op::Write);
}

// one-way close_notify: don't wait for the peer's
void TLSLayer::shutdown(void) {
    if (SSL_is_init_finished(ssl))
	(void)SSL_shutdown(ssl);
    ERR_clear_error();
}

/*
 * coalesce small iovecs into one record and write large ones directly. A
 * retry after a block or short count rebuilds the same leading record as
 * SSL_write requires since grouping restarts at the first unsent iovec
 */
long TLSLayer::write(const Socket &s, const iovec *iov, int count) {
    char buf[8192];
    long out = 0, ret = 0;
    ulong used = 0;
    const auto put = [&](const void *p, ulong len) {
	if ((ret = send(s, p, len)) > 0)
	    out += ret;
	return ret > 0 && (ulong)ret == len;
    };

    for (int i = 0; i < count; ++i) {
	const char *p = (const char *)iov[i].iov_base;
	const auto len = (ulong)iov[i].iov_len;

	if (used && used + len > sizeof (buf)) {
	    if (!put(buf, used))
		return out ? out : ret;
	    used = 0;
	}
	if (len >= sizeof (buf)) {
	    if (!put(p, len))
		return out ? out : ret;
	} else if (len) {
	    memcpy(buf + used, p, len);
	    used += len;
	}
    }
    if (used && !put(buf, used))
	return out ? out : ret;
    return out;
}

static SSL_CTX *newctx(const Config &cfg, const tchar *sect, bool server,
    bool verify, tstring &err, tstring &keysrc) {
    ctx_ptr ctx(SSL_CTX_new(server ? TLS_server_method() :
	TLS_client_method()));
    string cafile = confstr(cfg, T("tls.cacertfile"), sect);
    string capath = confstr(cfg, T("tls.cacertpath"), sect);
    string certfile = confstr(cfg, T("tls.certfile"), sect);
    string ciphers = confstr(cfg, T("tls.cipherlist"), sect);
    string crlpath = confstr(cfg, T("tls.crlpath"), sect);
    string groups = confstr(cfg, T("tls.groups"), sect);
    string keyfile = confstr(cfg, T("tls.keyfile"), sect);
    tstring minver = cfg.get(T("tls.proto_min"), T("TLSv1_2"), sect);
    string suites = confstr(cfg, T("tls.ciphersuites"), sect);
    int ver = 0;
    const auto fail = [&](const tchar *msg) {
	tstring e = sslerrors();

	err = msg;
	if (!e.empty()) {
	    err += T(": ");
	    err += e;
	}
	return nullptr;
    };

    if (!ctx)
	return fail(T("cannot create TLS context"));
    if (minver == T("TLSv1_3"))
	ver = TLS1_3_VERSION;
    else if (minver == T("TLSv1_2"))
	ver = TLS1_2_VERSION;
    else if (minver == T("TLSv1_1"))
	ver = TLS1_1_VERSION;
    else if (minver == T("TLSv1_0"))
	ver = TLS1_VERSION;
    else if (!minver.empty())
	return fail(T("unknown tls.proto_min"));
    SSL_CTX_set_min_proto_version(ctx.get(), ver);
    SSL_CTX_set_options(ctx.get(), SSL_OP_ALL | SSL_OP_IGNORE_UNEXPECTED_EOF |
	SSL_OP_NO_RENEGOTIATION | cfg.get(T("tls.options"), (uint64_t)0,
	sect));
    SSL_CTX_set_mode(ctx.get(), SSL_MODE_ENABLE_PARTIAL_WRITE |
	SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER | SSL_MODE_RELEASE_BUFFERS);
    // fewer recvs: polls check SSL_has_pending for buffered records
    SSL_CTX_set_read_ahead(ctx.get(), 1);
    SSL_CTX_set_default_read_buffer_len(ctx.get(), 64 * 1024);
    if (!ciphers.empty() && !SSL_CTX_set_cipher_list(ctx.get(),
	ciphers.c_str()))
	return fail(T("invalid tls.cipherlist"));
    if (!suites.empty() && !SSL_CTX_set_ciphersuites(ctx.get(),
	suites.c_str()))
	return fail(T("invalid tls.ciphersuites"));
    if (!groups.empty() && !SSL_CTX_set1_groups_list(ctx.get(),
	groups.c_str()))
	return fail(T("invalid tls.groups"));
    if (!crlpath.empty()) {
	X509_STORE *store = SSL_CTX_get_cert_store(ctx.get());
	X509_LOOKUP *lookup = X509_STORE_add_lookup(store,
	    X509_LOOKUP_hash_dir());

	if (!lookup || !X509_LOOKUP_add_dir(lookup, crlpath.c_str(),
	    X509_FILETYPE_PEM))
	    return fail(T("cannot load tls.crlpath"));
	X509_STORE_set_flags(store, X509_V_FLAG_CRL_CHECK |
	    X509_V_FLAG_CRL_CHECK_ALL);
    }
    if (!cafile.empty() || !capath.empty()) {
	if (!SSL_CTX_load_verify_locations(ctx.get(), cafile.empty() ?
	    nullptr : cafile.c_str(), capath.empty() ? nullptr :
	    capath.c_str()))
	    return fail(T("cannot load CA certificates"));
	if (server && !cafile.empty()) {
	    STACK_OF(X509_NAME) *calist = SSL_load_client_CA_file(
		cafile.c_str());

	    if (!calist)
		return fail(T("cannot load tls.cacertfile"));
	    SSL_CTX_set_client_CA_list(ctx.get(), calist);
	}
    } else if (verify && !SSL_CTX_set_default_verify_paths(ctx.get())) {
	return fail(T("cannot load default CA certificates"));
    }
    if (verify) {
	SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
    } else {
	// peer certs are reported by info(), never rejected
	SSL_CTX_set_verify(ctx.get(), server && cfg.get(T("tls.request_cert"),
	    false, sect) ? SSL_VERIFY_PEER : SSL_VERIFY_NONE,
	    [](int, X509_STORE_CTX *) { return 1; });
    }
    if (server) {
	// clients cache only their newest ticket
	SSL_CTX_set_num_tickets(ctx.get(), 1);
	SSL_CTX_set_session_id_context(ctx.get(), (const uchar *)"blister",
	    7);
    } else {
	SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_CLIENT |
	    SSL_SESS_CACHE_NO_INTERNAL_STORE);
	if (certfile.empty())
	    return ctx.release();
    }
    if (!certfile.empty()) {
	if (SSL_CTX_use_certificate_chain_file(ctx.get(),
	    certfile.c_str()) != 1)
	    return fail(T("cannot load tls.certfile"));
	if (SSL_CTX_use_PrivateKey_file(ctx.get(), (keyfile.empty() ?
	    certfile : keyfile).c_str(), SSL_FILETYPE_PEM) != 1)
	    return fail(T("cannot load tls.keyfile"));
	keysrc = achartotstring(certfile.c_str());
    } else {
	key_ptr key(keyfile.empty() ? defaultkey(keysrc) :
	    readkey(keyfile.c_str()));
	x509_ptr cert;

	if (!key)
	    return fail(T("cannot load tls.keyfile"));
	if (!keyfile.empty())
	    keysrc = achartotstring(keyfile.c_str());
	cert.reset(selfsign(key.get()));
	if (!cert)
	    return fail(T("cannot create self-signed certificate"));
	if (SSL_CTX_use_certificate(ctx.get(), cert.get()) != 1 ||
	    SSL_CTX_use_PrivateKey(ctx.get(), key.get()) != 1)
	    return fail(T("cannot use self-signed certificate"));
    }
    if (SSL_CTX_check_private_key(ctx.get()) != 1)
	return fail(T("TLS certificate and key mismatch"));
    return ctx.release();
}

TLSContext::~TLSContext() {
    clear();
    SSL_CTX_free(ctx.load(memory_order_relaxed));
}

void TLSContext::clear(void) {
    for (const auto &[_, sess] : sessions)
	SSL_SESSION_free(sess);
    sessions.clear();
}

bool TLSContext::init(const Config &cfg, const tchar *sect, tstring &err) {
    tstring keysrc;
    SSL_CTX *c = nullptr, *old;

    err.clear();
    // static TLSContexts are freed after exit handlers run
    OPENSSL_init_ssl(OPENSSL_INIT_NO_ATEXIT, nullptr);
    verify = !srv && cfg.get(T("tls.verify"), true, sect);
    if (!srv || cfg.get(T("tls.enable"), false, sect)) {
	if ((c = newctx(cfg, sect, srv, verify, err, keysrc)) == nullptr)
	    return false;
	if (srv) {
	    dlogi(Log::mod(sect ? sect : T("tls")), Log::cmd(T("tls")),
		Log::kv(T("key"), keysrc));
	} else {
	    SSL_CTX_set_app_data(c, this);
	    SSL_CTX_sess_set_new_cb(c, onsession);
	}
    }
    // live SSLs hold their own context reference
    lock.lock();
    old = ctx.exchange(c, memory_order_relaxed);
    clear();
    lock.unlock();
    SSL_CTX_free(old);
    return true;
}

TLSContext::Info TLSContext::info(const Socket &s) {
    char buf[256];
    Info i;

    if (!s.layer())
	return i;

    const SSL *ssl = static_cast<const TLSLayer *>(s.layer())->ssl;
    const SSL_CIPHER *c = SSL_get_current_cipher(ssl);
    const char *g = SSL_group_to_name((SSL *)ssl, (int)
	SSL_get_negotiated_group((SSL *)ssl));
    X509 *cert = SSL_get1_peer_certificate(ssl);
    long vr = SSL_get_verify_result(ssl);

    i.version = achartotstring(SSL_get_version(ssl));
    if (c) {
	i.bits = SSL_CIPHER_get_bits(c, nullptr);
	i.cipher = achartotstring(SSL_CIPHER_get_name(c));
    }
    if (g)
	i.group = achartotstring(g);
    if (vr != X509_V_OK) {
	i.verify = T("FAIL");
	i.verifyerr = achartotstring(X509_verify_cert_error_string(vr));
    } else if (cert) {
	i.verify = T("OK");
    } else {
	i.verify = SSL_get_verify_mode(ssl) & SSL_VERIFY_PEER ? T("NO") :
	    T("NOT");
    }
    if (cert) {
	X509_NAME *subj = X509_get_subject_name(cert);

	i.subject = achartotstring(X509_NAME_oneline(subj, buf, sizeof (buf)));
	i.issuer = achartotstring(X509_NAME_oneline(X509_get_issuer_name(
	    cert), buf, sizeof (buf)));
	if (X509_NAME_get_text_by_NID(subj, NID_commonName, buf,
	    sizeof (buf)) >= 0)
	    i.cn = achartotstring(buf);
	X509_free(cert);
    }
    return i;
}

bool TLSContext::layer(Socket &s, const tchar *host) const {
    string key;
    TLSLayer *l;
    Sockaddr sa;
    SSL *ssl = nullptr;

    if (!host)
	host = T("");
    if (!srv && s.peername(sa)) {
	key = tchartoachar(host);
	key += '/';
	key += tstringtoachar(sa.str());
    }
    lock.lock_shared();
    if (SSL_CTX *c = ctx.load(memory_order_relaxed); c && (ssl = SSL_new(c)) &&
	!key.empty()) {
	if (auto it = sessions.find(key); it != sessions.end())
	    SSL_set_session(ssl, it->second);
    }
    lock.unlock_shared();
    if (!ssl) {
	ERR_clear_error();
	s.err(EPROTO);
	return false;
    }
    SSL_set_fd(ssl, (int)s.fd());
    if (srv) {
	SSL_set_accept_state(ssl);
    } else {
	SSL_set_connect_state(ssl);
	if (*host) {
	    string h(tchartoachar(host));

	    SSL_set_tlsext_host_name(ssl, h.c_str());
	    if (verify)
		SSL_set1_host(ssl, h.c_str());
	} else if (verify && !key.empty()) {
	    // no name: the cert must list the peer IP
	    X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(ssl),
		tstringtoachar(sa.ip()));
	}
    }
    l = new TLSLayer(ssl);
    l->key = std::move(key);
    SSL_set_app_data(ssl, l);
    s.layer(l);
    return true;
}

// keep the newest resumable session per host and peer
int TLSContext::onsession(SSL *ssl, SSL_SESSION *sess) {
    auto *tc = static_cast<TLSContext *>(SSL_CTX_get_app_data(
	SSL_get_SSL_CTX(ssl)));
    const auto *l = static_cast<const TLSLayer *>(SSL_get_app_data(ssl));

    if (l->key.empty() || !SSL_SESSION_is_resumable(sess))
	return 0;
    tc->lock.lock();
    // sessions from a context replaced by init() skip its verify rules
    if (SSL_get_SSL_CTX(ssl) != tc->ctx.load(memory_order_relaxed)) {
	tc->lock.unlock();
	return 0;
    }
    if (tc->sessions.size() >= 1024)
	tc->clear();
    if (auto [it, added] = tc->sessions.try_emplace(l->key, sess); !added) {
	SSL_SESSION_free(it->second);
	it->second = sess;
    }
    tc->lock.unlock();
    return 1;
}

#endif

TLSContext &TLSContext::client(void) {
    // never freed so it outlives static objects using it
    static TLSContext *tc = [] {
	auto *c = new TLSContext(false);
	Config cfg;
	tstring err;

	(void)c->init(cfg, nullptr, err);
	return c;
    }();

    return *tc;
}

tstring TLSContext::sni(const Sockaddr &sa) {
    tstring s(sa.str());

    if (s == sa.ipstr())
	return {};
    if (size_t pos = s.rfind(':'); sa.port() && pos != s.npos)
	s.resize(pos);
    return s;
}

static constexpr ulong HANDSHAKE_TIMEOUT = 30 * 1000;

TLSContext HTTPTLSServer::tlsctx;

void HTTPTLSServer::shake(void) {
    int ret;

    if (error() || (ret = handshake(shake, HANDSHAKE_TIMEOUT)) < 0) {
	dlogd(Log::mod(section()), Log::cmd(T("handshake")), Log::error(
	    msg == DispatchTimeout ? tstring(T("timeout")) : errstr()));
	disconnect();
    } else if (ret > 0) {
	HTTPServerSocket::start();
    }
}

void HTTPTLSServer::starttls(void) {
    if (tlsctx.layer(*this))
	shake();
    else
	disconnect();
}

bool HTTPTLSClient::starttls(void) {
    if (!tctx.layer(sock, TLSContext::sni(addr).c_str()) ||
	sock.handshake() <= 0) {
	sockerr = sock.err() ? sock.err() : EPROTO;
	return false;
    }
    // drop plaintext read ahead of the handshake
    setup();
    return true;
}

template<class B>
bool SMTPTLSClientT<B>::greet(bool lmtp, const tchar *domain) {
    if (!(lmtp ? B::lhlo(domain) : B::ehlo(domain)))
	return false;
    if (!upgrade || secure())
	return true;
    if (!this->exts_find(T("STARTTLS"))) {
	this->sts = T("000 STARTTLS not offered");
	this->sock.close();
	return false;
    }
    return starttls() && (lmtp ? B::lhlo(domain) : B::ehlo(domain));
}

template<class B>
bool SMTPTLSClientT<B>::handshake(void) {
    return tctx->layer(this->sock, TLSContext::sni(this->peer).c_str()) &&
	this->sock.handshake() > 0;
}

template<class B>
bool SMTPTLSClientT<B>::starttls(void) {
    if (!this->cmd(T("STARTTLS"), nullptr, 220))
	return false;
    // drop plaintext read ahead of the handshake
    this->sstrm.clear();
    this->sstrm.rdbuf()->str(nullptr, 4096);
    if (!handshake()) {
	this->sts = T("000 TLS handshake failed: ") + this->sock.errstr();
	this->sock.close();
	return false;
    }
    this->exts.erase();
    this->ext_8bitmime = this->ext_chunking = this->ext_smtputf8 = false;
    return true;
}

template class BLISTERTLS SMTPTLSClientT<AsyncSMTPClient>;
template class BLISTERTLS SMTPTLSClientT<SMTPClient>;
