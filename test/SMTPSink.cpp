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

// SMTP and LMTP server that accepts and discards mail for client load tests

#include "stdapi.h"
#include <format>
#include <signal.h>
#include "Config.h"
#include "Dispatch.h"
#include "Log.h"

static constexpr uint BUFSZ = 256 * 1024;
static constexpr ulong TIMEOUT = 60000;

static atomic<ulong> bytes, msgs;
static bool chunking = true, verify = false;
static atomic_bool qflag;

// the first 4 bytes of a command verb in lower case
static constexpr uint32_t verb(const char (&s)[5]) {
    return bit_cast<uint32_t>(array<char, 4>{ s[0], s[1], s[2], s[3] });
}

// next '.' at or after p that starts a line, p[-1] must be readable
static const char *dotscan(const char *p, const char *end) {
#ifdef __AVX2__
    const auto hits = [](const char *s) {
	return _mm256_and_si256(_mm256_cmpeq_epi8(_mm256_loadu_si256(
	    (const __m256i *)s), _mm256_set1_epi8('.')), _mm256_cmpeq_epi8(
	    _mm256_loadu_si256((const __m256i *)(s - 1)),
	    _mm256_set1_epi8('\n')));
    };

    for (; end - p >= 128; p += 128) {
	__m256i h = _mm256_or_si256(_mm256_or_si256(hits(p), hits(p + 32)),
	    _mm256_or_si256(hits(p + 64), hits(p + 96)));

	if (!_mm256_testz_si256(h, h))
	    break;
    }
    for (; end - p >= 32; p += 32) {
	uint m = (uint)_mm256_movemask_epi8(hits(p));

	if (m)
	    return p + countr_zero(m);
    }
#elif defined(__ARM_NEON)
    const auto hits = [](const char *s) {
	return vandq_u8(vceqq_u8(vld1q_u8((const uint8_t *)s), vdupq_n_u8('.')),
	    vceqq_u8(vld1q_u8((const uint8_t *)(s - 1)), vdupq_n_u8('\n')));
    };

    for (; end - p >= 64; p += 64) {
	if (vmaxvq_u8(vorrq_u8(vorrq_u8(hits(p), hits(p + 16)),
	    vorrq_u8(hits(p + 32), hits(p + 48)))))
	    break;
    }
    for (; end - p >= 16; p += 16) {
	// 4 bits per byte, first byte in the low bits
	uint64_t m = vget_lane_u64(vreinterpret_u64_u8(vshrn_n_u16(
	    vreinterpretq_u16_u8(hits(p)), 4)), 0);

	if (m)
	    return p + countr_zero(m) / 4;
    }
#endif
    while ((p = (const char *)memchr(p, '.', (size_t)(end - p))) != nullptr) {
	if (p[-1] == '\n')
	    return p;
	++p;
    }
    return end;
}

class SMTPSinkSocket: public DispatchServerSocket {
public:
    SMTPSinkSocket(Dispatcher &d, const Socket &sock):
	DispatchServerSocket(d, sock), buf(new char[BUFSZ]) {}

    void start(void) override {
	nodelay(true);
	out = "220 sink ESMTP\r\n";
	flush();
    }
    static const tchar *section(void) { return T("smtpsink"); }

private:
    enum class State { Cmd, Data, Bdat };

    // SASL responses still expected
    uint auth = 0, chunks = 0, rcpts = 0;
    string body, out;
    unique_ptr<char[]> buf;
    uint have = 0, pos = 0, scan = 0;
    bool last = false, lmtp = false, quit = false;
    size_t left = 0, size = 0;
    State state = State::Cmd;

    void chunk(void);
    void command(const char *p, uint len);
    void delivered(void);
    void flush(void);
    void parse(void);
    void reset(void) {
	chunks = rcpts = 0;
	size = 0;
	body.clear();
    }

    DSP_DECLARE(SMTPSinkSocket, input);
    DSP_DECLARE(SMTPSinkSocket, output);
};

void SMTPSinkSocket::command(const char *p, uint len) {
    string_view line(p, len);
    uint vlen = (uint)min(line.find(' '), line.size());
    uint32_t w = 0;

    if (auth) {
	if (line == "*") {
	    auth = 0;
	    out += "501 5.7.0 Authentication cancelled\r\n";
	} else {
	    out += --auth ? "334 UGFzc3dvcmQ6\r\n" :
		"235 2.7.0 Authentication successful\r\n";
	}
	return;
    }
    if (vlen >= 4) {
	memcpy(&w, p, 4);
	w |= 0x20202020U;
    }
    // only STARTTLS and XCLIENT are not 4 characters
    if (vlen != 4 && !(vlen == 8 && w == verb("star") && !cstrnicmp(p + 4,
	"TTLS", 4)) && !(vlen == 7 && w == verb("xcli") && !cstrnicmp(p + 4,
	"ENT", 3)))
	w = 0;
    switch (w) {
    case verb("rcpt"):
	if (line.contains("bad")) {
	    out += "550 5.1.1 No such user\r\n";
	} else {
	    out += "250 2.1.5 Ok\r\n";
	    ++rcpts;
	}
	break;
    case verb("mail"):
    case verb("rset"):
	reset();
	out += "250 2.1.0 Ok\r\n";
	break;
    case verb("bdat"): {
	// BDAT size [LAST]
	const char *n = p + 4;

	while (n < p + len && *n == ' ')
	    ++n;
	left = atoun<size_t>(n, (size_t)(p + len - n));
	last = line.size() >= 5 && !cstrnicmp(p + len - 5, " LAST", 5);
	if (left)
	    state = State::Bdat;
	else
	    chunk();
	break;
    }
    case verb("data"):
	if (rcpts) {
	    out += "354 End data with <CR><LF>.<CR><LF>\r\n";
	    state = State::Data;
	} else {
	    out += "554 5.5.1 No valid recipients\r\n";
	}
	break;
    case verb("ehlo"):
    case verb("lhlo"):
	lmtp = w == verb("lhlo");
	reset();
	out += "250-sink\r\n250-PIPELINING\r\n250-SIZE\r\n250-8BITMIME\r\n"
	    "250-ENHANCEDSTATUSCODES\r\n250-DSN\r\n250-AUTH PLAIN LOGIN\r\n"
	    "250-XCLIENT NAME ADDR PROTO HELO\r\n250-ETRN\r\n";
	if (chunking)
	    out += "250-CHUNKING\r\n250-BINARYMIME\r\n";
	out += "250 SMTPUTF8\r\n";
	break;
    case verb("helo"):
	lmtp = false;
	reset();
	out += "250 sink\r\n";
	break;
    case verb("auth"): {
	// AUTH mechanism [initial-response]
	string_view mech = line.substr(min(vlen + 1, len));
	bool initial = mech.find(' ') != mech.npos;

	mech = mech.substr(0, mech.find(' '));
	if (stringieq(mech, string_view("PLAIN"))) {
	    auth = initial ? 0 : 1;
	} else if (stringieq(mech, string_view("LOGIN"))) {
	    auth = initial ? 1 : 2;
	} else {
	    out += "504 5.5.4 Unrecognized authentication type\r\n";
	    break;
	}
	out += auth == 2 ? "334 VXNlcm5hbWU6\r\n" : auth ?
	    (initial ? "334 UGFzc3dvcmQ6\r\n" : "334 \r\n") :
	    "235 2.7.0 Authentication successful\r\n";
	break;
    }
    case verb("etrn"):
	out += "250 2.0.0 Queuing started\r\n";
	break;
    case verb("expn"):
	out += "502 5.5.1 EXPN not supported\r\n";
	break;
    case verb("help"):
	out += "214 2.0.0 sink\r\n";
	break;
    case verb("noop"):
    case verb("xcli"):
	out += "250 2.0.0 Ok\r\n";
	break;
    case verb("quit"):
	out += "221 2.0.0 Bye\r\n";
	quit = true;
	break;
    case verb("star"):
	out += "454 4.7.0 TLS not available\r\n";
	break;
    case verb("vrfy"):
	out += "252 2.1.5 Cannot VRFY user\r\n";
	break;
    default:
	out += "500 5.5.2 Command unrecognized\r\n";
	break;
    }
}

void SMTPSinkSocket::chunk(void) {
    ++chunks;
    if (last)
	delivered();
    else
	out += "250 2.0.0 Chunk ok\r\n";
}

// reply to the end of a message, once per accepted recipient for LMTP
void SMTPSinkSocket::delivered(void) {
    if (!rcpts) {
	out += "554 5.5.1 No valid recipients\r\n";
	reset();
	return;
    }

    char reply[128];
    char *end = format_to_n(reply, sizeof (reply) - 2, "250 2.0.0 Ok via={}",
	chunks ? "BDAT" : "DATA").out;

    if (chunks)
	end = format_to(end, "{}", chunks);
    if (verify) {
	if (!chunks) {
	    // remove the dot that starts each stuffed line
	    size_t o = 0;

	    for (size_t i = 0; i < body.size(); ++i) {
		if (body[i] != '.' || (i && body[i - 1] != '\n'))
		    body[o++] = body[i];
	    }
	    body.resize(o);
	}
	end = format_to_n(end, reply + sizeof (reply) - 2 - end,
	    " len={} hash={:016x}", body.size(), rapid_hash(body.data(),
	    body.size())).out;
    }
    *end++ = '\r';
    *end++ = '\n';
    for (uint u = 0; u < (lmtp ? rcpts : 1); ++u)
	out.append(reply, (size_t)(end - reply));
    msgs.fetch_add(1, memory_order_relaxed);
    bytes.fetch_add(size, memory_order_relaxed);
    reset();
}

// process all complete input
void SMTPSinkSocket::parse(void) {
    char *b = buf.get();

    while (pos < have && !quit) {
	if (state == State::Bdat) {
	    size_t n = min(left, (size_t)(have - pos));

	    if (verify)
		body.append(b + pos, n);
	    size += n;
	    pos += (uint)n;
	    if ((left -= n) != 0)
		break;
	    state = State::Cmd;
	    chunk();
	} else if (state == State::Data) {
	    // a line with only a dot ends the message
	    const char *d = b + max(scan, pos);
	    const char *end = b + have;

	    while ((d = dotscan(d, end)) + 2 < end && (d[1] != '\r' ||
		d[2] != '\n'))
		++d;
	    if (d + 2 >= end) {
		scan = (uint)(min(d, end) - b);
		break;
	    }

	    uint dot = (uint)(d - b);

	    if (verify)
		body.append(b + pos, dot - pos);
	    size += dot - pos;
	    pos = dot + 3;
	    scan = 0;
	    state = State::Cmd;
	    delivered();
	} else {
	    const char *p = b + pos;
	    const char *nl = (const char *)memchr(p, '\n', have - pos);

	    if (!nl) {
		if (pos == 0 && have == BUFSZ) {
		    out += "500 5.5.2 Line too long\r\n";
		    quit = true;
		}
		break;
	    }
	    pos = (uint)(nl - b) + 1;
	    command(p, (uint)(nl - p - (nl > p && nl[-1] == '\r')));
	    // the dot scan needs the LF before the message
	    if (state == State::Data)
		scan = pos;
	}
    }

    // keep unprocessed input and the byte before the next scan position
    uint keep = state == State::Data ? scan - 1 : pos;

    if (state == State::Data && keep > pos) {
	if (verify)
	    body.append(b + pos, keep - pos);
	size += keep - pos;
	pos = keep;
    }
    keep = min(keep, pos);
    memmove(b, b + keep, have - keep);
    have -= keep;
    pos -= keep;
    if (state == State::Data)
	scan -= keep;
}

void SMTPSinkSocket::flush(void) {
    while (!out.empty()) {
	int n = write(out.data(), (uint)out.size());

	if (n < 0) {
	    erase();
	    return;
	} else if (n == 0) {
	    writeable(output, TIMEOUT);
	    return;
	}
	out.erase(0, (size_t)n);
    }
    if (quit)
	erase();
    else
	readable(input, TIMEOUT);
}

void SMTPSinkSocket::input(void) {
    int n;

    if (error() || (n = read(buf.get() + have, BUFSZ - have)) < 0) {
	dlogd(Log::mod(section()), Log::kv(T("status"), msg ==
	    DispatchTimeout ? T("timeout") : T("close")));
	erase();
	return;
    }
    have += (uint)n;
    parse();
    flush();
}

void SMTPSinkSocket::output(void) {
    if (error()) {
	erase();
	return;
    }
    flush();
}

// only async-signal-safe work here so main notices qflag and stops
static void signal_handler(int) { qflag = true; }

int tmain(int argc, const tchar * const argv[]) {
    Config cfg;
    Dispatcher dspr(cfg);
    tchar addr[32];
    uint port = 2525, threads = 32;
    ulong stattime = 0;
    auto *lsock = new SimpleDispatchListenSocket<Dispatcher, SMTPSinkSocket>(
	dspr);

    for (int i = 1; i < argc; ++i) {
	if (!tstricmp(argv[i], T("-d"))) {
	    chunking = false;
	} else if (!tstricmp(argv[i], T("-p")) && i + 1 < argc) {
	    port = atoi<uint>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-s")) && i + 1 < argc) {
	    stattime = atoi<ulong>(argv[++i]) * 1000;
	} else if (!tstricmp(argv[i], T("-t")) && i + 1 < argc) {
	    threads = atoi<uint>(argv[++i]);
	} else if (!tstricmp(argv[i], T("-v"))) {
	    verify = true;
	} else {
	    tcerr << T("usage: smtpsink [-d] [-p port] [-s stattime] ")
		T("[-t threads] [-v]") << endl;
	    delete lsock;
	    return 1;
	}
    }
    signal(SIGINT, signal_handler);
#ifndef _WIN32
    struct sigaction sig {};

    sig.sa_handler = SIG_IGN;
    sigaction(SIGPIPE, &sig, nullptr);
#endif
    tsprintf(addr, T("*:%u"), port);
    if (!dspr.start(threads, 32 * 1024)) {
	tcerr << T("smtpsink: unable to start") << endl;
	delete lsock;
	return 1;
    }
    if (!lsock->listen(Sockaddr(addr))) {
	tcerr << T("smtpsink: unable to listen on ") << addr << endl;
	delete lsock;
	dspr.stop();
	return 1;
    }

    usec_t begin = uticks(), last = begin;
    ulong lastmsgs = 0, lastbytes = 0;

    while (!qflag && !dspr.waitForMain(stattime ? stattime : 1000)) {
	if (!stattime)
	    continue;

	usec_t now = uticks();
	ulong m = msgs.load(memory_order_relaxed);
	ulong b = bytes.load(memory_order_relaxed);
	double secs = (double)(now - last) / 1e6;

	tcout << format("{:.0f} msg/s {:.1f} MB/s", (double)(m - lastmsgs) /
	    secs, (double)(b - lastbytes) / secs / 1e6).c_str() << endl;
	last = now;
	lastmsgs = m;
	lastbytes = b;
    }
    dspr.stop();
    tcout << format("{} msgs {} bytes in {:.1f}s", msgs.load(), bytes.load(),
	(double)(uticks() - begin) / 1e6).c_str() << endl;
    return 0;
}
