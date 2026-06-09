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
#include <algorithm>
#include <ranges>
#include "Timing.h"
#include "Log.h"

// UNIX loaders may try to construct static objects > 1 time
static Timing &_dtiming(void) {
    static Timing timing;

    return timing;
}

Timing &dtiming(_dtiming());

Timing::Stats *Timing::Stats::newstats(const tchar *k, uint klen, strhash_t h) {
    Stats *s;

    if (!klen)
	klen = (uint)tstrlen(k);
    s = (Stats *)new char[offsetof(Stats, key) + ((size_t)klen + 1) *
	sizeof (tchar)];
    s->hash = h;
    s->klen = klen;
    memcpy(s->key, k, ((size_t)klen + 1) * sizeof (tchar));
    return s;
}

Timing::~Timing() {
    // 1st call moves to free list and 2nd deletes
    clear();
    clear();
}

void Timing::add(const tchar *key, uint klen, strhash_t hash, timing_t diff) {
    uint idx = hash & (CACHESIZE - 1);
    uint slot;
    Stats *stats;
    static constexpr timing_t limits[TIMINGSLOTS - 1] = {
	10, 100, 1000, 10000, 100000, 1000000, 5000000, 10000000, 30000000
    };
    
    for (slot = 0; slot < TIMINGSLOTS - 1; ++slot) {
	if (diff < limits[slot])
	    break;
    }
    stats = cache[idx].load(memory_order_relaxed);
    if (UNLIKELY(!(stats && stats->hash == hash))) {
	lck.rlock();
	auto it = tmap.find(hash);
	if (it == tmap.end()) {
	    lck.runlock();
	    stats = Stats::newstats(key, klen, hash);
	    lck.wlock();
	    auto result = tmap.try_emplace(hash, stats);
	    lck.downlock();
	    if (!result.second) {
		Stats::delstats(stats);
		stats = result.first->second;
	    }
	} else {
	    stats = it->second;
	}
	lck.runlock();
	cache[idx].store(stats, memory_order_relaxed);
    }
    stats->cnt.fetch_add(1, memory_order_relaxed);
    stats->cnts[slot].fetch_add(1, memory_order_relaxed);
    stats->tot.fetch_add(diff, memory_order_relaxed);
}

void Timing::clear() {
    timingmap old;
    Stats *s, *next;

    lck.wlock();
    for (auto &entry : cache)
	entry.store(nullptr, memory_order_relaxed);
    old.swap(tmap);
    lck.wunlock();
    for (auto &[k, stats] : old)
	Stats::delstats(stats);
    s = flist.exchange(nullptr, memory_order_relaxed);
    while (s) {
	next = s->flist;
	Stats::delstats(s);
	s = next;
    }
}

const tstring Timing::data(bool sort_key, uint columns) const {
    uint begin = 0, last = 0;
    tstring s;
    vector<const Stats *> sorted;
    static constexpr const tchar *hdrs[TIMINGSLOTS] = {
	T("10u"), T(".1m"), T("1m"), T("10m"), T(".1s"), T("1s"),
	T("5s"), T("10s"), T("30s"), T("...")
    };

    columns = min(columns, TIMINGSLOTS);
    lck.rlock();
    sorted.reserve(tmap.size());
    for (const auto &[key, stats] : tmap) {
	sorted.emplace_back(stats);
	for (uint u = TIMINGSLOTS - 1; u > last; --u) {
	    if (stats->cnts[u].load(memory_order_relaxed)) {
		last = u;
		break;
	    }
	}
    }
    lck.runlock();
    if (sort_key) {
	ranges::sort(sorted, [](const Stats *a, const Stats *b)
	    { return stringless(a->key, b->key); });
    } else {
	ranges::sort(sorted, [](const Stats *a, const Stats *b) {
	    const timing_t tot_a = a->tot.load(memory_order_relaxed);
	    const timing_t tot_b = b->tot.load(memory_order_relaxed);
	    return tot_a == tot_b ? stringless(a->key, b->key) : tot_a > tot_b;
	});
    }
    begin = (!columns || last < columns) ? 0 : last - columns + 1;
    const size_t estimated_size = tmap.size() * (columns ? 60 : 90) + 200;
    s.reserve(estimated_size);
    
    s = columns ? T("key                            msec   cnt   avg") :
	T("key,msec,cnt,avg");
    for (uint u = begin; u <= last; ++u) {
	if (columns) {
	    const tchar *header = hdrs[u];
	    size_t header_len = tstrlen(header);

	    while (header_len++ < 4)
		s += ' ';
	    s += header;
	} else {
	    s += (tchar)',';
	    s += hdrs[u];
	}
    }
    s += (tchar)'\n';
    for (const Stats *stats : sorted) {
	tchar buf[128];
	ulong sum = 0;
	const ulong scnt = stats->cnt.load(memory_order_relaxed);
	const timing_t tot = stats->tot.load(memory_order_relaxed);

	if (columns) {
	    tchar cbuf[24];
	    size_t klen = stats->klen;

	    for (uint u = 0; u <= begin; ++u)
		sum += stats->cnts[u].load(memory_order_relaxed);
	    if (scnt >= 10000000UL)
		tsprintf(cbuf, T("%4lum"), (ulong)scnt / 1000000UL);
	    else if (scnt >= 10000UL)
		tsprintf(cbuf, T("%4luk"), (ulong)scnt / 1000UL);
	    else
		tsprintf(cbuf, T("%5lu"), (ulong)scnt);
	    if (tot) {
		tchar abuf[16], sbuf[16];

		tsprintf(buf, T("%-29s%6s%6s%6s"), stats->key + (klen < sizeof
		    (buf) - 19 ? 0 : klen - sizeof (buf) + 19), format(tot,
		    sbuf), cbuf, format(tot / scnt, abuf));
	    } else {
		tsprintf(buf, T("%-35s%6s"), stats->key + (klen < sizeof (buf) -
		    7 ? 0 : klen - sizeof (buf) + 7), cbuf);
	    }
	} else {
	    bool quote = false;

	    for (const tchar *p = stats->key; *p; ++p) {
		if (*p == ',' || *p == ' ' || *p == '\t' || *p == '"') {
		    quote = true;
		    break;
		}
	    }
	    if (quote)
		s += (tchar)'"';
	    for (const tchar *p = stats->key; *p; ++p) {
		if (*p == T('"') || *p == T('\\'))
		    s += T('\\');
		s += *p;
	    }
	    if (quote)
		s += (tchar)'"';
	    tsprintf(buf, T(",%llu,%lu,%lu"), (ullong)tot, (ulong)scnt,
		scnt ? (ulong)(tot / scnt) : 0UL);
	}
	s += buf;
	for (uint u = begin; u <= last && tot; ++u) {
	    const ulong cnt = (columns && u == begin) ? sum :
		stats->cnts[u].load(memory_order_relaxed);

	    if (!columns) {
		tsprintf(buf, T(",%lu"), cnt);
		s += buf;
	    } else if (cnt == 0) {
		s += T("    ");
	    } else if (cnt < 100) {
		tsprintf(buf, T(" %3lu"), cnt);
		s += buf;
	    } else if (cnt == scnt) {
		s += T("   *");
	    } else {
		tsprintf(buf, T(" %2u%%"), (uint)(cnt * 100 / scnt));
		s += buf;
	    }
	}
	while (!s.empty() && s.back() == ' ')
	    s.pop_back();
	s += (tchar)'\n';
    }
    return s;
}

void Timing::erase(strhash_t hash) {
    Stats *stats = nullptr;

    lck.wlock();
    auto it = tmap.find(hash);
    if (it != tmap.end()) {
	stats = it->second;
	tmap.erase(it);
    }
    lck.wunlock();
    if (stats) {
	Stats *expected = stats, *s;
	uint idx = hash & (CACHESIZE - 1);

	cache[idx].compare_exchange_strong(expected, nullptr,
	    memory_order_relaxed);
	s = flist.load(memory_order_relaxed);
	do {
	    stats->flist = s;
	} while (!flist.compare_exchange_weak(s, stats, memory_order_release,
	    memory_order_relaxed));
    }
}

const tchar *Timing::format(timing_t t, tchar *buf) {
    if (t < 10000LLU)
	    tsprintf(buf, T("%.3f"), (double)t / 1000.0);
    else if (t < 100000LLU)
	    tsprintf(buf, T("%.2f"), (double)t / 1000.0);
    else if (t < 1000000LLU)
	    tsprintf(buf, T("%llu"), t / 1000LLU);
    else if (t < 100000000LLU)
	    tsprintf(buf, T("%.1fk"), (double)t / 1000000.0);
    else if (t < 1000000000LLU)
	    tsprintf(buf, T("%lluk"), t / 1000000LLU);
    else if (t < 100000000000LLU)
	    tsprintf(buf, T("%.1fm"), (double)t / 1000000000.0);
    else if (t < 1000000000000LLU)
	tsprintf(buf, T("%llum"), t / 1000000000LLU);
    else
	tsprintf(buf, T("%llug"), t / 1000000000000LLU);
    return buf;
}

void Timing::record(void) {
    Tlsdata &tlsd(*tls);

    if (tlsd.entries.empty()) {
	dloge(Log::mod(T("Timing")), T("stack mismatch"));
	return;
    }
    
    const size_t entries = tlsd.entries.size() - 1;
    const auto &entry = tlsd.entries.back();
    const timing_t diff = now() - entry.start;
    size_t len;
    
    if (!entries) {
	add(entry.caller, 0, entry.hash, diff);
	tlsd.entries.pop_back();
	return;
    }
    len = tstrlen(entry.caller) + entries * 2;
    for (size_t i = 0; i < entries; ++i)
	len += tstrlen(tlsd.entries[i].caller);
    tstring s;
    s.reserve(len);
    for (size_t i = 0; i < entries; ++i) {
	s += tlsd.entries[i].caller;
	s += T("->");
    }
    s += entry.caller;
    add(s, diff);
    add(entry.caller, 0, entry.hash, diff);
    tlsd.entries.pop_back();
}

void Timing::restart() {
    Tlsdata &tlsd(*tls);

    if (!tlsd.entries.empty())
	tlsd.entries.back().start = now();
}

void Timing::start(const tchar *key, strhash_t hash) {
    Tlsdata &tlsd(*tls);

    tlsd.entries.emplace_back(key, hash, now());
}

void Timing::stop() {
    Tlsdata &tlsd(*tls);

    if (tlsd.entries.empty())
	dloge(Log::mod(T("Timing")), T("stack mismatch"));
    else
	tlsd.entries.pop_back();
}
