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

Timing::Stats *Timing::Stats::newstats(const tchar *k, uint klen, strhash_t
    h) {
    Stats *s;

    if (!klen)
	klen = (uint)tstrlen(k);
    s = (Stats *)operator new(offsetof(Stats, key) + ((size_t)klen + 1) *
	sizeof (tchar), align_val_t(alignof (Stats)));
    new (s) Stats(h, klen);
    memcpy(s->key, k, (size_t)klen * sizeof (tchar));
    s->key[klen] = 0;
    return s;
}

Timing::~Timing() {
    clear();
    release(flist.exchange(nullptr, memory_order_acquire));
    release(prior);
}

void Timing::release(Stats *s) {
    while (s) {
	Stats *next = s->flist;

	Stats::delstats(s);
	s = next;
    }
}

void Timing::add(const tchar *key, uint klen, strhash_t hash, timing_t diff) {
    uint idx = hash & (CACHESIZE - 1);
    Stats *stats;
    static constexpr timing_t limits[TIMINGSLOTS - 1] = {
	10, 100, 1000, 10000, 100000, 1000000, 5000000, 10000000, 30000000
    };
    const auto slot = ranges::find_if(limits, [=](timing_t l) {
	return diff < l;
    }) - limits;

    stats = cache[idx].load(memory_order_acquire);
    // the adjacent slot absorbs a cache collision between 2 hot keys
    if (UNLIKELY(!(stats && stats->hash == hash)))
	stats = cache[idx ^ 1].load(memory_order_acquire);
    if (UNLIKELY(!(stats && stats->hash == hash))) {
	lck.lock_shared();
	auto it = tmap.find(hash);
	if (it == tmap.end()) {
	    lck.unlock_shared();
	    stats = Stats::newstats(key, klen, hash);
	    lck.lock();
	    auto result = tmap.try_emplace(hash, stats);
	    lck.downlock();
	    if (!result.second) {
		Stats::delstats(stats);
		stats = result.first->second;
	    }
	} else {
	    stats = it->second;
	}

	// store under lock so clear() and erase() cannot be undone
	const Stats *cur = cache[idx].load(memory_order_relaxed);

	if (cur && cur->hash != hash)
	    idx ^= 1;
	cache[idx].store(stats, memory_order_release);
	lck.unlock_shared();
    }
    stats->cnts[slot].fetch_add(1, memory_order_relaxed);
    stats->tot.fetch_add(diff, memory_order_relaxed);
}

// threads may still hold Stats pointers so defer freeing until the next clear
void Timing::clear() {
    timingmap old;

    lck.lock();
    for (auto &entry : cache)
	entry.store(nullptr, memory_order_relaxed);
    old.swap(tmap);
    Stats *dead = prior;

    prior = flist.exchange(nullptr, memory_order_acquire);
    lck.unlock();
    release(dead);
    for (auto &[k, stats] : old)
	defer(stats);
}

tstring Timing::data(bool sort_key, uint columns) const {
    // snapshot so sorting and each row see stable values
    struct Row {
	const Stats *stats;
	uint64_t tot = 0, cnt = 0;
	uint64_t cnts[TIMINGSLOTS];
    };
    uint begin = 0, last = 0;
    tstring s;
    vector<Row> rows;
    static constexpr const tchar *hdrs[TIMINGSLOTS] = {
	T("10u"), T(".1m"), T("1m"), T("10m"), T(".1s"), T("1s"),
	T("5s"), T("10s"), T("30s"), T("...")
    };

    columns = min(columns, TIMINGSLOTS);
    lck.lock_shared();
    rows.reserve(tmap.size());
    for (const auto &[key, stats] : tmap) {
	Row &row = rows.emplace_back();

	row.stats = stats;
	row.tot = stats->tot.load(memory_order_relaxed);
	for (uint u = 0; u < TIMINGSLOTS; ++u) {
	    row.cnts[u] = stats->cnts[u].load(memory_order_relaxed);
	    row.cnt += row.cnts[u];
	    if (row.cnts[u] && u > last)
		last = u;
	}
    }
    lck.unlock_shared();
    if (sort_key) {
	ranges::sort(rows, [](const Row &a, const Row &b) {
	    return stringless(a.stats->key, b.stats->key);
	});
    } else {
	ranges::sort(rows, [](const Row &a, const Row &b) {
	    return a.tot == b.tot ? stringless(a.stats->key, b.stats->key) :
		a.tot > b.tot;
	});
    }
    begin = (!columns || last < columns) ? 0 : last - columns + 1;
    const size_t estimated_size = rows.size() * (columns ? 60 : 90) + 200;
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
    for (const Row &row : rows) {
	tchar buf[128];
	const Stats *stats = row.stats;
	const uint64_t scnt = row.cnt, tot = row.tot;
	uint64_t sum = 0;

	if (columns) {
	    tchar cbuf[24];
	    size_t klen = stats->klen;

	    for (uint u = 0; u <= begin; ++u)
		sum += row.cnts[u];
	    if (scnt >= 10000000ULL)
		tsprintf(cbuf, T("%4llum"), (ullong)(scnt / 1000000));
	    else if (scnt >= 10000ULL)
		tsprintf(cbuf, T("%4lluk"), (ullong)(scnt / 1000));
	    else
		tsprintf(cbuf, T("%5llu"), (ullong)scnt);
	    if (tot) {
		tchar abuf[16], sbuf[16];
		constexpr size_t bufsz = sizeof (buf) / sizeof (buf[0]);

		tsprintf(buf, T("%-29s%6s%6s%6s"), stats->key + (klen < bufsz
		    - 19 ? 0 : klen - bufsz + 19), format(tot,
		    sbuf), cbuf, format(scnt ? tot / scnt : 0, abuf));
	    } else {
		constexpr size_t bufsz = sizeof (buf) / sizeof (buf[0]);

		tsprintf(buf, T("%-35s%6s"), stats->key + (klen < bufsz -
		    7 ? 0 : klen - bufsz + 7), cbuf);
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
	    tsprintf(buf, T(",%llu,%llu,%llu"), (ullong)tot, (ullong)scnt,
		(ullong)(scnt ? tot / scnt : 0));
	}
	s += buf;
	for (uint u = begin; u <= last && tot; ++u) {
	    const uint64_t cnt = (columns && u == begin) ? sum : row.cnts[u];

	    if (!columns) {
		tsprintf(buf, T(",%llu"), (ullong)cnt);
		s += buf;
	    } else if (cnt == 0) {
		s += T("    ");
	    } else if (cnt < 100) {
		tsprintf(buf, T(" %3llu"), (ullong)cnt);
		s += buf;
	    } else if (cnt >= scnt) {
		s += T("   *");
	    } else {
		tsprintf(buf, T(" %2u%%"), (uint)(cnt * 100 / scnt));
		s += buf;
	    }
	}
	auto trim = s.find_last_not_of(' ');
	if (trim != s.npos)
	    s.erase(trim + 1);
	s += (tchar)'\n';
    }
    return s;
}

void Timing::erase(strhash_t hash) {
    Stats *stats = nullptr;

    lck.lock();
    auto it = tmap.find(hash);
    if (it != tmap.end()) {
	uint idx = hash & (CACHESIZE - 1);

	stats = it->second;
	tmap.erase(it);
	for (uint u : { idx, idx ^ 1 }) {
	    Stats *expected = stats;

	    cache[u].compare_exchange_strong(expected, nullptr,
		memory_order_relaxed);
	}
    }
    lck.unlock();
    if (stats)
	defer(stats);
}

void Timing::defer(Stats *stats) {
    Stats *s = flist.load(memory_order_relaxed);

    do {
	stats->flist = s;
    } while (!flist.compare_exchange_weak(s, stats, memory_order_release,
	memory_order_relaxed));
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

    const auto &entry = tlsd.entries.back();
    const timing_t diff = now() - entry.start;

    if (entry.pathlen)
	add(tlsd.path, diff);
    add(entry.caller, 0, entry.hash, diff);
    tlsd.path.resize(entry.pathlen);
    tlsd.entries.pop_back();
}

void Timing::restart() {
    Tlsdata &tlsd(*tls);

    if (!tlsd.entries.empty())
	tlsd.entries.back().start = now();
}

void Timing::start(const tchar *key, strhash_t hash) {
    Tlsdata &tlsd(*tls);
    size_t len = tlsd.path.size();

    if (len)
	tlsd.path += T("->");
    tlsd.path += key;
    tlsd.entries.emplace_back(key, hash, now(), len);
}

void Timing::stop() {
    Tlsdata &tlsd(*tls);

    if (tlsd.entries.empty()) {
	dloge(Log::mod(T("Timing")), T("stack mismatch"));
    } else {
	tlsd.path.resize(tlsd.entries.back().pathlen);
	tlsd.entries.pop_back();
    }
}
