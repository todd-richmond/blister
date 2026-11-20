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

#ifndef HTTPServer_h
#define HTTPServer_h

#include <map>
#include <memory>
#include <span>
#include <unordered_map>
#include <vector>
#include <version>
#ifdef __cpp_lib_flat_map
#include <flat_map>
#endif
#include "Dispatch.h"
#include "Service.h"

class PrometheusWriter;
class Timing;

class BLISTER HTTPServerSocket: public DispatchServerSocket {
public:
    // literal attribute names are hashed at compile time
    using attrkey = basic_strkey<char, true>;
    using attrmap = unordered_map<const char *, const char *, strihash,
	strieq>;
#ifdef __cpp_lib_flat_map
    // a handful of headers: sorted vectors beat hashing, inserts are O(n)
    using hdrmap = flat_map<const char *, const char *, striless>;
#else
    using hdrmap = attrmap;
#endif

    HTTPServerSocket(Dispatcher &d, const Socket &sock);
    virtual ~HTTPServerSocket();

    const attrmap &arguments(void) const { return args; }
    const hdrmap &attributes(void) const { return attrs; }
    const attrmap &postarguments(void) const { return postargs; }
    void urldecode(char *buf, attrmap &amap) const;
    virtual const char *mimetype(const char *ext) const;
    void start(void) override { readable(readhdrs, rto); }
    static void pause(bool b) { paused = b; }
    static void senddate(bool b) { date = b; }
    static const tchar *section(void) { return T("http"); }

protected:
    string argdata;
    iovec iov[3] = {};
    bufferstream<char> hdrs, ss;
    const char *path = nullptr, *prot = nullptr;
    char *postdata = nullptr;
    ulong postsz = 0;

    const char *arg(const attrkey &name) const { return find(args, name); }
    const char *attr(const attrkey &name) const { return find(attrs, name); }
    const char *postarg(const attrkey &name) const {
	return find(postargs, name);
    }
    template<class C> ostream &operator <<(const C &c) { return ss << c; }
    void header(const char *attr, const char *val);
    using DispatchObj::error;
    void error(uint sts, bool close = false);
    void error(uint sts, const char *errstr, bool close = false);
    void keepalive(void);
    void reply(const char *data = nullptr, ulong len = (ulong)-1);
    void reply(int fd, ulong sz);
    void reply(uint sts) { status(sts, nullptr); reply(); }
    void sendmetrics(bool close = false);
    void status(uint sts, const char *mime = "text/plain", time_t mtime = 0,
	const char *str = nullptr, bool close = false);
    virtual void del(void) { error(501); }
    virtual void disconnect(DispatchObjCB cb = done) { ready(cb); }
    virtual void exec(void);
    virtual void get(bool head = false);
    // overrides call the base first
    virtual void metrics(PrometheusWriter &w) const;
    virtual void post(void) { error(501); }
    // call at beginning of PUT or POST unless all body data read
    virtual void postpre(DispatchObjCB cb) { ready(cb); }
    // subclass owned postdata must be nulled in its dtor to avoid this delete
    virtual void postdata_free(void) { delete [] postdata; }
    virtual void postdata_grow(DispatchObjCB cb, ulong keepsize, ulong newsize);
    virtual void put(void) { error(501); }
    // reply() is done with its data; cb defers if pipelined or body still used
    virtual void replydone(DispatchObjCB cb) {
	if (datasz || postdatasz)
	    ready(cb);
	else
	    cb(this);
    }
    DSP_DECLARE(HTTPServerSocket, done);
    DSP_DECLARE(HTTPServerSocket, send);

private:
    attrmap args, postargs;
    hdrmap attrs;
    ulong chunkin = 0;
    bool chunktrailer = false, postchunking = false;
    const char *cmd = nullptr;
    char *data = nullptr;
    ulong datasz = 0, sz = 0;
    char *fmap = nullptr;
    ulong fmapsz = 0;
    bool ka = false, nagleon = true, staticfile = false;
    ulong postdatasz = 0, postin = 0;
    uint rto = 30 * 1000, wto = 150 * 1000;
    char savechar = 0;
    uint _status = 0;
    usec_t begin = 0;
    static bool date;
    static string docroot;	// http.docroot, default ${installdir}/htdocs
    static atomic_bool paused;

    template<class M>
    const char *find(const M &amap, const attrkey &name) const {
	auto it = amap.find(name);

	return it == amap.end() ? nullptr : it->second;
    }
    static void configure(const Config &cfg);
    static const char *httpdate(time_t t, char (&buf)[30]);
    static bool readfull(int fd, char *buf, size_t len);
    static string_view resource(string_view p);
    void scan(char *buf, ulong len, bool append = false);
    static const char *statusmsg(uint sts);
    static void unescape(char *s);
    void unmap(void);
    DSP_DECLARE(HTTPServerSocket, parse);
    DSP_DECLARE(HTTPServerSocket, readhdrs);
    DSP_DECLARE(HTTPServerSocket, readpost);
    DSP_DECLARE(HTTPServerSocket, senddone);
};

// literals are hashed and classified at compile time
struct PrometheusStr: string_view {
    enum: uchar { Known = 1, Name = 2, Clean = 4 };

    template<size_t N>
    // cppcheck-suppress noExplicitConstructor
    consteval PrometheusStr(const char (&s)[N]): string_view(strview(s)),
	hash(charhash(data(), size())), flags(classify(*this)) {}
    template<typename K> requires (!const_array<K> &&
	is_convertible_v<K, string_view>)
    // cppcheck-suppress noExplicitConstructor
    // NOLINTNEXTLINE(runtime/explicit)
    constexpr PrometheusStr(K &&s): string_view(std::forward<K>(s)) {}

    // Name: legacy label name; Clean: value needs no escaping
    static constexpr uchar classify(string_view s) {
	return (uchar)(Known | (legacy(s, false) ? Name : 0) |
	    (s.find_first_of("\"\\\n") == npos ? Clean : 0));
    }
    strhash_t key(void) const {
	return flags ? hash : charhash(data(), size());
    }
    static constexpr bool legacy(char c, bool metric) {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
	    (c >= '0' && c <= '9') || c == '_' || (metric && c == ':');
    }
    static constexpr bool legacy(string_view n, bool metric) {
	return !n.empty() && !(n[0] >= '0' && n[0] <= '9') &&
	    ranges::all_of(n, [=](char c) { return legacy(c, metric); });
    }

    strhash_t hash = 0;
    uchar flags = 0;
};

struct PrometheusLabel {
    PrometheusStr name, value;
};

// {{"code", "2xx"}, {"path", p}}
struct PrometheusLabels: span<const PrometheusLabel> {
    constexpr PrometheusLabels() = default;
    // cppcheck-suppress noExplicitConstructor
    // NOLINTNEXTLINE(runtime/explicit)
    constexpr PrometheusLabels(initializer_list<PrometheusLabel> l):
	span(l.begin(), l.size()) {}
    constexpr PrometheusLabels(const PrometheusLabel *l, size_t n):
	span(l, n) {}
};

// unit is appended to the name if missing
struct PrometheusFamily {
    PrometheusStr name;
    string_view help = {}, unit = {};
};

/*
 * OpenMetrics 1.0 or Prometheus text 0.0.4 per Accept. Consecutive calls for
 * one family share its header; histogram counts are per bucket, +Inf last.
 * UTF-8 names are quoted for Accept escaping=allow-utf-8, else underscored
 */
class BLISTER PrometheusWriter: nocopy {
public:
    enum Type: uchar {
	Counter, Gauge, GaugeHistogram, Histogram, Info, StateSet, Summary
    };

    explicit PrometheusWriter(const char *accept);

    const char *contenttype(void) const;
    void counter(const PrometheusFamily &f, ullong val, PrometheusLabels
	labels = {});
    // keep only families with this family or sample name
    void filter(string_view n) { names.emplace_back(n); }
    const string &finish(void);
    void gauge(const PrometheusFamily &f, double val, PrometheusLabels labels =
	{});
    void gaugehistogram(const PrometheusFamily &f, span<const double> bounds,
	span<const ulong> counts, double sum, PrometheusLabels labels = {}) {
	family(f, GaugeHistogram);
	distribution(GaugeHistogram, bounds, counts, sum, labels);
    }
    void histogram(const PrometheusFamily &f, span<const double> bounds,
	span<const ulong> counts, double sum, PrometheusLabels labels = {}) {
	family(f, Histogram);
	distribution(Histogram, bounds, counts, sum, labels);
    }
    void info(const PrometheusFamily &f, PrometheusLabels labels);
    // default labels from prometheus.labels and prometheus.label.<name>
    void labels(const Config &cfg);
    void stateset(const PrometheusFamily &f,
	initializer_list<pair<string_view, bool>> states);
    void summary(const PrometheusFamily &f, ullong count, double sum,
	PrometheusLabels labels = {});
    // keys with the most total time; untimed keys are counters
    void timing(const Timing &t, size_t top);
    // set before serving; p must outlive the writers
    static void prefix(string_view p) { pfx = p; }

private:
    enum Escape: uchar { None, Underscores, Utf8 };

    Type cur = Counter;
    Escape esc = None;
    string name;
    vector<string> names;
    bool om = false, quote = false, skip = false;
    string s, tags;
    static string_view pfx;

    void distribution(Type type, span<const double> bounds, span<const ulong>
	counts, double sum, PrometheusLabels labels);
    static void escape(string &s, string_view val);
    void family(const PrometheusFamily &f, Type type);
    void labelname(string &str, string_view n) const;
    // 6 decimals hide binary float noise
    static void number(string &s, double val);
    void putlabel(const PrometheusLabel &l);
    template<class V> void sample(string_view suffix, PrometheusLabels labels,
	V val, PrometheusLabels extra = {});
    static string underscore(string_view n, bool metric);

    friend class PrometheusMetrics;
};

/*
 * Named series of one type, each split by optional labels. Series are found
 * by a hash of the name and labels, precomputed for literals
 */
class BLISTER PrometheusMetrics: nocopy {
public:
    // default histogram bounds
    explicit PrometheusMetrics(PrometheusWriter::Type t, span<const double>
	b = {}): defbounds(b), type(t) {}

    void add(const PrometheusStr &name, integral auto val, PrometheusLabels
	labels = {}) {
	update(name, (llong)val, labels, Add);
    }
    // bounds only apply before the first update
    void describe(const PrometheusFamily &f, span<const double> bounds = {});
    void record(const PrometheusStr &name, msec_t start, PrometheusLabels
	labels = {}) {
	update(name, (llong)(mticks() - start), labels, Add);
    }
    // gauge histograms only
    void remove(const PrometheusStr &name, integral auto val,
	PrometheusLabels labels = {}) {
	update(name, (llong)val, labels, Remove);
    }
    void report(PrometheusWriter &w) const;
    // gauges only
    void set(const PrometheusStr &name, integral auto val, PrometheusLabels
	labels = {}) {
	update(name, (llong)val, labels, Set);
    }
    // size="0-32Kb" style payload buckets
    static const PrometheusLabel &sizelabel(ullong size);

private:
    enum Op: uchar { Add, Remove, Set };

    static constexpr uint CACHESIZE = 256;

    struct Family;
    struct Series {
	unique_ptr<atomic<ulong>[]> cnts;
	const Family *fam = nullptr;
	strhash_t hash = 0;
	vector<PrometheusLabel> labels;		// views of text
	atomic<ullong> sum = 0;		// llong bits so gauges may go down
	string text;
    };
    struct Family {
	vector<double> bounds;
	string help, name, unit;
	vector<const Series *> series;
    };

    // series are never freed so lookups skip the lock
    atomic<Series *> cache[CACHESIZE]{};
    span<const double> defbounds;
    unordered_map<strhash_t, Family> fams;
    mutable SpinRWLock lck;
    unordered_map<strhash_t, Series> smap;
    PrometheusWriter::Type type;

    Family &family(const PrometheusStr &name);
    Series *series(const PrometheusStr &name, PrometheusLabels labels,
	strhash_t hash);
    void update(const PrometheusStr &name, llong val, PrometheusLabels labels,
	Op op);
};

// histograms default to Prometheus buckets in milliseconds
extern BLISTER PrometheusMetrics &cntrstats, &gaugestats, &gdstats,
    &sumstats, &tdstats;

#endif // HTTPServer_h
