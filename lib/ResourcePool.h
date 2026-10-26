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
#ifndef ResourcePool_h
#define ResourcePool_h

#include <algorithm>
#include <concepts>
#include <limits>
#include <memory>
#include <vector>
#include "Dispatch.h"

/*
 * Pools of lazily created resources, each shared by at most maxcount users.
 * Resources are constructed outside the pool lock. lock() waits for every
 * resource to be idle, then blocks other getters until unlock(); the holder
 * must not get() or clear() but release() still works
 */
template<default_initializable C>
class BLISTER ResourcePool: nocopy {
public:
    explicit ResourcePool(uint lim = 32, uint maxcount = 1): lmt(lim),
	maxuse(maxcount) {}
    ~ResourcePool() { clear(); }

    [[nodiscard]] C *allocate(void) {
	Locker lkr(lk);

	while (locked)
	    change.wait();
	return pool.size() + pending < lmt ? create() : nullptr;
    }
    [[nodiscard]] vector<C *> all(bool lockit = true, bool hold = false) {
	vector<C *> ret;

	if (lockit)
	    lock();

	FastLocker lkr(lk);

	ret.reserve(pool.size());
	for (Entry &e : pool)
	    ret.push_back(hold ? take(e) : e.obj.get());
	return ret;
    }
    void clear(uint cnt = numeric_limits<uint>::max()) {
	vector<Entry> dead;
	Locker lkr(lk);

	reap(cnt, dead);
    }
    [[nodiscard]] C *get(void) { return acquire(nullptr); }
    [[nodiscard]] C *getsticky(const C *prefer) { return acquire(prefer); }
    uint limit(void) const {
	FastLocker lkr(lk);

	return lmt;
    }
    void limit(uint lim) {
	vector<Entry> dead;		// cppcheck-suppress variableScope
	Locker lkr(lk);
	const uint old = exchange(lmt, lim);

	if (lim > old)
	    avail.set(lim - old);
	else if (pool.size() > lim)
	    reap((uint)pool.size() - lim, dead);
    }
    void lock(void) {
	Locker lkr(lk);

	while (locked)
	    change.wait();
	locked = true;
	while (used || pending)
	    change.wait();
    }
    void release(C *p) {
	FastLocker lkr(lk);

	--find(p)->inuse;
	--used;
	if (!locked)
	    avail.set();
	change.broadcast();
    }
    uint size(void) const {
	FastLocker lkr(lk);

	return (uint)pool.size();
    }
    void unlock(void) {
	FastLocker lkr(lk);

	locked = false;
	avail.broadcast();
	change.broadcast();
    }

private:
    struct Entry {
	unique_ptr<C> obj;
	uint inuse = 0;
    };
    using iterator = vector<Entry>::iterator;

    C *acquire(const C *prefer) {
	Locker lkr(lk);

	for (;;) {
	    iterator it = prefer ? find(prefer) : pool.end();

	    if (it == pool.end()) {
		prefer = nullptr;
		if (C *p = grab())
		    return p;
	    } else if (!locked && it->inuse < maxuse) {
		return take(*it);
	    }
	    (prefer ? change : avail).wait();
	}
    }
    // lk held but released while constructing: returns the new resource, taken
    C *create(void) {
	++pending;
	lk.unlock();

	unique_ptr<C> obj = make_unique<C>();

	lk.lock();
	--pending;
	return take(pool.emplace_back(std::move(obj)));
    }
    iterator find(const C *p) {
	return ranges::find(pool, p, [](const Entry &e) {
	    return e.obj.get();
	});
    }
    // any resource with capacity, round-robin; null if locked or full
    C *grab(void) {
	if (locked)
	    return nullptr;

	const size_t n = pool.size();
	size_t i = cursor < n ? cursor : 0;

	for (size_t k = 0; k < n; ++k) {
	    if (pool[i].inuse < maxuse) {
		cursor = i + 1;
		return take(pool[i]);
	    }
	    if (++i == n)
		i = 0;
	}
	return n + pending < lmt ? create() : nullptr;
    }
    void reap(uint cnt, vector<Entry> &dead) {
	for (;;) {
	    if (!locked) {
		size_t keep = 0;

		for (size_t i = 0; i < pool.size(); ++i) {
		    Entry &e = pool[i];

		    if (cnt && !e.inuse) {
			dead.push_back(std::move(e));
			--cnt;
		    } else if (keep++ != i) {
			pool[keep - 1] = std::move(e);
		    }
		}
		if (keep != pool.size()) {
		    avail.set((uint)(pool.size() - keep));
		    pool.resize(keep);
		}
	    }
	    if (!cnt || pool.empty())
		return;
	    change.wait();
	}
    }
    C *take(Entry &e) {
	++e.inuse;
	++used;
	return e.obj.get();
    }

    size_t cursor = 0;
    uint lmt;
    bool locked = false;
    const uint maxuse;
    uint pending = 0, used = 0;
    vector<Entry> pool;
    mutable Lock lk;
    Condvar avail { lk };
    Condvar change { lk };
};

template<default_initializable C>
class BLISTER AsyncResourcePool: nocopy {
public:
    // Waiters must be destroyed before the pool
    class BLISTER Waiter: public AsyncCondvar::Waiter {
    public:
	explicit Waiter(AsyncResourcePool &p): AsyncCondvar::Waiter(p.acv),
	    pool(p) {}
	Waiter(AsyncResourcePool &p, DispatchObj &parent):
	    AsyncCondvar::Waiter(p.acv, parent), pool(p) {}

	void get(DispatchObjCB cb, DispatchObj &co, C *&retp) {
	    begin(cb, co, retp, nullptr);
	}
	void getsticky(DispatchObjCB cb, DispatchObj &co, C *&retp) {
	    begin(cb, co, retp, retp);
	}

    private:
	void begin(DispatchObjCB cb, DispatchObj &co, C *&retp, const C *pref) {
	    caller = &co;
	    callercb = cb;
	    ret = &retp;
	    prefer = pref;
	    pool.lk.lock();
	    tryget();
	}

	DSP_DECLARE(Waiter, retry) {
	    pool.lk.lock();
	    tryget();
	}

	// pool lock held on entry and always released
	void tryget(void) {
	    auto it = prefer ? pool.find(prefer) : pool.pool.end();

	    if (it == pool.pool.end()) {
		prefer = nullptr;
		if (!(*ret = pool.grab())) {
		    wait(retry, pool.acv);
		    return;
		}
	    } else if (!pool.locked && it->inuse < pool.maxuse) {
		*ret = pool.take(*it);
	    } else {
		wait(retry, *it->cv);
		return;
	    }
	    pool.lk.unlock();
	    caller->ready(callercb);
	}

	AsyncResourcePool &pool;
	DispatchObj *caller = nullptr;
	DispatchObjCB callercb = nullptr;
	const C *prefer = nullptr;
	C **ret = nullptr;

	friend class AsyncResourcePool;
    };

    explicit AsyncResourcePool(Dispatcher &d, uint lim = 32, uint maxcount = 1):
	lmt(lim), maxuse(maxcount), acv(d, lk) {}
    ~AsyncResourcePool() { clear(); }

    [[nodiscard]] C *allocate(void) {
	Locker lkr(lk);

	while (locked)
	    change.wait();
	return pool.size() + pending < lmt ? create() : nullptr;
    }
    [[nodiscard]] vector<C *> all(bool lockit = true, bool hold = false) {
	vector<C *> ret;

	if (lockit)
	    lock();

	FastLocker lkr(lk);

	ret.reserve(pool.size());
	for (Entry &e : pool)
	    ret.push_back(hold ? take(e) : e.obj.get());
	return ret;
    }
    void clear(uint cnt = numeric_limits<uint>::max()) {
	vector<Entry> dead;
	Locker lkr(lk);

	reap(cnt, dead);
    }
    uint limit(void) const {
	FastLocker lkr(lk);

	return lmt;
    }
    void limit(uint lim) {
	vector<Entry> dead;
	Locker lkr(lk);
	const uint old = exchange(lmt, lim);

	if (lim > old) {
	    if (acv)
		acv.set(lim - old);
	} else if (pool.size() > lim) {
	    reap((uint)pool.size() - lim, dead);
	}
    }
    void lock(void) {
	Locker lkr(lk);

	while (locked)
	    change.wait();
	locked = true;
	while (ninuse || pending)
	    change.wait();
    }
    void release(C *p) {
	FastLocker lkr(lk);
	auto it = find(p);

	--it->inuse;
	--ninuse;
	change.broadcast();
	if (locked)
	    return;
	if (*it->cv)
	    it->cv->set();
	else if (acv)
	    acv.set();
    }
    uint size(void) const {
	FastLocker lkr(lk);

	return (uint)pool.size();
    }
    void unlock(void) {
	FastLocker lkr(lk);

	locked = false;
	change.broadcast();
	acv.broadcast();
	for (Entry &e : pool)
	    e.cv->broadcast();
    }

private:
    struct Entry {
	unique_ptr<C> obj;
	unique_ptr<AsyncCondvar> cv;
	uint inuse = 0;
    };
    using iterator = vector<Entry>::iterator;

    // lk held but released while constructing: returns the new resource, taken
    C *create(void) {
	++pending;
	lk.unlock();

	unique_ptr<C> obj = make_unique<C>();
	unique_ptr<AsyncCondvar> rcv = make_unique<AsyncCondvar>(
	    acv.dispatcher(), lk);

	lk.lock();
	--pending;
	return take(pool.emplace_back(std::move(obj), std::move(rcv)));
    }
    iterator find(const C *p) {
	return ranges::find(pool, p, [](const Entry &e) {
	    return e.obj.get();
	});
    }
    // any resource with capacity, round-robin; null if locked or full
    C *grab(void) {
	if (locked)
	    return nullptr;

	const size_t n = pool.size();
	size_t i = cursor < n ? cursor : 0;

	for (size_t k = 0; k < n; ++k) {
	    if (pool[i].inuse < maxuse) {
		cursor = i + 1;
		return take(pool[i]);
	    }
	    if (++i == n)
		i = 0;
	}
	return n + pending < lmt ? create() : nullptr;
    }
    void reap(uint cnt, vector<Entry> &dead) {
	for (;;) {
	    if (!locked) {
		size_t keep = 0;

		for (size_t i = 0; i < pool.size(); ++i) {
		    Entry &e = pool[i];

		    if (cnt && !e.inuse) {
			e.cv->requeue(acv);
			dead.push_back(std::move(e));
			--cnt;
		    } else if (keep++ != i) {
			pool[keep - 1] = std::move(e);
		    }
		}
		if (keep != pool.size()) {
		    if (acv)
			acv.set((uint)(pool.size() - keep));
		    pool.resize(keep);
		}
	    }
	    if (!cnt || pool.empty())
		return;
	    change.wait();
	}
    }
    C *take(Entry &e) {
	++e.inuse;
	++ninuse;
	return e.obj.get();
    }

    size_t cursor = 0;
    uint lmt;
    bool locked = false;
    const uint maxuse;
    uint ninuse = 0, pending = 0;
    vector<Entry> pool;
    mutable Lock lk;
    Condvar change { lk };
    AsyncCondvar acv;
};

#endif // ResourcePool_h
