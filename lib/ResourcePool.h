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
 * pools of lazily created resources, each shared by at most maxcount users
 * and constructed outside the pool lock. lock() waits until all are idle and
 * blocks getters until unlock(); the holder may release() but not get/clear
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
	Locker lkr(lk);

	if (lockit)
	    drain();
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
    [[nodiscard]] C *get(void) { return getsticky(nullptr); }
    // waits for prefer while it is still pooled, else gets any resource
    [[nodiscard]] C *getsticky(const C *prefer) {
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
    uint limit(void) const {
	FastLocker lkr(lk);

	return lmt;
    }
    void limit(uint lim) {
	vector<Entry> dead;		// cppcheck-suppress variableScope
	Locker lkr(lk);
	const uint old = exchange(lmt, lim);

	if (lim > old)
	    avail.broadcast();
	else if (pool.size() > lim)
	    reap((uint)pool.size() - lim, dead);
    }
    void lock(void) {
	Locker lkr(lk);

	drain();
    }
    void release(const C *p) {
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
	uint inuse = 0;
	unique_ptr<C> obj;
    };
    using iterator = vector<Entry>::iterator;

    // lk held but released while constructing: returns the new resource, taken
    C *create(void) {
	++pending;
	lk.unlock();

	unique_ptr<C> obj = make_unique<C>();

	lk.lock();
	--pending;
	return take(pool.emplace_back(0U, std::move(obj)));
    }
    // lk held: set locked once free, then wait for all users to release
    void drain(void) {
	while (locked)
	    change.wait();
	locked = true;
	while (used || pending)
	    change.wait();
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
    // remove up to cnt idle entries that exist now, waiting for busy ones
    void reap(uint cnt, vector<Entry> &dead) {
	cnt = (uint)min<size_t>(cnt, pool.size());
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

    Condvar avail { lk };
    Condvar change { lk };
    size_t cursor = 0;
    mutable Lock lk;
    uint lmt;
    bool locked = false;
    const uint maxuse;
    uint pending = 0;
    vector<Entry> pool;
    uint used = 0;
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
	~Waiter() override { Waiter::cancel(); }

	// pass on a wakeup this waiter received but did not consume
	void cancel(void) override {
	    AsyncCondvar::Waiter::cancel();

	    FastLocker lkr(pool.lk);

	    if (exchange(queued, false))
		pool.wake(prefer ? pool.find(prefer) : pool.pool.end());
	}

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
	    queued = false;
	    tryget();
	}

	// pool lock held on entry and always released
	void tryget(void) {
	    auto it = prefer ? pool.find(prefer) : pool.pool.end();

	    if (it == pool.pool.end()) {
		prefer = nullptr;
		if (!(*ret = pool.grab())) {
		    queued = true;
		    wait(retry, pool.acv);
		    return;
		}
	    } else if (!pool.locked && it->inuse < pool.maxuse) {
		*ret = pool.take(*it);
	    } else {
		queued = true;
		wait(retry, *it->cv);
		return;
	    }
	    pool.lk.unlock();
	    caller->ready(callercb);
	}

	DispatchObj *caller = nullptr;
	DispatchObjCB callercb = nullptr;
	AsyncResourcePool &pool;
	const C *prefer = nullptr;
	bool queued = false;
	C **ret = nullptr;

	friend class AsyncResourcePool;
    };

    explicit AsyncResourcePool(Dispatcher &d, uint lim = 32, uint maxcount = 1):
	acv(d, lk), lmt(lim), maxuse(maxcount) {}
    ~AsyncResourcePool() { clear(); }

    [[nodiscard]] C *allocate(void) {
	Locker lkr(lk);

	while (locked)
	    change.wait();
	return pool.size() + pending < lmt ? create() : nullptr;
    }
    [[nodiscard]] vector<C *> all(bool lockit = true, bool hold = false) {
	vector<C *> ret;
	Locker lkr(lk);

	if (lockit)
	    drain();
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
	vector<Entry> dead;		// cppcheck-suppress variableScope
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

	drain();
    }
    void release(const C *p) {
	FastLocker lkr(lk);
	auto it = find(p);

	--it->inuse;
	--used;
	change.broadcast();
	wake(it);
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
	unique_ptr<AsyncCondvar> cv;
	uint inuse = 0;
	unique_ptr<C> obj;
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
	return take(pool.emplace_back(std::move(rcv), 0U, std::move(obj)));
    }
    // lk held: set locked once free, then wait for all users to release
    void drain(void) {
	while (locked)
	    change.wait();
	locked = true;
	while (used || pending)
	    change.wait();
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
    // remove up to cnt idle entries that exist now, waiting for busy ones
    void reap(uint cnt, vector<Entry> &dead) {
	cnt = (uint)min<size_t>(cnt, pool.size());
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
	++used;
	return e.obj.get();
    }
    // pass one wakeup to a sticky waiter on it, else to any waiter
    void wake(iterator it) {
	if (locked)
	    return;
	if (it != pool.end() && *it->cv)
	    it->cv->set();
	else if (acv)
	    acv.set();
    }

    AsyncCondvar acv;
    Condvar change { lk };
    size_t cursor = 0;
    mutable Lock lk;
    uint lmt;
    bool locked = false;
    const uint maxuse;
    uint pending = 0;
    vector<Entry> pool;
    uint used = 0;
};

#endif // ResourcePool_h
