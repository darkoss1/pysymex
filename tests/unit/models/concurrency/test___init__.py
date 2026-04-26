"""Tests for pysymex.models.concurrency — threading model primitives."""

from __future__ import annotations

import pytest

from pysymex.models.concurrency import (
    BarrierModel,
    BoundedSemaphoreModel,
    ConditionModel,
    EventModel,
    LockModel,
    RLockModel,
    SemaphoreModel,
    ThreadModel,
    get_threading_model,
    THREADING_MODELS,
)


class TestThreadModel:
    """Tests for ThreadModel lifecycle."""

    def test_init_defaults(self) -> None:
        """ThreadModel initializes with default values."""
        t = ThreadModel()
        assert t.is_alive() is False
        assert isinstance(t.thread_id, str)
        assert t.daemon is False

    def test_init_custom(self) -> None:
        """ThreadModel accepts custom name, daemon, target."""
        t = ThreadModel(target=lambda: None, name="worker", daemon=True)
        assert t.name == "worker"
        assert t.daemon is True

    def test_start_sets_alive(self) -> None:
        """start() transitions thread to alive state."""
        t = ThreadModel()
        t.start()
        assert t.is_alive() is True

    def test_start_twice_raises(self) -> None:
        """start() called twice raises RuntimeError."""
        t = ThreadModel()
        t.start()
        with pytest.raises(RuntimeError, match="started once"):
            t.start()

    def test_join_clears_alive(self) -> None:
        """join() marks thread as no longer alive."""
        t = ThreadModel()
        t.start()
        t.join()
        assert t.is_alive() is False

    def test_join_with_timeout(self) -> None:
        """join(timeout=...) accepts a timeout argument."""
        t = ThreadModel()
        t.start()
        t.join(timeout=1.0)
        assert t.is_alive() is False

    def test_repr_not_started(self) -> None:
        """repr shows 'not started' for new thread."""
        t = ThreadModel(name="t1")
        r = repr(t)
        assert "not started" in r
        assert "t1" in r

    def test_repr_started_alive(self) -> None:
        """repr shows 'started' and 'alive' after start."""
        t = ThreadModel(name="t2")
        t.start()
        r = repr(t)
        assert "started" in r
        assert "alive" in r

    def test_thread_id_unique(self) -> None:
        """Each ThreadModel gets a unique thread_id."""
        t1 = ThreadModel()
        t2 = ThreadModel()
        assert t1.thread_id != t2.thread_id

    def test_kwargs_default(self) -> None:
        """kwargs defaults to empty dict."""
        t = ThreadModel()
        assert t._kwargs == {}

    def test_args_stored(self) -> None:
        """args tuple is stored."""
        t = ThreadModel(args=(1, 2, 3))
        assert t._args == (1, 2, 3)


class TestLockModel:
    """Tests for LockModel acquire/release."""

    def test_init_unlocked(self) -> None:
        """Lock starts unlocked."""
        lock = LockModel()
        assert lock.locked() is False

    def test_acquire_locks(self) -> None:
        """acquire() sets lock to locked."""
        lock = LockModel()
        result = lock.acquire()
        assert result is True
        assert lock.locked() is True

    def test_release_unlocks(self) -> None:
        """release() unlocks the lock."""
        lock = LockModel()
        lock.acquire()
        lock.release()
        assert lock.locked() is False

    def test_release_unlocked_raises(self) -> None:
        """release() on unlocked lock raises RuntimeError."""
        lock = LockModel()
        with pytest.raises(RuntimeError, match="release unlocked lock"):
            lock.release()

    def test_acquire_nonblocking_fails_when_locked(self) -> None:
        """Non-blocking acquire returns False when locked."""
        lock = LockModel()
        lock.acquire()
        result = lock.acquire(blocking=False)
        assert result is False

    def test_context_manager(self) -> None:
        """Lock works as context manager."""
        lock = LockModel()
        with lock:
            assert lock.locked() is True
        assert lock.locked() is False

    def test_name_property(self) -> None:
        """name property returns a string."""
        lock = LockModel()
        assert isinstance(lock.name, str)
        assert lock.name.startswith("lock_")

    def test_repr(self) -> None:
        """repr shows locked/unlocked status."""
        lock = LockModel()
        assert "unlocked" in repr(lock)
        lock.acquire()
        assert "locked" in repr(lock)


class TestRLockModel:
    """Tests for RLockModel reentrant behavior."""

    def test_acquire_twice(self) -> None:
        """RLock can be acquired multiple times."""
        rlock = RLockModel()
        assert rlock.acquire() is True
        assert rlock.acquire() is True
        assert rlock.locked() is True

    def test_release_decrements_count(self) -> None:
        """Each release() decrements the reentrant count."""
        rlock = RLockModel()
        rlock.acquire()
        rlock.acquire()
        rlock.release()
        assert rlock.locked() is True
        rlock.release()
        assert rlock.locked() is False

    def test_release_unlocked_raises(self) -> None:
        """release() on unlocked RLock raises RuntimeError."""
        rlock = RLockModel()
        with pytest.raises(RuntimeError, match="release unlocked lock"):
            rlock.release()

    def test_repr(self) -> None:
        """repr shows count for locked RLock."""
        rlock = RLockModel()
        rlock.acquire()
        assert "count=1" in repr(rlock)
        rlock.acquire()
        assert "count=2" in repr(rlock)


class TestSemaphoreModel:
    """Tests for SemaphoreModel counting behavior."""

    def test_init_default_value(self) -> None:
        """Default semaphore value is 1."""
        sem = SemaphoreModel()
        assert sem._value == 1

    def test_init_custom_value(self) -> None:
        """Custom initial value is stored."""
        sem = SemaphoreModel(5)
        assert sem._value == 5

    def test_init_negative_raises(self) -> None:
        """Negative initial value raises ValueError."""
        with pytest.raises(ValueError, match="must be >= 0"):
            SemaphoreModel(-1)

    def test_acquire_decrements(self) -> None:
        """acquire() decrements the value."""
        sem = SemaphoreModel(2)
        assert sem.acquire() is True
        assert sem._value == 1

    def test_acquire_at_zero_nonblocking(self) -> None:
        """Non-blocking acquire at zero returns False."""
        sem = SemaphoreModel(0)
        assert sem.acquire(blocking=False) is False

    def test_release_increments(self) -> None:
        """release() increments the value."""
        sem = SemaphoreModel(1)
        sem.acquire()
        sem.release()
        assert sem._value == 1

    def test_release_multiple(self) -> None:
        """release(n) increments by n."""
        sem = SemaphoreModel(0)
        sem.release(3)
        assert sem._value == 3

    def test_context_manager(self) -> None:
        """Semaphore works as context manager."""
        sem = SemaphoreModel(1)
        with sem:
            assert sem._value == 0
        assert sem._value == 1

    def test_repr(self) -> None:
        """repr shows current value."""
        sem = SemaphoreModel(3)
        assert "value=3" in repr(sem)


class TestBoundedSemaphoreModel:
    """Tests for BoundedSemaphoreModel overflow protection."""

    def test_release_beyond_initial_raises(self) -> None:
        """Releasing beyond initial value raises ValueError."""
        bsem = BoundedSemaphoreModel(1)
        with pytest.raises(ValueError, match="released too many times"):
            bsem.release()

    def test_acquire_then_release_ok(self) -> None:
        """Normal acquire-release cycle works."""
        bsem = BoundedSemaphoreModel(1)
        bsem.acquire()
        bsem.release()
        assert bsem._value == 1


class TestEventModel:
    """Tests for EventModel flag management."""

    def test_init_not_set(self) -> None:
        """Event starts unset."""
        event = EventModel()
        assert event.is_set() is False

    def test_set(self) -> None:
        """set() sets the flag."""
        event = EventModel()
        event.set()
        assert event.is_set() is True

    def test_clear(self) -> None:
        """clear() clears the flag."""
        event = EventModel()
        event.set()
        event.clear()
        assert event.is_set() is False

    def test_wait_returns_flag(self) -> None:
        """wait() returns current flag state."""
        event = EventModel()
        assert event.wait() is False
        event.set()
        assert event.wait() is True

    def test_wait_with_timeout(self) -> None:
        """wait(timeout=...) accepts a timeout argument."""
        event = EventModel()
        assert event.wait(timeout=0.1) is False

    def test_repr(self) -> None:
        """repr shows set status."""
        event = EventModel()
        assert "set=False" in repr(event)
        event.set()
        assert "set=True" in repr(event)


class TestConditionModel:
    """Tests for ConditionModel wait/notify."""

    def test_init_default_lock(self) -> None:
        """ConditionModel creates its own lock by default."""
        cond = ConditionModel()
        assert isinstance(cond._lock, LockModel)

    def test_init_custom_lock(self) -> None:
        """ConditionModel accepts a custom lock."""
        lock = LockModel()
        cond = ConditionModel(lock=lock)
        assert cond._lock is lock

    def test_acquire_release(self) -> None:
        """acquire and release delegate to underlying lock."""
        cond = ConditionModel()
        cond.acquire()
        assert cond.locked() is True
        cond.release()
        assert cond.locked() is False

    def test_wait_releases_and_reacquires(self) -> None:
        """wait() releases and reacquires the lock."""
        cond = ConditionModel()
        cond.acquire()
        result = cond.wait()
        assert result is True
        assert cond.locked() is True

    def test_wait_for_returns_true(self) -> None:
        """wait_for() returns True (simplified model)."""
        cond = ConditionModel()
        cond.acquire()
        assert cond.wait_for(lambda: True) is True

    def test_notify(self) -> None:
        """notify() clears waiters."""
        cond = ConditionModel()
        cond._waiters.append("waiter1")
        cond.notify()
        assert len(cond._waiters) == 0

    def test_notify_all(self) -> None:
        """notify_all() clears all waiters."""
        cond = ConditionModel()
        cond._waiters.extend(["w1", "w2", "w3"])
        cond.notify_all()
        assert len(cond._waiters) == 0

    def test_context_manager(self) -> None:
        """ConditionModel works as context manager."""
        cond = ConditionModel()
        with cond:
            assert cond.locked() is True
        assert cond.locked() is False

    def test_repr(self) -> None:
        """repr shows locked status."""
        cond = ConditionModel()
        assert "locked=False" in repr(cond)


class TestBarrierModel:
    """Tests for BarrierModel synchronization."""

    def test_init(self) -> None:
        """BarrierModel initializes with parties."""
        b = BarrierModel(3)
        assert b.parties == 3
        assert b.n_waiting == 0
        assert b.broken is False

    def test_init_zero_parties_raises(self) -> None:
        """parties < 1 raises ValueError."""
        with pytest.raises(ValueError, match="parties must be >= 1"):
            BarrierModel(0)

    def test_wait_increments_count(self) -> None:
        """wait() increments the waiting count."""
        b = BarrierModel(3)
        idx = b.wait()
        assert idx == 0
        assert b.n_waiting == 1

    def test_wait_trips_at_parties(self) -> None:
        """Barrier trips when all parties arrive."""
        b = BarrierModel(2)
        b.wait()
        b.wait()
        assert b.n_waiting == 0

    def test_wait_calls_action(self) -> None:
        """Action callback is called when barrier trips."""
        called: list[bool] = []
        b = BarrierModel(1, action=lambda: called.append(True))
        b.wait()
        assert called == [True]

    def test_wait_broken_raises(self) -> None:
        """wait() on broken barrier raises RuntimeError."""
        b = BarrierModel(2)
        b.abort()
        with pytest.raises(RuntimeError, match="barrier is broken"):
            b.wait()

    def test_reset(self) -> None:
        """reset() clears count and broken state."""
        b = BarrierModel(2)
        b.wait()
        b.abort()
        b.reset()
        assert b.n_waiting == 0
        assert b.broken is False

    def test_abort(self) -> None:
        """abort() sets broken state."""
        b = BarrierModel(2)
        b.abort()
        assert b.broken is True

    def test_action_exception_breaks_barrier(self) -> None:
        """Exception in action breaks the barrier."""

        def bad_action() -> None:
            raise ValueError("boom")

        b = BarrierModel(1, action=bad_action)
        with pytest.raises(ValueError, match="boom"):
            b.wait()
        assert b.broken is True

    def test_repr(self) -> None:
        """repr shows parties, waiting, broken."""
        b = BarrierModel(3)
        r = repr(b)
        assert "parties=3" in r
        assert "waiting=0" in r
        assert "broken=False" in r


class TestGetThreadingModel:
    """Tests for get_threading_model lookup."""

    def test_known_model(self) -> None:
        """Known model names return the class."""
        assert get_threading_model("Lock") is LockModel
        assert get_threading_model("Thread") is ThreadModel

    def test_unknown_returns_none(self) -> None:
        """Unknown name returns None."""
        assert get_threading_model("Nonexistent") is None


class TestThreadingModelsDict:
    """Tests for THREADING_MODELS registry."""

    def test_contains_all_models(self) -> None:
        """Registry contains all 8 threading primitives."""
        expected = {
            "Thread",
            "Lock",
            "RLock",
            "Semaphore",
            "BoundedSemaphore",
            "Event",
            "Condition",
            "Barrier",
        }
        assert set(THREADING_MODELS.keys()) == expected
