"""Tests for threading primitive concurrency models."""

from __future__ import annotations

import pytest

from pysymex.models.concurrency.threading.locks import (
    BoundedSemaphoreModel,
    LockModel,
    RLockModel,
    SemaphoreModel,
)
from pysymex.models.concurrency.threading.threads import (
    ThreadModel,
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
        assert t.kwargs == {}

    def test_args_stored(self) -> None:
        """args tuple is stored."""
        t = ThreadModel(args=(1, 2, 3))
        assert t.args == (1, 2, 3)


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
        assert sem.value == 1

    def test_init_custom_value(self) -> None:
        """Custom initial value is stored."""
        sem = SemaphoreModel(5)
        assert sem.value == 5

    def test_init_negative_raises(self) -> None:
        """Negative initial value raises ValueError."""
        with pytest.raises(ValueError, match="must be >= 0"):
            SemaphoreModel(-1)

    def test_acquire_decrements(self) -> None:
        """acquire() decrements the value."""
        sem = SemaphoreModel(2)
        assert sem.acquire() is True
        assert sem.value == 1

    def test_acquire_at_zero_nonblocking(self) -> None:
        """Non-blocking acquire at zero returns False."""
        sem = SemaphoreModel(0)
        assert sem.acquire(blocking=False) is False

    def test_release_increments(self) -> None:
        """release() increments the value."""
        sem = SemaphoreModel(1)
        sem.acquire()
        sem.release()
        assert sem.value == 1

    def test_release_multiple(self) -> None:
        """release(n) increments by n."""
        sem = SemaphoreModel(0)
        sem.release(3)
        assert sem.value == 3

    def test_context_manager(self) -> None:
        """Semaphore works as context manager."""
        sem = SemaphoreModel(1)
        with sem:
            assert sem.value == 0
        assert sem.value == 1

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
        assert bsem.value == 1
