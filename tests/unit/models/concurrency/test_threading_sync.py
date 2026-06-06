"""Tests for threading synchronization concurrency models."""

from __future__ import annotations

import pytest

from pysymex.models.concurrency.threading.locks import LockModel
from pysymex.models.concurrency.threading.registry import THREADING_MODELS, get_threading_model
from pysymex.models.concurrency.threading.sync import (
    BarrierModel,
    ConditionModel,
    EventModel,
)
from pysymex.models.concurrency.threading.threads import (
    ThreadModel,
)


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
        assert isinstance(cond.lock, LockModel)

    def test_init_custom_lock(self) -> None:
        """ConditionModel accepts a custom lock."""
        lock = LockModel()
        cond = ConditionModel(lock=lock)
        assert cond.lock is lock

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
        cond.waiters.append("waiter1")
        cond.notify()
        assert len(cond.waiters) == 0

    def test_notify_all(self) -> None:
        """notify_all() clears all waiters."""
        cond = ConditionModel()
        cond.waiters.extend(["w1", "w2", "w3"])
        cond.notify_all()
        assert len(cond.waiters) == 0

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
