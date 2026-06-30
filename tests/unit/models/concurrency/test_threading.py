from __future__ import annotations

import pytest

from pysymex._internal.models.stdlib.threading.state.locks import (
    BoundedSemaphoreModel,
    LockModel,
    RLockModel,
    SemaphoreModel,
)
from pysymex._internal.models.stdlib.threading.state.sync import (
    BarrierModel,
    ConditionModel,
    EventModel,
)
from pysymex._internal.models.stdlib.threading.state.threads import ThreadModel


class TestThreadModel:
    """Test suite for pysymex._internal.models.stdlib.threading.state.ThreadModel."""

    def test_faithfulness(self) -> None:
        """start and join update lifecycle state."""
        thread = ThreadModel(name="t")
        thread.start()
        assert thread.is_alive() is True
        thread.join()
        assert thread.is_alive() is False

    def test_error_path(self) -> None:
        """starting twice raises RuntimeError."""
        thread = ThreadModel()
        thread.start()
        with pytest.raises(RuntimeError, match="started once"):
            thread.start()


class TestLockModel:
    """Test suite for pysymex._internal.models.stdlib.threading.state.LockModel."""

    def test_faithfulness(self) -> None:
        """acquire and release toggle lock state."""
        lock = LockModel()
        assert lock.acquire() is True
        assert lock.locked() is True
        lock.release()
        assert lock.locked() is False

    def test_error_path(self) -> None:
        """releasing unlocked lock raises RuntimeError."""
        lock = LockModel()
        with pytest.raises(RuntimeError, match="unlocked"):
            lock.release()


class TestRLockModel:
    """Test suite for pysymex._internal.models.stdlib.threading.state.RLockModel."""

    def test_faithfulness(self) -> None:
        """reentrant acquire increments recursion depth."""
        lock = RLockModel()
        assert lock.acquire() is True
        assert lock.acquire() is True
        lock.release()
        assert lock.locked() is True

    def test_error_path(self) -> None:
        """releasing without acquisition raises RuntimeError."""
        lock = RLockModel()
        with pytest.raises(RuntimeError, match="unlocked"):
            lock.release()


class TestSemaphoreModel:
    """Test suite for pysymex._internal.models.stdlib.threading.state.SemaphoreModel."""

    def test_faithfulness(self) -> None:
        """acquire decrements positive semaphore and release restores it."""
        sem = SemaphoreModel(1)
        assert sem.acquire() is True
        sem.release()
        assert sem.acquire(blocking=False) is True

    def test_error_path(self) -> None:
        """non-blocking acquire fails when counter is zero."""
        sem = SemaphoreModel(0)
        assert sem.acquire(blocking=False) is False


class TestBoundedSemaphoreModel:
    """Test suite for pysymex._internal.models.stdlib.threading.state.BoundedSemaphoreModel."""

    def test_faithfulness(self) -> None:
        """acquire and balanced release succeed."""
        sem = BoundedSemaphoreModel(1)
        assert sem.acquire() is True
        sem.release()
        assert sem.acquire(blocking=False) is True

    def test_error_path(self) -> None:
        """release above initial value raises ValueError."""
        sem = BoundedSemaphoreModel(1)
        with pytest.raises(ValueError, match="too many"):
            sem.release()


class TestEventModel:
    """Test suite for pysymex._internal.models.stdlib.threading.state.EventModel."""

    def test_faithfulness(self) -> None:
        """set and clear control event flag."""
        event = EventModel()
        event.set()
        assert event.is_set() is True
        event.clear()
        assert event.is_set() is False

    def test_error_path(self) -> None:
        """edge path: wait on unset event returns False."""
        event = EventModel()
        assert event.wait(timeout=0.01) is False


class TestConditionModel:
    """Test suite for pysymex._internal.models.stdlib.threading.state.ConditionModel."""

    def test_faithfulness(self) -> None:
        """acquire and release track condition lock state."""
        cond = ConditionModel()
        assert cond.acquire() is True
        assert cond.locked() is True
        cond.release()
        assert cond.locked() is False

    def test_error_path(self) -> None:
        """wait on unlocked condition raises RuntimeError from lock release."""
        cond = ConditionModel()
        with pytest.raises(RuntimeError, match="unlocked"):
            cond.wait()


class TestBarrierModel:
    """Test suite for pysymex._internal.models.stdlib.threading.state.BarrierModel."""

    def test_faithfulness(self) -> None:
        """barrier wait returns arrival index and resets after trip."""
        barrier = BarrierModel(parties=2)
        first = barrier.wait()
        second = barrier.wait()
        assert first == 0
        assert second == 1
        assert barrier.n_waiting == 0

    def test_error_path(self) -> None:
        """broken barrier wait raises RuntimeError."""
        barrier = BarrierModel(parties=1)
        barrier.abort()
        with pytest.raises(RuntimeError, match="broken"):
            barrier.wait()
