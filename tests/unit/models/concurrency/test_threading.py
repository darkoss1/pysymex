from __future__ import annotations

import pytest

import pysymex.models.concurrency.threading as threading_models


class TestThreadModel:
    """Test suite for pysymex.models.concurrency.threading.ThreadModel."""

    def test_faithfulness(self) -> None:
        """start and join update lifecycle state."""
        thread = threading_models.ThreadModel(name="t")
        thread.start()
        assert thread.is_alive() is True
        thread.join()
        assert thread.is_alive() is False

    def test_error_path(self) -> None:
        """starting twice raises RuntimeError."""
        thread = threading_models.ThreadModel()
        thread.start()
        with pytest.raises(RuntimeError, match="started once"):
            thread.start()


class TestLockModel:
    """Test suite for pysymex.models.concurrency.threading.LockModel."""

    def test_faithfulness(self) -> None:
        """acquire and release toggle lock state."""
        lock = threading_models.LockModel()
        assert lock.acquire() is True
        assert lock.locked() is True
        lock.release()
        assert lock.locked() is False

    def test_error_path(self) -> None:
        """releasing unlocked lock raises RuntimeError."""
        lock = threading_models.LockModel()
        with pytest.raises(RuntimeError, match="unlocked"):
            lock.release()


class TestRLockModel:
    """Test suite for pysymex.models.concurrency.threading.RLockModel."""

    def test_faithfulness(self) -> None:
        """reentrant acquire increments recursion depth."""
        lock = threading_models.RLockModel()
        assert lock.acquire() is True
        assert lock.acquire() is True
        lock.release()
        assert lock.locked() is True

    def test_error_path(self) -> None:
        """releasing without acquisition raises RuntimeError."""
        lock = threading_models.RLockModel()
        with pytest.raises(RuntimeError, match="unlocked"):
            lock.release()


class TestSemaphoreModel:
    """Test suite for pysymex.models.concurrency.threading.SemaphoreModel."""

    def test_faithfulness(self) -> None:
        """acquire decrements positive semaphore and release restores it."""
        sem = threading_models.SemaphoreModel(1)
        assert sem.acquire() is True
        sem.release()
        assert sem.acquire(blocking=False) is True

    def test_error_path(self) -> None:
        """non-blocking acquire fails when counter is zero."""
        sem = threading_models.SemaphoreModel(0)
        assert sem.acquire(blocking=False) is False


class TestBoundedSemaphoreModel:
    """Test suite for pysymex.models.concurrency.threading.BoundedSemaphoreModel."""

    def test_faithfulness(self) -> None:
        """acquire and balanced release succeed."""
        sem = threading_models.BoundedSemaphoreModel(1)
        assert sem.acquire() is True
        sem.release()
        assert sem.acquire(blocking=False) is True

    def test_error_path(self) -> None:
        """release above initial value raises ValueError."""
        sem = threading_models.BoundedSemaphoreModel(1)
        with pytest.raises(ValueError, match="too many"):
            sem.release()


class TestEventModel:
    """Test suite for pysymex.models.concurrency.threading.EventModel."""

    def test_faithfulness(self) -> None:
        """set and clear control event flag."""
        event = threading_models.EventModel()
        event.set()
        assert event.is_set() is True
        event.clear()
        assert event.is_set() is False

    def test_error_path(self) -> None:
        """edge path: wait on unset event returns False."""
        event = threading_models.EventModel()
        assert event.wait(timeout=0.01) is False


class TestConditionModel:
    """Test suite for pysymex.models.concurrency.threading.ConditionModel."""

    def test_faithfulness(self) -> None:
        """acquire and release track condition lock state."""
        cond = threading_models.ConditionModel()
        assert cond.acquire() is True
        assert cond.locked() is True
        cond.release()
        assert cond.locked() is False

    def test_error_path(self) -> None:
        """wait on unlocked condition raises RuntimeError from lock release."""
        cond = threading_models.ConditionModel()
        with pytest.raises(RuntimeError, match="unlocked"):
            cond.wait()


class TestBarrierModel:
    """Test suite for pysymex.models.concurrency.threading.BarrierModel."""

    def test_faithfulness(self) -> None:
        """barrier wait returns arrival index and resets after trip."""
        barrier = threading_models.BarrierModel(parties=2)
        first = barrier.wait()
        second = barrier.wait()
        assert first == 0
        assert second == 1
        assert barrier.n_waiting == 0

    def test_error_path(self) -> None:
        """broken barrier wait raises RuntimeError."""
        barrier = threading_models.BarrierModel(parties=1)
        barrier.abort()
        with pytest.raises(RuntimeError, match="broken"):
            barrier.wait()


def test_get_threading_model() -> None:
    """Known threading names resolve, unknown names do not."""
    assert threading_models.get_threading_model("Lock") is threading_models.LockModel
    assert threading_models.get_threading_model("missing") is None
