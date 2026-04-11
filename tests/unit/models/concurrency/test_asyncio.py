from __future__ import annotations

import asyncio

import pytest

import pysymex.models.concurrency.asyncio as asyncio_models


async def _dummy_coro() -> int:
    return 1


class TestCoroutineModel:
    """Test suite for pysymex.models.concurrency.asyncio.CoroutineModel."""

    def test_faithfulness(self) -> None:
        """send returns the configured result while not done."""
        model = asyncio_models.CoroutineModel[int](_result=7)
        assert model.send(None) == 7

    def test_error_path(self) -> None:
        """send after close follows StopIteration semantics."""
        model = asyncio_models.CoroutineModel[int](_result=3)
        model.close()
        with pytest.raises(StopIteration):
            model.send(None)


class TestTaskModel:
    """Test suite for pysymex.models.concurrency.asyncio.TaskModel."""

    def test_faithfulness(self) -> None:
        """done task returns result and supports naming helpers."""
        coro = _dummy_coro()
        task = asyncio_models.TaskModel[int](_coro=coro, _result=9, _done=True)
        try:
            assert task.result() == 9
            assert task.set_name("worker").get_name() == "worker"
        finally:
            coro.close()

    def test_error_path(self) -> None:
        """result on pending task raises the expected exception."""
        coro = _dummy_coro()
        task = asyncio_models.TaskModel[int](_coro=coro)
        try:
            with pytest.raises(Exception, match="Task not done"):
                task.result()
        finally:
            coro.close()


class TestEventModel:
    """Test suite for pysymex.models.concurrency.asyncio.EventModel."""

    def test_faithfulness(self) -> None:
        """set and clear toggle event state."""
        event = asyncio_models.EventModel()
        event.set()
        assert event.is_set() is True
        event.clear()
        assert event.is_set() is False

    def test_error_path(self) -> None:
        """edge path: wait returns promptly even when unset."""
        event = asyncio_models.EventModel()
        assert asyncio.run(event.wait()) is True


class TestLockModel:
    """Test suite for pysymex.models.concurrency.asyncio.LockModel."""

    def test_faithfulness(self) -> None:
        """acquire and release update lock state."""
        lock = asyncio_models.LockModel()
        assert asyncio.run(lock.acquire()) is True
        assert lock.locked() is True
        lock.release()
        assert lock.locked() is False

    def test_error_path(self) -> None:
        """releasing unlocked lock raises RuntimeError."""
        lock = asyncio_models.LockModel()
        with pytest.raises(RuntimeError, match="not locked"):
            lock.release()


class TestSemaphoreModel:
    """Test suite for pysymex.models.concurrency.asyncio.SemaphoreModel."""

    def test_faithfulness(self) -> None:
        """acquire decrements and release increments internal value."""
        sem = asyncio_models.SemaphoreModel(2)
        assert asyncio.run(sem.acquire()) is True
        sem.release()
        assert sem.locked() is False

    def test_error_path(self) -> None:
        """edge path: acquire at zero succeeds in this model instead of blocking."""
        sem = asyncio_models.SemaphoreModel(0)
        assert asyncio.run(sem.acquire()) is True
        assert sem.locked() is False


class TestConditionModel:
    """Test suite for pysymex.models.concurrency.asyncio.ConditionModel."""

    def test_faithfulness(self) -> None:
        """acquire/release delegate to underlying lock."""
        cond = asyncio_models.ConditionModel()
        assert asyncio.run(cond.acquire()) is True
        assert cond.locked() is True
        cond.release()
        assert cond.locked() is False

    def test_error_path(self) -> None:
        """edge path: notify calls are no-op and do not raise."""
        cond = asyncio_models.ConditionModel()
        cond.notify(2)
        cond.notify_all()
        assert cond.locked() is False


class TestQueueModel:
    """Test suite for pysymex.models.concurrency.asyncio.QueueModel."""

    def test_faithfulness(self) -> None:
        """put/get preserve FIFO behavior and queue size."""
        queue = asyncio_models.QueueModel[int]()
        asyncio.run(queue.put(5))
        asyncio.run(queue.put(6))
        assert queue.qsize() == 2
        assert asyncio.run(queue.get()) == 5

    def test_error_path(self) -> None:
        """get_nowait on empty queue raises the expected exception."""
        queue = asyncio_models.QueueModel[int]()
        with pytest.raises(Exception, match="Queue is empty"):
            queue.get_nowait()


class TestFutureModel:
    """Test suite for pysymex.models.concurrency.asyncio.FutureModel."""

    def test_faithfulness(self) -> None:
        """set_result marks done and exposes result."""
        future = asyncio_models.FutureModel[int]()
        future.set_result(11)
        assert future.done() is True
        assert future.result() == 11

    def test_error_path(self) -> None:
        """setting result twice raises an error."""
        future = asyncio_models.FutureModel[int]()
        future.set_result(1)
        with pytest.raises(Exception, match="already done"):
            future.set_result(2)


def test_get_asyncio_model() -> None:
    """Known names are mapped and unknown names return None."""
    assert asyncio_models.get_asyncio_model("Task") is asyncio_models.TaskModel
    assert asyncio_models.get_asyncio_model("missing") is None
