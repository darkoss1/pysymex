"""Tests for pysymex.models.concurrency.asyncio — QueueModel.join waiter."""

from __future__ import annotations

import asyncio

import pytest


class TestQueueModelJoinWaiter:
    """Test the QueueModel.join() async waiter closure."""

    @pytest.mark.asyncio
    @pytest.mark.timeout(10)
    async def test_join_returns_awaitable(self) -> None:
        """QueueModel.join() returns an awaitable that resolves to None."""
        from pysymex.models.concurrency.asyncio import QueueModel

        q: QueueModel[int] = QueueModel()
        result = q.join()
        assert asyncio.iscoroutine(result)
        await result

    @pytest.mark.asyncio
    @pytest.mark.timeout(10)
    async def test_join_waiter_completes(self) -> None:
        """The inner waiter() coroutine completes without error."""
        from pysymex.models.concurrency.asyncio import QueueModel

        q: QueueModel[str] = QueueModel()
        awaitable = q.join()
        value = await awaitable
        assert value is None


class TestQueueModelTaskDone:
    """Test QueueModel.task_done edge cases."""

    def test_task_done_too_many_raises(self) -> None:
        """task_done() raises ValueError when called too many times."""
        from pysymex.models.concurrency.asyncio import QueueModel

        q: QueueModel[int] = QueueModel()
        with pytest.raises(ValueError, match="too many"):
            q.task_done()
