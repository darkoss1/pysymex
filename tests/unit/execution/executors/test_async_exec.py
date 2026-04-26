from __future__ import annotations

import sys
import pytest
import pytest

from pysymex.core.state import VMState
from pysymex.execution.executors.async_exec import (
    AsyncSymbolicExecutor,
    CoroutineState,
    SymbolicCoroutine,
    SymbolicEventLoop,
    analyze_async,
)
from pysymex.execution.types import ExecutionConfig


class TestCoroutineState:
    """Test suite for pysymex.execution.executors.async_exec.CoroutineState."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert CoroutineState.CREATED.name == "CREATED"


class TestSymbolicCoroutine:
    """Test suite for pysymex.execution.executors.async_exec.SymbolicCoroutine."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        coro = SymbolicCoroutine(coro_id="c1", name="main")
        assert coro.coro_id == "c1"
        assert coro.state is CoroutineState.CREATED


class TestSymbolicEventLoop:
    """Test suite for pysymex.execution.executors.async_exec.SymbolicEventLoop."""

    def test_create_coroutine(self) -> None:
        """Test create_coroutine behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("task", VMState())
        assert coro.name == "task"

    def test_schedule(self) -> None:
        """Test schedule behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("t")
        loop.schedule(coro)
        assert loop.is_empty() is False

    def test_suspend_coroutine(self) -> None:
        """Test suspend_coroutine behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("t")
        loop.schedule(coro)
        loop.suspend_coroutine(coro.coro_id, VMState())
        assert coro.state is CoroutineState.SUSPENDED

    def test_resume_coroutine(self) -> None:
        """Test resume_coroutine behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("t")
        loop.suspend_coroutine(coro.coro_id, VMState())
        resumed = loop.resume_coroutine(coro.coro_id)
        assert resumed is not None
        assert resumed.state is CoroutineState.RUNNING

    def test_complete_coroutine(self) -> None:
        """Test complete_coroutine behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("t")
        loop.schedule(coro)
        loop.complete_coroutine(coro.coro_id, 42)
        assert coro.state is CoroutineState.COMPLETED
        assert coro.result == 42

    def test_cancel_coroutine(self) -> None:
        """Test cancel_coroutine behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("t")
        ok = loop.cancel_coroutine(coro.coro_id)
        assert ok is True

    def test_get_possible_schedules(self) -> None:
        """Test get_possible_schedules behavior."""
        loop = SymbolicEventLoop()
        c1 = loop.create_coroutine("a")
        c2 = loop.create_coroutine("b")
        loop.schedule(c1)
        loop.schedule(c2)
        schedules = loop.get_possible_schedules()
        assert len(schedules) >= 1

    def test_step(self) -> None:
        """Test step behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("a", VMState())
        loop.schedule(coro)
        steps = loop.step()
        assert len(steps) == 1

    def test_detect_await_cycles(self) -> None:
        """Test detect_await_cycles behavior."""
        loop = SymbolicEventLoop()
        c1 = loop.create_coroutine("a")
        c2 = loop.create_coroutine("b")
        c1.awaiting = c2.coro_id
        c2.awaiting = c1.coro_id
        cycles = loop.detect_await_cycles()
        assert len(cycles) >= 1

    def test_is_empty(self) -> None:
        """Test is_empty behavior."""
        loop = SymbolicEventLoop()
        assert loop.is_empty() is True

    def test_get_all_coroutines(self) -> None:
        """Test get_all_coroutines behavior."""
        loop = SymbolicEventLoop()
        _ = loop.create_coroutine("a")
        all_coros = loop.get_all_coroutines()
        assert len(all_coros) == 1


class TestAsyncSymbolicExecutor:
    """Test suite for pysymex.execution.executors.async_exec.AsyncSymbolicExecutor."""

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_execute_function(self) -> None:
        """Test execute_function behavior."""

        async def sample(x: int) -> int:
            return x + 1

        import pysymex.execution.opcodes  # Ensure opcodes are registered

        executor = AsyncSymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))
        executor.execute_function(sample, {"x": "int"})
        await sample(1)


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_analyze_async() -> None:
    """Test analyze_async behavior."""

    async def sample(v: int) -> int:
        return v * 2

    analyze_async(sample, {"v": "int"}, max_paths=3, max_iterations=30)
    await sample(2)
