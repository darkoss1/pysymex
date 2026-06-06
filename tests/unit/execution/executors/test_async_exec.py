from __future__ import annotations

import pytest

from pysymex.core.state.record import VMState
from pysymex.execution.executors.async_support.runner import (
    AsyncSymbolicExecutor,
    CoroutineState,
    SymbolicCoroutine,
    SymbolicEventLoop,
    analyze,
)
from pysymex.execution.config.settings import ExecutionConfig


class TestCoroutineState:
    """Test suite for pysymex.execution.executors.async_support.runner.CoroutineState."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert CoroutineState.CREATED.name == "CREATED"


class TestSymbolicCoroutine:
    """Test suite for pysymex.execution.executors.async_support.runner.SymbolicCoroutine."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        coro = SymbolicCoroutine(coro_id="c1", name="main")
        assert coro.coro_id == "c1"
        assert coro.state is CoroutineState.CREATED


class TestSymbolicEventLoop:
    """Test suite for pysymex.execution.executors.async_support.runner.SymbolicEventLoop."""

    def test_create_coroutine(self) -> None:
        """Test create_coroutine behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("task", VMState())
        assert coro.name == "task"

    def test_suspend_coroutine(self) -> None:
        """Test suspend_coroutine behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("t")
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
        loop.complete_coroutine(coro.coro_id, 42)
        assert coro.state is CoroutineState.COMPLETED
        assert coro.result == 42

    def test_step(self) -> None:
        """Test step behavior."""
        loop = SymbolicEventLoop()
        coro = loop.create_coroutine("a", VMState())
        loop.suspend_coroutine(coro.coro_id, VMState())
        loop.resume_coroutine(coro.coro_id)
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


class TestAsyncSymbolicExecutor:
    """Test suite for pysymex.execution.executors.async_support.runner.AsyncSymbolicExecutor."""

    @pytest.mark.asyncio
    @pytest.mark.timeout(30)
    async def test_execute_function(self) -> None:
        """Test execute_function behavior."""

        async def sample(x: int) -> int:
            return x + 1

        executor = AsyncSymbolicExecutor(ExecutionConfig(max_paths=4, max_iterations=40))
        executor.execute_function(sample, {"x": "int"})
        await sample(1)


@pytest.mark.asyncio
@pytest.mark.timeout(30)
async def test_analyze() -> None:
    """Test analyze behavior."""

    async def sample(v: int) -> int:
        return v * 2

    analyze(sample, {"v": "int"}, max_paths=3, max_iterations=30)
    await sample(2)
