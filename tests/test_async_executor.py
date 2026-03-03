"""Tests for AsyncSymbolicExecutor and SymbolicEventLoop."""

import pytest


from pysymex.execution.async_executor import (
    AsyncSymbolicExecutor,
    CoroutineState,
    SymbolicCoroutine,
    SymbolicEventLoop,
)


class TestCoroutineState:
    """Coroutine lifecycle states."""

    def test_states_exist(self):
        assert CoroutineState.CREATED is not None

        assert CoroutineState.RUNNING is not None

        assert CoroutineState.SUSPENDED is not None

        assert CoroutineState.COMPLETED is not None

        assert CoroutineState.CANCELLED is not None

    def test_all_states_unique(self):
        states = [
            CoroutineState.CREATED,
            CoroutineState.RUNNING,
            CoroutineState.SUSPENDED,
            CoroutineState.COMPLETED,
            CoroutineState.CANCELLED,
        ]

        assert len(set(states)) == 5


class TestSymbolicCoroutine:
    """Symbolic coroutine representation."""

    def test_create(self):
        coro = SymbolicCoroutine(coro_id="test_0")

        assert coro.coro_id == "test_0"

        assert coro.state == CoroutineState.CREATED

        assert coro.vm_state is None

        assert coro.awaiting is None

    def test_with_name(self):
        coro = SymbolicCoroutine(coro_id="c1", name="my_coro")

        assert coro.name == "my_coro"


class TestSymbolicEventLoop:
    """Event loop for coroutine scheduling."""

    def test_create(self):
        loop = SymbolicEventLoop()

        assert loop.is_empty()

    def test_create_coroutine(self):
        loop = SymbolicEventLoop()

        coro = loop.create_coroutine("test_coro")

        assert coro.coro_id.startswith("coro_")

        assert coro.name == "test_coro"

    def test_schedule_coroutine(self):
        loop = SymbolicEventLoop()

        coro = loop.create_coroutine("c1")

        loop.schedule(coro)

        assert not loop.is_empty() or len(loop._ready) > 0

    def test_suspend_coroutine(self):
        loop = SymbolicEventLoop()

        coro = loop.create_coroutine("c1")

        loop.schedule(coro)

        loop.suspend_coroutine(coro.coro_id, vm_state=None, awaiting="other")

        assert coro.state == CoroutineState.SUSPENDED

        assert coro.awaiting == "other"

    def test_resume_coroutine(self):
        loop = SymbolicEventLoop()

        coro = loop.create_coroutine("c1")

        loop.schedule(coro)

        loop.suspend_coroutine(coro.coro_id, vm_state=None)

        resumed = loop.resume_coroutine(coro.coro_id)

        assert resumed is not None

        assert resumed.state == CoroutineState.RUNNING

    def test_complete_coroutine(self):
        loop = SymbolicEventLoop()

        coro = loop.create_coroutine("c1")

        loop.schedule(coro)

        loop.complete_coroutine(coro.coro_id, result=42)

        assert coro.state == CoroutineState.COMPLETED

        assert coro.result == 42

    def test_cancel_coroutine(self):
        loop = SymbolicEventLoop()

        coro = loop.create_coroutine("c1")

        loop.schedule(coro)

        result = loop.cancel_coroutine(coro.coro_id)

        assert result is True

        assert coro.state == CoroutineState.CANCELLED

    def test_cancel_completed_fails(self):
        loop = SymbolicEventLoop()

        coro = loop.create_coroutine("c1")

        loop.complete_coroutine(coro.coro_id)

        result = loop.cancel_coroutine(coro.coro_id)

        assert result is False

    def test_cancel_nonexistent(self):
        loop = SymbolicEventLoop()

        result = loop.cancel_coroutine("nonexistent")

        assert result is False


class TestEventLoopScheduling:
    """Scheduling and interleaving."""

    def test_get_possible_schedules_empty(self):
        loop = SymbolicEventLoop()

        schedules = loop.get_possible_schedules()

        assert schedules == []

    def test_get_possible_schedules_single(self):
        loop = SymbolicEventLoop()

        coro = loop.create_coroutine("c1")

        loop.schedule(coro)

        schedules = loop.get_possible_schedules()

        assert len(schedules) == 1

    def test_get_possible_schedules_two(self):
        loop = SymbolicEventLoop()

        c1 = loop.create_coroutine("c1")

        c2 = loop.create_coroutine("c2")

        loop.schedule(c1)

        loop.schedule(c2)

        schedules = loop.get_possible_schedules()

        assert len(schedules) == 2

    def test_max_interleavings_limit(self):
        loop = SymbolicEventLoop(max_interleavings=5)

        for i in range(10):
            coro = loop.create_coroutine(f"c{i}")

            loop.schedule(coro)

        schedules = loop.get_possible_schedules()

        assert len(schedules) <= 5

    def test_step_returns_ready_coroutines(self):
        loop = SymbolicEventLoop()

        c1 = loop.create_coroutine("c1")

        loop.schedule(c1)

        steps = loop.step()

        assert isinstance(steps, list)


class TestAwaitCycleDetection:
    """Deadlock detection via await cycles."""

    def test_no_cycles(self):
        loop = SymbolicEventLoop()

        c1 = loop.create_coroutine("c1")

        c2 = loop.create_coroutine("c2")

        cycles = loop.detect_await_cycles()

        assert cycles == []

    def test_simple_cycle(self):
        loop = SymbolicEventLoop()

        c1 = loop.create_coroutine("c1")

        c2 = loop.create_coroutine("c2")

        loop.schedule(c1)

        loop.schedule(c2)

        loop.suspend_coroutine(c1.coro_id, vm_state=None, awaiting=c2.coro_id)

        loop.suspend_coroutine(c2.coro_id, vm_state=None, awaiting=c1.coro_id)

        cycles = loop.detect_await_cycles()

        assert len(cycles) >= 1

    def test_no_cycle_linear(self):
        loop = SymbolicEventLoop()

        c1 = loop.create_coroutine("c1")

        c2 = loop.create_coroutine("c2")

        c3 = loop.create_coroutine("c3")

        loop.schedule(c1)

        loop.schedule(c2)

        loop.schedule(c3)

        loop.suspend_coroutine(c1.coro_id, vm_state=None, awaiting=c2.coro_id)

        loop.suspend_coroutine(c2.coro_id, vm_state=None, awaiting=c3.coro_id)

        cycles = loop.detect_await_cycles()

        assert cycles == []


class TestGetAllCoroutines:
    """Coroutine management."""

    def test_get_all_empty(self):
        loop = SymbolicEventLoop()

        assert loop.get_all_coroutines() == []

    def test_get_all(self):
        loop = SymbolicEventLoop()

        loop.create_coroutine("c1")

        loop.create_coroutine("c2")

        all_coros = loop.get_all_coroutines()

        assert len(all_coros) == 2


class TestCompletionResumption:
    """Completing a coroutine resumes waiters."""

    def test_completion_resumes_awaiter(self):
        loop = SymbolicEventLoop()

        c1 = loop.create_coroutine("c1")

        c2 = loop.create_coroutine("c2")

        loop.schedule(c1)

        loop.schedule(c2)

        loop.suspend_coroutine(c1.coro_id, vm_state=None, awaiting=c2.coro_id)

        loop.complete_coroutine(c2.coro_id, result="done")

        assert c1.state == CoroutineState.RUNNING
