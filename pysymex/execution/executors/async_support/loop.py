# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Symbolic asyncio event-loop and coroutine scheduling models.

Used by :class:`~pysymex.execution.executors.async_support.runner.AsyncSymbolicExecutor`
to suspend/resume coroutines at await points and detect await cycles after a
scan completes.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from enum import Enum, auto

from pysymex.core.state.record import VMState


class CoroutineState(Enum):
    """Lifecycle state of a symbolic coroutine."""

    CREATED = auto()
    RUNNING = auto()
    SUSPENDED = auto()
    COMPLETED = auto()


@dataclass
class SymbolicCoroutine:
    """Represents a coroutine in symbolic execution."""

    coro_id: str
    state: CoroutineState = CoroutineState.CREATED
    vm_state: VMState | None = None
    result: object = None
    awaiting: str | None = None
    name: str = ""


class SymbolicEventLoop:
    """In-memory registry of symbolic coroutines and scheduling queues.

    Tracks ready, suspended, and completed coroutines. Does not execute bytecode
    itself; the async executor updates ``vm_state`` at suspension points and
    forks interleavings from the ready queue.

    Limitations:
        Task creation, cancellation, and ``asyncio`` primitives beyond
        await/resume are not modeled.
    """

    def __init__(self, max_interleavings: int = 1000) -> None:
        """Initialize empty coroutine tables and interleaving cap.

        Args:
            max_interleavings: Maximum ready coroutine records retained for
                future interleaving expansion.
        """
        self._ready: list[SymbolicCoroutine] = []
        self._suspended: dict[str, SymbolicCoroutine] = {}
        self._completed: dict[str, SymbolicCoroutine] = {}
        self._all_coroutines: dict[str, SymbolicCoroutine] = {}
        self._next_id: int = 0
        self._max_interleavings = max_interleavings

    def create_coroutine(
        self,
        name: str,
        initial_state: VMState | None = None,
    ) -> SymbolicCoroutine:
        """Create and register a new coroutine."""
        coro_id = f"coro_{self._next_id}"
        self._next_id += 1
        coro = SymbolicCoroutine(
            coro_id=coro_id,
            state=CoroutineState.CREATED,
            vm_state=initial_state,
            name=name or coro_id,
        )
        self._all_coroutines[coro_id] = coro
        return coro

    def suspend_coroutine(
        self,
        coro_id: str,
        vm_state: VMState,
        awaiting: str | None = None,
    ) -> None:
        """Suspend a coroutine at an await point."""
        coro = self._all_coroutines.get(coro_id)
        if coro is None:
            return
        coro.state = CoroutineState.SUSPENDED
        coro.vm_state = vm_state
        coro.awaiting = awaiting
        self._suspended[coro_id] = coro

        self._ready = [c for c in self._ready if c.coro_id != coro_id]

    def resume_coroutine(self, coro_id: str) -> SymbolicCoroutine | None:
        """Resume a suspended coroutine."""
        coro = self._suspended.pop(coro_id, None)
        if coro is None:
            return None
        coro.state = CoroutineState.RUNNING
        coro.awaiting = None
        self._ready.append(coro)
        return coro

    def complete_coroutine(
        self,
        coro_id: str,
        result: object = None,
    ) -> None:
        """Mark a coroutine as completed."""
        coro = self._all_coroutines.get(coro_id)
        if coro is None:
            return
        coro.state = CoroutineState.COMPLETED
        coro.result = result
        self._completed[coro_id] = coro
        self._ready = [c for c in self._ready if c.coro_id != coro_id]
        self._suspended.pop(coro_id, None)

        for sid, suspended in list(self._suspended.items()):
            if suspended.awaiting == coro_id:
                self.resume_coroutine(sid)

    def step(self) -> list[tuple[str, VMState]]:
        """Get possible next steps, one per ready coroutine."""
        steps: list[tuple[str, VMState]] = []
        for coro in itertools.islice(self._ready, self._max_interleavings):
            if coro.vm_state is not None:
                steps.append((coro.coro_id, coro.vm_state))
        return steps

    def detect_await_cycles(self) -> list[list[str]]:
        """Detect circular await chains using DFS."""
        await_graph: dict[str, str | None] = {}
        for coro_id, coro in self._all_coroutines.items():
            await_graph[coro_id] = coro.awaiting

        cycles: list[list[str]] = []
        visited: set[str] = set()
        in_path: set[str] = set()

        def dfs(node: str, path: list[str]) -> None:
            """Depth-first walk of the await graph to record cycles."""
            if node in in_path:
                idx = path.index(node)
                cycles.append([*path[idx:], node])
                return
            if node in visited:
                return
            visited.add(node)
            in_path.add(node)
            path.append(node)
            target = await_graph.get(node)
            if target is not None:
                dfs(target, path)
            path.pop()
            in_path.discard(node)

        for coro_id in await_graph:
            if coro_id not in visited:
                dfs(coro_id, [])

        return cycles
