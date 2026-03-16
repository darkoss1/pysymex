"""Async/await coroutine scheduling model for symbolic execution.

Provides a symbolic event loop that models coroutine scheduling with
all possible interleavings at await points, enabling detection of
async-specific bugs like await-cycle deadlocks.
"""

from __future__ import annotations

import itertools
import logging
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum, auto

logger = logging.getLogger(__name__)

from pysymex.analysis.concurrency import ConcurrencyAnalyzer
from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.state import VMState
from pysymex.execution.executor import (
    BRANCH_OPCODES,
    ExecutionConfig,
    ExecutionResult,
    SymbolicExecutor,
)


class CoroutineState(Enum):
    """Lifecycle state of a symbolic coroutine.

    Transitions: ``CREATED → RUNNING → SUSPENDED ⇄ RUNNING → COMPLETED``.
    A coroutine may also be ``CANCELLED`` at any point before completion.
    """

    CREATED = auto()
    RUNNING = auto()
    SUSPENDED = auto()
    COMPLETED = auto()
    CANCELLED = auto()


@dataclass
class SymbolicCoroutine:
    """Represents a coroutine in symbolic execution.

    Attributes:
        coro_id: Unique identifier for this coroutine.
        state: Current lifecycle state.
        vm_state: Saved VM state when suspended.
        result: Return value after completion.
        awaiting: ID of the coroutine being awaited, if any.
        name: Human-readable coroutine name.
    """

    coro_id: str
    state: CoroutineState = CoroutineState.CREATED
    vm_state: VMState | None = None
    result: object = None
    awaiting: str | None = None
    name: str = ""


class SymbolicEventLoop:
    """Models an asyncio event loop for symbolic execution.

    At each await point, the event loop generates all possible
    scheduling orderings of ready coroutines, enabling exploration
    of async interleavings.

    Args:
        max_interleavings: Maximum number of scheduling permutations
                           to explore at each await point.
    """

    def __init__(self, max_interleavings: int = 1000) -> None:
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
        coro_id = f"coro_{self ._next_id }"
        self._next_id += 1
        coro = SymbolicCoroutine(
            coro_id=coro_id,
            state=CoroutineState.CREATED,
            vm_state=initial_state,
            name=name or coro_id,
        )
        self._all_coroutines[coro_id] = coro
        return coro

    def schedule(self, coro: SymbolicCoroutine) -> None:
        """Add a coroutine to the ready queue."""
        coro.state = CoroutineState.CREATED
        if coro not in self._ready:
            self._ready.append(coro)

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

    def cancel_coroutine(self, coro_id: str) -> bool:
        """Cancel a coroutine. Returns True if successfully cancelled."""
        coro = self._all_coroutines.get(coro_id)
        if coro is None or coro.state == CoroutineState.COMPLETED:
            return False
        coro.state = CoroutineState.CANCELLED
        self._ready = [c for c in self._ready if c.coro_id != coro_id]
        self._suspended.pop(coro_id, None)
        return True

    def get_possible_schedules(self) -> list[list[str]]:
        """Return all possible orderings of ready coroutines.

        Bounded by max_interleavings. For N ready coroutines,
        generates up to N! permutations (pruned).
        """
        ready_ids = [c.coro_id for c in self._ready]
        if not ready_ids:
            return []

        schedules: list[list[str]] = []
        for perm in itertools.islice(
            itertools.permutations(ready_ids),
            self._max_interleavings,
        ):
            schedules.append(list(perm))
        return schedules

    def step(self) -> list[tuple[str, VMState]]:
        """Get possible next steps (one per ready coroutine).

        Returns list of (coro_id, vm_state) pairs for each coroutine
        that could be scheduled next.
        """
        steps: list[tuple[str, VMState]] = []
        for coro in self._ready:
            if coro.vm_state is not None:
                steps.append((coro.coro_id, coro.vm_state))
        return steps

    def detect_await_cycles(self) -> list[list[str]]:
        """Detect circular await chains using DFS.

        Returns list of cycles found (e.g., [["A", "B", "A"]]
        means A awaits B and B awaits A).
        """
        await_graph: dict[str, str | None] = {}
        for coro_id, coro in self._all_coroutines.items():
            await_graph[coro_id] = coro.awaiting

        cycles: list[list[str]] = []
        visited: set[str] = set()
        in_path: set[str] = set()

        def dfs(node: str, path: list[str]) -> None:
            """Dfs."""
            if node in in_path:
                idx = path.index(node)
                cycles.append(path[idx:] + [node])
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

    def is_empty(self) -> bool:
        """Check if there are no more schedulable coroutines."""
        return not self._ready and not self._suspended

    def get_all_coroutines(self) -> list[SymbolicCoroutine]:
        """Return all registered coroutines."""
        return list(self._all_coroutines.values())


_ASYNC_OPCODES = frozenset(
    {
        "GET_AWAITABLE",
        "SEND",
        "YIELD_VALUE",
        "GET_AITER",
        "GET_ANEXT",
        "END_ASYNC_FOR",
        "BEFORE_ASYNC_WITH",
        "RETURN_GENERATOR",
    }
)


class AsyncSymbolicExecutor(SymbolicExecutor):
    """Symbolic executor with async/await coroutine scheduling.

    At each await point (GET_AWAITABLE), explores possible interleavings
    of ready coroutines. Detects await-cycle deadlocks.
    """

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        **kwargs: object,
    ) -> None:
        super().__init__(config=config, **kwargs)
        self._event_loop = SymbolicEventLoop(max_interleavings=self.config.max_interleavings)
        self._coroutine_states: dict[str, VMState] = {}
        self._current_coro_id: str | None = None
        self._concurrency_analyzer: ConcurrencyAnalyzer | None = None

        if self.config.enable_concurrency_analysis:
            try:
                self._concurrency_analyzer = ConcurrencyAnalyzer(
                    timeout_ms=self.config.solver_timeout_ms
                )
            except (RuntimeError, TypeError, ValueError):
                logger.error("Internal AsyncExecutor error during coroutine interleaving or cycle detection", exc_info=True)

    def execute_function(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
    ) -> ExecutionResult:
        """Execute with async analysis."""
        result = super().execute_function(func, symbolic_args)

        deadlock_issues = self._check_await_deadlocks()
        result.issues.extend(deadlock_issues)

        return result

    def _execute_step(self, state: VMState) -> None:
        """Execute with async interception."""
        instr, active_instructions = self._fetch_instruction(state)
        if instr is None:
            self._paths_completed += 1
            self._last_globals = state.global_vars
            self._last_locals = state.local_vars

            if self._current_coro_id:
                self._event_loop.complete_coroutine(self._current_coro_id)
            return

        if not self._check_resource_limits(state):
            return

        if self._state_merger is not None and self._state_merger.should_merge(state):
            merged = self._state_merger.add_state_for_merge(state)
            if merged is None:
                self._paths_pruned += 1
                return
            if merged is not state:
                state = merged

        if not self._handle_loop_logic(state, active_instructions):
            return

        state_key = self._state_key(state)
        if state_key in self._visited_states:
            self._paths_pruned += 1
            return
        else:
            self._visited_states.add(state_key)

        self._coverage.add(state.pc)
        state.visited_pcs.add(state.pc)

        needs_check = (
            instr.opname in BRANCH_OPCODES
            or state.pending_constraint_count >= self.config.lazy_eval_threshold
        )
        if needs_check:
            if not self._check_path_feasibility(state):
                return
            state.pending_constraint_count = 0

        if instr.opname in _ASYNC_OPCODES:
            self._intercept_async(instr, state)

        self._run_detectors(state, instr, active_instructions)

        try:
            result = self.dispatcher.dispatch(instr, state)
            self._process_execution_result(result, state, active_instructions)
        except (RuntimeError, TypeError, ValueError, KeyError, AttributeError, IndexError) as e:
            if self.config.verbose:
                logger.warning("Execution error at PC %d: %s", state.pc, e)
            self._paths_pruned += 1
            return

    def _intercept_async(self, instr: object, state: VMState) -> None:
        """Intercept async opcodes for coroutine scheduling."""
        try:
            if instr.opname == "GET_AWAITABLE":

                if self._current_coro_id:
                    self._event_loop.suspend_coroutine(
                        self._current_coro_id,
                        state.fork(),
                        awaiting=None,
                    )
                self._explore_interleavings(state)

            elif instr.opname == "YIELD_VALUE":

                if self._current_coro_id:
                    self._event_loop.suspend_coroutine(
                        self._current_coro_id,
                        state.fork(),
                    )

            elif instr.opname == "SEND":

                if self._current_coro_id:
                    self._event_loop.resume_coroutine(self._current_coro_id)

            elif instr.opname == "RETURN_GENERATOR":

                coro = self._event_loop.create_coroutine(
                    name=f"gen_{state .pc }",
                    initial_state=state.fork(),
                )
                self._current_coro_id = coro.coro_id

        except (AttributeError, KeyError, RuntimeError):
            logger.error("Internal AsyncExecutor error during coroutine interleaving or cycle detection", exc_info=True)

    def _explore_interleavings(self, state: VMState) -> None:
        """At an await point, fork states for possible schedulings."""
        try:
            steps = self._event_loop.step()
            if len(steps) <= 1:
                return

            for _coro_id, coro_state in steps:
                forked = state.fork()
                forked = forked.set_pc(coro_state.pc)
                if self._worklist:
                    self._worklist.add_state(forked)
                self._paths_explored += 1
        except (RuntimeError, KeyError):
            logger.error("Internal AsyncExecutor error during coroutine interleaving or cycle detection", exc_info=True)

    def _check_await_deadlocks(self) -> list[Issue]:
        """Detect circular await chains and convert to Issues."""
        issues: list[Issue] = []
        try:
            cycles = self._event_loop.detect_await_cycles()
            for cycle in cycles:
                issues.append(
                    Issue(
                        kind=IssueKind.ASSERTION_ERROR,
                        message=f"[Async] Deadlock: await cycle " f"{' -> '.join (cycle )}",
                    )
                )
        except (RuntimeError, KeyError):
            logger.error("Internal AsyncExecutor error during coroutine interleaving or cycle detection", exc_info=True)
        return issues


def analyze_async(
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
    **config_kwargs: object,
) -> ExecutionResult:
    """Analyze an async function with coroutine scheduling.

    Args:
        func: Async function to analyze.
        symbolic_args: Mapping of parameter names to types.
        **config_kwargs: Additional ExecutionConfig options.

    Returns:
        ExecutionResult with async-specific issues.
    """
    config = ExecutionConfig(**config_kwargs)
    executor = AsyncSymbolicExecutor(config)
    return executor.execute_function(func, symbolic_args)
