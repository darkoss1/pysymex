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

"""``AsyncSymbolicExecutor`` – async/await symbolic analysis.

Subclasses ``SymbolicExecutor`` and intercepts async opcodes
(``GET_AWAITABLE``, ``SEND``, ``YIELD_VALUE``, ``RETURN_GENERATOR``,
``GET_AITER``, ``GET_ANEXT``, ``BEFORE_ASYNC_WITH``, ``END_ASYNC_FOR``) to
model coroutine suspension points.

At each ``GET_AWAITABLE`` the current coroutine is suspended in a
``SymbolicEventLoop`` and, if more than one coroutine is ready, forked
states are queued into the worklist to explore interleaving orderings.
After execution completes, ``_check_await_deadlocks`` queries the event loop
for await-cycle graphs and logs detected cycles.

Limitations:
    The interleaving model is approximate. Only states forked at
    ``GET_AWAITABLE`` points are explored; asyncio task creation and
    cancellation are not tracked. ``ConcurrencyAnalyzer`` is initialised
    optionally but its output is not currently integrated into reported issues.
"""

from __future__ import annotations

import dis
from pysymex.logger import get_logger
from collections.abc import Callable
from typing import cast

logger = get_logger(__name__)

from pysymex.analysis.domains.concurrency import ConcurrencyAnalyzer
from pysymex.analysis.detectors import DetectorRegistry
from pysymex.core.state.record import VMState
from pysymex.execution.executors.async_support.loop import (
    CoroutineState as CoroutineState,
    SymbolicCoroutine as SymbolicCoroutine,
    SymbolicEventLoop,
)
from pysymex.execution.executors.core import SymbolicExecutor
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.results.result import ExecutionResult


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
        detector_registry: DetectorRegistry | None = None,
        **config_overrides: object,
    ) -> None:
        """Initialize the async executor and optional concurrency analyzer.

        Args:
            config: Execution configuration (interleaving cap via ``max_interleavings``).
            detector_registry: Detector registry forwarded to the base executor.
            **config_overrides: Overrides applied to ``ExecutionConfig``.
        """
        super().__init__(
            config=config,
            detector_registry=detector_registry,
            **config_overrides,
        )
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
                logger.error(
                    "Internal AsyncExecutor error during coroutine interleaving or cycle detection",
                    exc_info=True,
                )

    def execute_function(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
        initial_values: dict[str, object] | None = None,
    ) -> ExecutionResult:
        """Execute a (possibly async) function with async-aware symbolic analysis.

        Delegates to ``SymbolicExecutor.execute_function`` which drives the
        worklist loop. After execution completes, calls
        ``_check_await_deadlocks`` to detect circular await chains in the
        symbolic event loop; detected cycles are logged at WARNING level.

        Returns:
            The ``ExecutionResult`` produced by the base executor.
        """
        result = super().execute_function(func, symbolic_args, initial_values)
        self._check_await_deadlocks()
        return result

    def _on_path_complete(self, state: VMState) -> None:
        """Complete the active coroutine when its symbolic path terminates."""
        _ = state
        if self._current_coro_id:
            self._event_loop.complete_coroutine(self._current_coro_id)

    def _before_dispatch(
        self, instr: dis.Instruction, state: VMState, active_instructions: list[dis.Instruction]
    ) -> None:
        """Intercept async opcodes after the core feasibility checks."""
        _ = active_instructions
        self._current_coro_id = state.current_coro_id
        if instr.opname in _ASYNC_OPCODES:
            self._intercept_async(instr, state)

    def _intercept_async(self, instr: dis.Instruction, state: VMState) -> None:
        """Dispatch symbolic coroutine-scheduling side effects for async opcodes.

        Handles:
        - ``GET_AWAITABLE``: suspends the current coroutine in the event loop
          (if ``_current_coro_id`` is set) and calls ``_explore_interleavings``
          to fork states for any ready coroutines.
        - ``YIELD_VALUE``: suspends the current coroutine without exploring
          interleavings.
        - ``SEND``: resumes the current coroutine in the event loop.
        - ``RETURN_GENERATOR``: creates a new ``SymbolicCoroutine`` in the
          event loop, assigns its ID to ``_current_coro_id`` and
          ``state.current_coro_id``.

        Other opcode names (``GET_AITER``, ``GET_ANEXT``, ``BEFORE_ASYNC_WITH``,
        ``END_ASYNC_FOR``) are accepted by the ``_ASYNC_OPCODES`` set but not
        explicitly handled here; they fall through without side effects.

        ``AttributeError``, ``KeyError``, and ``RuntimeError`` are caught and
        logged at ERROR level rather than propagated.
        """
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
                    name=f"gen_{state.pc}",
                    initial_state=state.fork(),
                )
                self._current_coro_id = coro.coro_id
                state.current_coro_id = coro.coro_id

        except (AttributeError, KeyError, RuntimeError):
            logger.error(
                "Internal AsyncExecutor error during coroutine interleaving or cycle detection",
                exc_info=True,
            )

    def _explore_interleavings(self, state: VMState) -> None:
        """At an await point, fork states for possible schedulings."""
        try:
            steps = self._event_loop.step()
            if len(steps) <= 1:
                return

            for _coro_id, coro_state in steps:
                forked = state.fork()
                forked = forked.set_pc(coro_state.pc)
                if self.session.worklist:
                    self.session.worklist.add_state(forked)
                self.session.paths_explored += 1
        except (RuntimeError, KeyError):
            logger.error(
                "Internal AsyncExecutor error during coroutine interleaving or cycle detection",
                exc_info=True,
            )

    def _check_await_deadlocks(self) -> list[list[str]]:
        """Detect circular await chains and log deadlock cycles."""
        try:
            cycles = self._event_loop.detect_await_cycles()
            for cycle in cycles:
                logger.warning("[Async] Deadlock cycle detected: %s", " -> ".join(cycle))
            return cycles
        except (RuntimeError, KeyError):
            logger.error(
                "Internal AsyncExecutor error during coroutine interleaving or cycle detection",
                exc_info=True,
            )
        return []


def analyze(
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
    config_ctor = cast("Callable[..., ExecutionConfig]", ExecutionConfig)
    config = config_ctor(**config_kwargs)
    executor = AsyncSymbolicExecutor(config)
    return executor.execute_function(func, symbolic_args)
