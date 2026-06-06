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

"""Concurrency-aware symbolic executor for pysymex.

Extends SymbolicExecutor to detect threading/asyncio patterns during
opcode dispatch and feed operations into ConcurrencyAnalyzer for
race detection, deadlock analysis, and interleaving exploration.
"""

from __future__ import annotations

import dis
from pysymex.logger import get_logger
from collections.abc import Callable
from typing import cast

logger = get_logger(__name__)

from pysymex.analysis.domains.concurrency import (
    ConcurrencyAnalyzer,
    MemoryOrder,
)
from pysymex.analysis.detectors import DetectorRegistry
from pysymex.core.state.record import VMState
from pysymex.execution.config.settings import ExecutionConfig
from pysymex.execution.executors import SymbolicExecutor
from pysymex.execution.results.result import ExecutionResult
from pysymex.execution.executors.concurrent.finalization import finalize_concurrency_analysis
from pysymex.execution.executors.concurrent.tracking import (
    CALL_OPCODES,
    LOAD_OPCODES,
    STORE_OPCODES,
    SharedVariableTracker,
)


class ConcurrentSymbolicExecutor(SymbolicExecutor):
    """Symbolic executor with concurrency analysis integration.

    Extends the base executor to intercept opcodes related to threading
    and asyncio, feeding them into :class:`ConcurrencyAnalyzer` for
    automated race-condition detection, deadlock analysis, and
    interleaving exploration via DPOR.

    Concurrency events are intercepted transparently during normal
    opcode dispatch; no source-code changes are required.
    """

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
        **config_overrides: object,
    ) -> None:
        """Initialize the concurrent symbolic executor.

        Args:
            config: Optional ExecutionConfig to control engine behavior.
            detector_registry: Optional DetectorRegistry mapping issue detectors.
            **config_overrides: Optional overrides for ExecutionConfig attributes.
        """
        super().__init__(
            config=config,
            detector_registry=detector_registry,
            **config_overrides,
        )
        self._concurrency_analyzer = ConcurrencyAnalyzer(timeout_ms=self.config.solver_timeout_ms)
        self._shared_tracker = SharedVariableTracker()
        self._current_thread_id = "main"
        self._thread_counter = 0
        self._known_threads: dict[str, str] = {}
        self._known_locks: set[str] = set()

        self._concurrency_analyzer.create_thread("main", is_main=True)

    def execute_function(
        self,
        func: Callable[..., object],
        symbolic_args: dict[str, str] | None = None,
        initial_values: dict[str, object] | None = None,
    ) -> ExecutionResult:
        """Execute a function while tracing thread and asyncio concurrency events.

        Delegates to the standard SymbolicExecutor VM loop and runs DPOR analysis
        on completion to identify interleavings, deadlocks, and race conditions.

        Args:
            func: The target callable to execute.
            symbolic_args: Mapping of parameter names to symbolic type strings.
            initial_values: Concrete default parameter bindings to populate the entry frame.

        Returns:
            An ExecutionResult containing normal path exploration and concurrency issues.
        """
        result = super().execute_function(func, symbolic_args, initial_values)
        if self.config.enable_concurrency_analysis:
            self._finalize_concurrency_analysis()
        return result

    def _before_dispatch(
        self, instr: dis.Instruction, state: VMState, active_instructions: list[dis.Instruction]
    ) -> None:
        """Intercept concurrency-sensitive opcodes before normal VM dispatch.

        Args:
            instr: The current VM instruction to inspect.
            state: The current active symbolic VMState.
            active_instructions: The list of active instructions in the frame.
        """
        _ = active_instructions
        if self.config.enable_concurrency_analysis:
            self._intercept_concurrency(instr, state)

    def _intercept_concurrency(self, instr: dis.Instruction, state: VMState) -> None:
        """Intercept load, store, and call opcodes to record concurrency operations.

        Args:
            instr: The VM instruction to intercept.
            state: The current symbolic VMState.
        """
        try:
            opname = instr.opname
            arg_name = instr.argval
            line = self.session.pc_to_line.get(state.pc)

            if opname in STORE_OPCODES and arg_name:
                self._shared_tracker.record_access(
                    self._current_thread_id, str(arg_name), is_write=True
                )
                if self._shared_tracker.is_shared(str(arg_name)):
                    self._concurrency_analyzer.record_write(
                        self._current_thread_id,
                        str(arg_name),
                        order=MemoryOrder.SEQ_CST,
                        line_number=line,
                    )

            elif opname in LOAD_OPCODES and arg_name:
                self._shared_tracker.record_access(
                    self._current_thread_id, str(arg_name), is_write=False
                )
                if self._shared_tracker.is_shared(str(arg_name)):
                    self._concurrency_analyzer.record_read(
                        self._current_thread_id,
                        str(arg_name),
                        order=MemoryOrder.SEQ_CST,
                        line_number=line,
                    )

            elif opname in CALL_OPCODES:
                self._intercept_call(state, arg_name, line)

        except (AttributeError, KeyError, RuntimeError) as e:
            if self.config.verbose:
                logger.warning("Concurrency interception error: %s", e)

    def _intercept_call(
        self,
        _state: VMState,
        arg_name: object,
        line: int | None,
    ) -> None:
        """Intercept function calls for threading patterns.

        Monitors calls to start, join, acquire, or release threads and locks,
        passing them to the concurrency analyzer.

        Args:
            _state: Unused symbolic VMState.
            arg_name: The name or value of the callable being invoked.
            line: The source code line number where the call is made.
        """
        if arg_name is None:
            return
        name = str(arg_name).lower()

        if "thread" in name and ("create" in name or "thread(" in name):
            self._thread_counter += 1
            thread_id = f"thread_{self._thread_counter}"
            self._concurrency_analyzer.create_thread(thread_id)

        elif "start" in name:
            for tid in self._known_threads.values():
                try:
                    self._concurrency_analyzer.start_thread(
                        tid, self._current_thread_id, line_number=line
                    )
                except (RuntimeError, KeyError) as e:
                    if self.config.verbose:
                        logger.warning("Concurrency thread tracking error (start): %s", e)

        elif "join" in name:
            for tid in self._known_threads.values():
                try:
                    issue = self._concurrency_analyzer.join_thread(
                        tid, self._current_thread_id, line_number=line
                    )
                    if issue:
                        logger.warning("[Concurrency] %s", issue.format())
                except (RuntimeError, KeyError) as e:
                    if getattr(self, "config", None) and getattr(self.config, "verbose", False):
                        logger.warning("Concurrency thread tracking error (join): %s", e)

        elif "acquire" in name:
            lock_name = str(arg_name)
            issue = self._concurrency_analyzer.acquire_lock(
                self._current_thread_id, lock_name, line_number=line
            )
            if issue:
                logger.warning("[Concurrency] %s", issue.format())

        elif "release" in name:
            lock_name = str(arg_name)
            issue = self._concurrency_analyzer.release_lock(
                self._current_thread_id, lock_name, line_number=line
            )
            if issue:
                logger.warning("[Concurrency] %s", issue.format())

    def _finalize_concurrency_analysis(self) -> None:
        """Run final concurrency analysis, including DPOR interleaving search.

        Performs search space exploration over recorded threads and operations
        to detect data races, deadlocks, and atomicity violations. Findings are
        logged rather than converted into detector issues.
        """
        finalize_concurrency_analysis(self._concurrency_analyzer, self.config)


def analyze_concurrent(
    func: Callable[..., object],
    symbolic_args: dict[str, str] | None = None,
    **config_kwargs: object,
) -> ExecutionResult:
    """Analyze a function with concurrency analysis enabled.

    Convenience wrapper that sets enable_concurrency_analysis=True.

    Args:
        func: Function to analyze.
        symbolic_args: Mapping of parameter names to types.
        **config_kwargs: Additional ExecutionConfig options.

    Returns:
        ExecutionResult with both standard and concurrency issues.
    """
    config_kwargs.setdefault("enable_concurrency_analysis", True)
    config_ctor = cast("Callable[..., ExecutionConfig]", ExecutionConfig)
    config = config_ctor(**config_kwargs)
    executor = ConcurrentSymbolicExecutor(config)
    return executor.execute_function(func, symbolic_args)
