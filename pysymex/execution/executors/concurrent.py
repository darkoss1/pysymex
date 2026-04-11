# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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
import logging
from collections.abc import Callable
from typing import cast

logger = logging.getLogger(__name__)

from pysymex.analysis.concurrency import (
    ConcurrencyAnalyzer,
    ConcurrencyIssue,
    ConcurrencyIssueKind,
    MemoryOrder,
)
from pysymex.analysis.detectors import DetectorRegistry, Issue, IssueKind
from pysymex.core.state import VMState
from pysymex.execution.executors import (
    ExecutionConfig,
    ExecutionResult,
    SymbolicExecutor,
)


class SharedVariableTracker:
    """Tracks variables accessed from multiple threads.

    A variable is considered "shared" once it has been accessed by
    two or more distinct thread IDs.
    """

    def __init__(self) -> None:
        self._accesses: dict[str, set[str]] = {}
        self._writes: dict[str, set[str]] = {}

    def record_access(
        self,
        thread_id: str,
        variable_name: str,
        is_write: bool = False,
    ) -> None:
        """Record a variable access by a thread."""
        self._accesses.setdefault(variable_name, set()).add(thread_id)
        if is_write:
            self._writes.setdefault(variable_name, set()).add(thread_id)

    def get_shared_variables(self) -> set[str]:
        """Return variables accessed by 2+ threads."""
        return {var for var, threads in self._accesses.items() if len(threads) >= 2}

    def is_shared(self, variable_name: str) -> bool:
        """Check if a variable has been accessed by multiple threads."""
        return len(self._accesses.get(variable_name, set())) >= 2

    def reset(self) -> None:
        """Clear all tracked accesses."""
        self._accesses.clear()
        self._writes.clear()


_STORE_OPCODES = frozenset(
    {
        "STORE_FAST",
        "STORE_NAME",
        "STORE_GLOBAL",
        "STORE_DEREF",
        "STORE_ATTR",
    }
)


_LOAD_OPCODES = frozenset(
    {
        "LOAD_FAST",
        "LOAD_NAME",
        "LOAD_GLOBAL",
        "LOAD_DEREF",
        "LOAD_ATTR",
    }
)


_CALL_OPCODES = frozenset(
    {
        "CALL",
        "CALL_FUNCTION",
        "CALL_METHOD",
        "CALL_FUNCTION_KW",
        "CALL_FUNCTION_EX",
    }
)


class ConcurrentSymbolicExecutor(SymbolicExecutor):
    """Symbolic executor with concurrency analysis integration.

    Extends the base executor to intercept opcodes related to threading
    and asyncio, feeding them into :class:`ConcurrencyAnalyzer` for
    automated race-condition detection, deadlock analysis, and
    interleaving exploration via DPOR.

    Concurrency events are intercepted transparently during normal
    opcode dispatch â€” no source-code changes are required.
    """

    def __init__(
        self,
        config: ExecutionConfig | None = None,
        detector_registry: DetectorRegistry | None = None,
        **config_overrides: object,
    ) -> None:
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
        """Execute with concurrency analysis."""
        result = super().execute_function(func, symbolic_args, initial_values)

        if self.config.enable_concurrency_analysis:
            concurrency_issues = self._finalize_concurrency_analysis()
            result.issues.extend(concurrency_issues)

        return result

    def _execute_step(self, state: VMState) -> None:
        """Execute a step with concurrency interception."""
        from pysymex.execution.executors import BRANCH_OPCODES

        instr, active_instructions = self._fetch_instruction(state)
        if instr is None:
            self._paths_completed += 1
            self._last_globals = state.global_vars
            self._last_locals = state.local_vars
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

        is_jump_or_branch = instr.opname in BRANCH_OPCODES or "JUMP" in instr.opname
        if is_jump_or_branch:
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

        if self.config.enable_concurrency_analysis:
            self._intercept_concurrency(instr, state)

        self._run_detectors(state, instr, active_instructions)

        try:
            result = self.dispatcher.dispatch(instr, state)
            self._process_execution_result(result, state, active_instructions)
        except (RuntimeError, TypeError, ValueError, KeyError, AttributeError, IndexError) as e:
            if self.config.verbose:
                logger.warning("Execution error at PC %d: %s", state.pc, e)
            self._paths_pruned += 1
            return

    def _intercept_concurrency(self, instr: dis.Instruction, state: VMState) -> None:
        """Intercept opcodes for concurrency analysis."""
        try:
            opname = instr.opname
            arg_name = instr.argval
            line = self._pc_to_line.get(state.pc)

            if opname in _STORE_OPCODES and arg_name:
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

            elif opname in _LOAD_OPCODES and arg_name:
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

            elif opname in _CALL_OPCODES:
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
        """Intercept function calls for threading patterns."""
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
                        self._issues.append(self._convert_concurrency_issue(issue))
                except (RuntimeError, KeyError) as e:
                    if getattr(self, "config", None) and getattr(self.config, "verbose", False):
                        logger.warning("Concurrency thread tracking error (join): %s", e)

        elif "acquire" in name:
            lock_name = str(arg_name)
            issue = self._concurrency_analyzer.acquire_lock(
                self._current_thread_id, lock_name, line_number=line
            )
            if issue:
                self._issues.append(self._convert_concurrency_issue(issue))

        elif "release" in name:
            lock_name = str(arg_name)
            issue = self._concurrency_analyzer.release_lock(
                self._current_thread_id, lock_name, line_number=line
            )
            if issue:
                self._issues.append(self._convert_concurrency_issue(issue))

    def _finalize_concurrency_analysis(self) -> list[Issue]:
        """Run final concurrency analysis and convert issues.

        Includes DPOR interleaving exploration to find additional data
        races and atomicity violations beyond the single-execution analysis.
        """
        issues: list[Issue] = []
        try:
            all_concurrency_issues = self._concurrency_analyzer.get_all_issues()
            for ci in all_concurrency_issues:
                issues.append(self._convert_concurrency_issue(ci))
        except (RuntimeError, KeyError, AttributeError) as e:
            if getattr(self, "config", None) and getattr(self.config, "verbose", False):
                logger.warning("Concurrency finalization error: %s", e)

        try:
            from pysymex.analysis.concurrency.interleaving import DPORExplorer

            hb_graph = self._concurrency_analyzer.hb_graph
            thread_ops = self._concurrency_analyzer.get_thread_operations()
            if hb_graph and thread_ops and len(thread_ops) > 1:
                explorer = DPORExplorer(hb_graph, thread_ops, max_interleavings=100)
                schedules = explorer.explore()
                race_candidates = explorer.get_race_candidates()
                for op1_id, op2_id in race_candidates:
                    op1 = hb_graph.get_operation(op1_id)
                    op2 = hb_graph.get_operation(op2_id)
                    if op1 and op2:
                        line = getattr(op1, "line_number", None) or getattr(
                            op2, "line_number", None
                        )
                        issues.append(
                            Issue(
                                kind=IssueKind.TYPE_ERROR,
                                message=(
                                    f"[Concurrency] Data race: {op1.thread_id} and "
                                    f"{op2.thread_id} access '{op1.address}' concurrently "
                                    f"(DPOR found {len(schedules)} interleavings)"
                                ),
                                line_number=line,
                            )
                        )
                if self.config.verbose and schedules:
                    logger.debug(
                        "  DPOR explored %d interleavings, found %d race candidate(s)",
                        len(schedules),
                        len(race_candidates),
                    )
        except (ImportError, RuntimeError, AttributeError) as e:
            if getattr(self, "config", None) and getattr(self.config, "verbose", False):
                logger.warning("DPOR exploration error: %s", e)

        return issues

    @staticmethod
    def _convert_concurrency_issue(ci: ConcurrencyIssue) -> Issue:
        """Convert a ConcurrencyIssue to an executor Issue."""
        kind_map = {
            ConcurrencyIssueKind.DATA_RACE: IssueKind.TYPE_ERROR,
            ConcurrencyIssueKind.RACE_CONDITION: IssueKind.TYPE_ERROR,
            ConcurrencyIssueKind.DEADLOCK: IssueKind.ASSERTION_ERROR,
            ConcurrencyIssueKind.POTENTIAL_DEADLOCK: IssueKind.ASSERTION_ERROR,
            ConcurrencyIssueKind.ATOMICITY_VIOLATION: IssueKind.TYPE_ERROR,
            ConcurrencyIssueKind.LOCK_NOT_HELD: IssueKind.ASSERTION_ERROR,
        }
        issue_kind = kind_map.get(ci.kind, IssueKind.TYPE_ERROR)
        return Issue(
            kind=issue_kind,
            message=f"[Concurrency] {ci.format()}",
            line_number=ci.line_number,
        )


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


