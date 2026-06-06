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

"""Z3-backed concurrency analyser coordinating thread, lock, and memory-operation modelling."""

from __future__ import annotations

from collections.abc import Mapping

import z3

from pysymex.analysis.domains.concurrency.deadlocks import detect_deadlocks
from pysymex.analysis.domains.concurrency.operations import (
    acquire_lock,
    join_thread,
    record_memory_operation,
    release_lock,
    start_thread,
)
from pysymex.analysis.domains.concurrency.races import detect_data_races
from pysymex.analysis.domains.concurrency.schedules import (
    RaceCheckResult,
    ScheduleSearchResult,
    check_race_condition_z3,
    check_race_condition_z3_result,
    detect_atomicity_violations,
    detect_await_cycles,
    find_problematic_schedule,
    find_problematic_schedule_result,
)
from pysymex.analysis.domains.concurrency.enums import MemoryOrder, OperationKind, ThreadState
from pysymex.analysis.domains.concurrency.happens_before import HappensBeforeGraph
from pysymex.analysis.domains.concurrency.models import ConcurrencyIssue, MemoryOperation, Thread
from pysymex.core.solver.engine.incremental import IncrementalSolver


class ConcurrencyAnalyzer:
    """Stateful concurrency analyser backed by a Z3 ``IncrementalSolver``.

    Records threads, shared-variable accesses, lock operations, and
    happens-before edges, then delegates detection of races, deadlocks,
    atomicity violations, and problematic schedules to specialised
    analysis functions.
    """

    def __init__(self, timeout_ms: int = 10000) -> None:
        """Initialize a ConcurrencyAnalyzer instance.

        Args:
            timeout_ms (int): Query timeout in milliseconds for the underlying Z3 solver. Defaults to 10000.
        """
        self.timeout_ms = timeout_ms
        self.solver = IncrementalSolver(timeout_ms=timeout_ms)
        self.threads: dict[str, Thread] = {}
        self.shared_variables: set[str] = set()
        self.locks: dict[str, str | None] = {}
        self.lock_acquisitions: dict[str, list[str]] = {}
        self.hb_graph = HappensBeforeGraph()
        self.thread_op_ids: dict[str, list[int]] = {}
        self.issues: list[ConcurrencyIssue] = []
        self.has_lock_activity = False

    def reset(self) -> None:
        """Clear all analyser state (solver, threads, operations, issues)."""
        self.solver.reset()
        self.threads.clear()
        self.shared_variables.clear()
        self.locks.clear()
        self.lock_acquisitions.clear()
        self.hb_graph = HappensBeforeGraph()
        self.thread_op_ids.clear()
        self.issues.clear()
        self.has_lock_activity = False

    def create_thread(self, thread_id: str, is_main: bool = False) -> Thread:
        """Create and register a new thread.  If *is_main*, it starts in ``RUNNING`` state."""
        thread = Thread(thread_id=thread_id)
        self.threads[thread_id] = thread
        self.thread_op_ids[thread_id] = []
        if is_main:
            thread.state = ThreadState.RUNNING
        return thread

    def start_thread(
        self, thread_id: str, parent_thread: str, line_number: int | None = None
    ) -> ConcurrencyIssue | None:
        """Record the launching/starting of a thread from its parent thread.

        Args:
            thread_id (str): The ID of the thread being started.
            parent_thread (str): The ID of the parent thread that launched it.
            line_number (int | None): Optional source line number.

        Returns:
            ConcurrencyIssue | None: A ConcurrencyIssue if starting failed (e.g. already started), else None.
        """
        return start_thread(self, thread_id, parent_thread, line_number)

    def join_thread(
        self, thread_id: str, joining_thread: str, line_number: int | None = None
    ) -> ConcurrencyIssue | None:
        """Record a thread-join operation, waiting for the child thread to terminate.

        Args:
            thread_id (str): The ID of the thread being joined.
            joining_thread (str): The ID of the thread executing the join.
            line_number (int | None): Optional source line number.

        Returns:
            ConcurrencyIssue | None: A ConcurrencyIssue if joining failed (e.g. not started), else None.
        """
        return join_thread(self, thread_id, joining_thread, line_number)

    def record_read(
        self,
        thread_id: str,
        variable: str,
        order: MemoryOrder = MemoryOrder.SEQ_CST,
        line_number: int | None = None,
    ) -> int:
        """Record a memory read operation on a shared variable.

        Args:
            thread_id (str): The ID of the thread executing the read.
            variable (str): The shared variable name.
            order (MemoryOrder): Consistency memory ordering. Defaults to MemoryOrder.SEQ_CST.
            line_number (int | None): Optional source line number.

        Returns:
            int: The unique ID assigned to the memory operation.
        """
        return record_memory_operation(
            self, thread_id, variable, OperationKind.READ, None, order, line_number
        )

    def record_write(
        self,
        thread_id: str,
        variable: str,
        value: object = None,
        order: MemoryOrder = MemoryOrder.SEQ_CST,
        line_number: int | None = None,
    ) -> int:
        """Record a memory write operation on a shared variable.

        Args:
            thread_id (str): The ID of the thread executing the write.
            variable (str): The shared variable name.
            value (object): The value being written. Defaults to None.
            order (MemoryOrder): Consistency memory ordering. Defaults to MemoryOrder.SEQ_CST.
            line_number (int | None): Optional source line number.

        Returns:
            int: The unique ID assigned to the memory operation.
        """
        return record_memory_operation(
            self, thread_id, variable, OperationKind.WRITE, value, order, line_number
        )

    def record_atomic_rmw(
        self,
        thread_id: str,
        variable: str,
        value: object = None,
        order: MemoryOrder = MemoryOrder.SEQ_CST,
        line_number: int | None = None,
    ) -> int:
        """Record an atomic read-modify-write operation on a shared variable.

        Args:
            thread_id (str): The ID of the thread executing the operation.
            variable (str): The shared variable name.
            value (object): The value used in the update. Defaults to None.
            order (MemoryOrder): Consistency memory ordering. Defaults to MemoryOrder.SEQ_CST.
            line_number (int | None): Optional source line number.

        Returns:
            int: The unique ID assigned to the memory operation.
        """
        return record_memory_operation(
            self, thread_id, variable, OperationKind.READ_MODIFY_WRITE, value, order, line_number
        )

    def acquire_lock(
        self, thread_id: str, lock_name: str, line_number: int | None = None
    ) -> ConcurrencyIssue | None:
        """Record a lock acquisition by a thread.

        Args:
            thread_id (str): The ID of the thread acquiring the lock.
            lock_name (str): The lock identifier.
            line_number (int | None): Optional source line number.

        Returns:
            ConcurrencyIssue | None: A ConcurrencyIssue if lock is already held by this thread, else None.
        """
        return acquire_lock(self, thread_id, lock_name, line_number)

    def release_lock(
        self, thread_id: str, lock_name: str, line_number: int | None = None
    ) -> ConcurrencyIssue | None:
        """Record a lock release by a thread.

        Args:
            thread_id (str): The ID of the thread releasing the lock.
            lock_name (str): The lock identifier.
            line_number (int | None): Optional source line number.

        Returns:
            ConcurrencyIssue | None: A ConcurrencyIssue if the lock is not currently held, else None.
        """
        return release_lock(self, thread_id, lock_name, line_number)

    def detect_data_races(self) -> list[ConcurrencyIssue]:
        """Analyze recorded memory accesses for concurrent, conflicting data races.

        Returns:
            list[ConcurrencyIssue]: List of detected data races.
        """
        return detect_data_races(self)

    def detect_deadlocks(self) -> list[ConcurrencyIssue]:
        """Analyze recorded lock operations for potential lock-ordering deadlock cycles.

        Returns:
            list[ConcurrencyIssue]: List of detected deadlock cycles.
        """
        return detect_deadlocks(self)

    def detect_await_cycles(self, await_graph: Mapping[str, str | None]) -> list[ConcurrencyIssue]:
        """Analyze coroutines for cyclic dependencies (deadlocks in await).

        Args:
            await_graph (Mapping[str, str | None]): Map detailing coroutine await targets.

        Returns:
            list[ConcurrencyIssue]: List of detected await cycle deadlocks.
        """
        return detect_await_cycles(self, await_graph)

    def detect_atomicity_violations(
        self, atomic_regions: list[tuple[str, list[MemoryOperation]]]
    ) -> list[ConcurrencyIssue]:
        """Analyze designated atomic regions for serializability violations.

        Args:
            atomic_regions (list[tuple[str, list[MemoryOperation]]]): Declared atomic transactions.

        Returns:
            list[ConcurrencyIssue]: List of detected atomicity violations.
        """
        return detect_atomicity_violations(self, atomic_regions)

    def check_race_condition_z3(
        self,
        variable: str,
        _expected_final_value: object,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> tuple[bool, ConcurrencyIssue | None]:
        """Verify data race feasibility using Z3 solver constraints.

        Args:
            variable (str): The shared variable to check.
            _expected_final_value (object): The expected value under sequential execution.
            path_constraints (list[z3.BoolRef] | None): Optional path constraints.

        Returns:
            tuple[bool, ConcurrencyIssue | None]: A tuple of (verified, issue_details). verified is True if no race condition is feasible, or False if a race condition is feasible or the solver check is inconclusive.
        """
        return check_race_condition_z3(self, variable, _expected_final_value, path_constraints)

    def check_race_condition_z3_result(
        self,
        variable: str,
        _expected_final_value: object,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> RaceCheckResult:
        """Verify data-race feasibility while preserving solver UNKNOWN status."""
        return check_race_condition_z3_result(
            self, variable, _expected_final_value, path_constraints
        )

    def find_problematic_schedule(
        self,
        assertion: z3.BoolRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> list[tuple[str, str]] | None:
        """Search for an execution schedule that violates a safety assertion using Z3.

        Args:
            assertion (z3.BoolRef): The Z3 safety assertion to falsify.
            path_constraints (list[z3.BoolRef] | None): Optional path constraints.

        Returns:
            list[tuple[str, str]] | None: The list of schedule transitions if found, or None.
        """
        return find_problematic_schedule(self, assertion, path_constraints)

    def find_problematic_schedule_result(
        self,
        assertion: z3.BoolRef,
        path_constraints: list[z3.BoolRef] | None = None,
    ) -> ScheduleSearchResult:
        """Search for a violating schedule and preserve solver UNKNOWN status."""
        return find_problematic_schedule_result(self, assertion, path_constraints)

    def get_thread(self, thread_id: str) -> Thread | None:
        """Return the ``Thread`` for *thread_id*, or ``None``."""
        return self.threads.get(thread_id)

    def get_thread_operations(self) -> dict[str, list[int]]:
        """Return a copy of recorded operation IDs keyed by thread ID."""
        return {thread_id: list(op_ids) for thread_id, op_ids in self.thread_op_ids.items()}

    def get_all_issues(self) -> list[ConcurrencyIssue]:
        """Return all detected issues, including on-demand race and deadlock detection."""
        all_issues = list(self.issues)
        all_issues.extend(self.detect_data_races())
        all_issues.extend(self.detect_deadlocks())
        return all_issues

    def get_summary(self) -> dict[str, object]:
        """Return a summary dict with thread, variable, lock, and operation counts."""
        return {
            "threads": len(self.threads),
            "shared_variables": list(self.shared_variables),
            "locks": list(self.locks.keys()),
            "total_operations": len(self.hb_graph.operations),
            "happens_before_edges": len(self.hb_graph.edges_set),
        }


__all__ = ["ConcurrencyAnalyzer"]
