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

"""Await-cycle detection, atomicity-violation analysis, and Z3-based schedule search."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum

import z3

from pysymex.analysis.domains.concurrency.protocols import ConcurrencyAnalyzerState
from pysymex.analysis.domains.concurrency.enums import ConcurrencyIssueKind
from pysymex.analysis.domains.concurrency.models import ConcurrencyIssue, MemoryOperation
from pysymex.logger import get_logger

logger = get_logger(__name__)
_SCHEDULE_MODEL_ERRORS = (
    z3.Z3Exception,
    AttributeError,
    OSError,
    RuntimeError,
    TypeError,
    ValueError,
)


class ScheduleSearchStatus(Enum):
    """Outcome of searching for an assertion-violating schedule."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    INCONCLUSIVE = "inconclusive"


class RaceCheckStatus(Enum):
    """Outcome of checking whether write ordering can expose a race."""

    FOUND = "found"
    NOT_FOUND = "not_found"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True, slots=True)
class ScheduleSearchResult:
    """Structured result for schedule search without collapsing solver UNKNOWN."""

    status: ScheduleSearchStatus
    schedule: list[tuple[str, str]] | None = None
    reason: str | None = None

    @property
    def found(self) -> bool:
        """Return true only when a violating schedule was found."""
        return self.status == ScheduleSearchStatus.FOUND


@dataclass(frozen=True, slots=True)
class RaceCheckResult:
    """Structured result for race-order checks without collapsing solver UNKNOWN."""

    status: RaceCheckStatus
    issue: ConcurrencyIssue | None = None
    reason: str | None = None

    @property
    def is_safe(self) -> bool:
        """Return true only when no reorderable race was found."""
        return self.status == RaceCheckStatus.NOT_FOUND


def detect_await_cycles(
    _analyzer: ConcurrencyAnalyzerState,
    await_graph: Mapping[str, str | None],
) -> list[ConcurrencyIssue]:
    """Detect circular await chains (coroutine deadlocks) via DFS on an await graph."""
    issues: list[ConcurrencyIssue] = []
    visited: set[str] = set()
    in_path: set[str] = set()

    def dfs(node: str, path: list[str]) -> list[str] | None:
        if node in in_path:
            cycle_start = path.index(node)
            return [*path[cycle_start:], node]
        if node in visited:
            return None
        visited.add(node)
        in_path.add(node)
        path.append(node)
        target = await_graph.get(node)
        if target is not None:
            result = dfs(target, path)
            if result:
                return result
        path.pop()
        in_path.discard(node)
        return None

    for coro_id in await_graph:
        if coro_id not in visited:
            cycle = dfs(coro_id, [])
            if cycle:
                issues.append(
                    ConcurrencyIssue(
                        kind=ConcurrencyIssueKind.DEADLOCK,
                        message=f"Async deadlock: await cycle {' -> '.join(cycle)}",
                        threads_involved=cycle[:-1],
                        severity="error",
                    )
                )
    return issues


def detect_atomicity_violations(
    analyzer: ConcurrencyAnalyzerState,
    atomic_regions: list[tuple[str, list[MemoryOperation]]],
) -> list[ConcurrencyIssue]:
    """Detect atomicity violations."""
    issues: list[ConcurrencyIssue] = []
    for thread_id, region_ops in atomic_regions:
        if len(region_ops) < 2:
            continue
        region_vars = {op.address for op in region_ops}
        for other_thread_id, other_thread in analyzer.threads.items():
            if other_thread_id == thread_id:
                continue
            for other_op in other_thread.operations:
                if other_op.address in region_vars:
                    issues.append(
                        ConcurrencyIssue(
                            kind=ConcurrencyIssueKind.ATOMICITY_VIOLATION,
                            message=f"Atomicity violation: thread '{other_thread_id}' can access "
                            f"'{other_op.address}' during atomic region",
                            threads_involved=[thread_id, other_thread_id],
                            shared_resource=other_op.address,
                        )
                    )
                    break
    return issues


def check_race_condition_z3(
    analyzer: ConcurrencyAnalyzerState,
    variable: str,
    _expected_final_value: object,
    path_constraints: list[z3.BoolRef] | None = None,
) -> tuple[bool, ConcurrencyIssue | None]:
    """Use Z3 to check whether write order can change for a variable."""
    result = check_race_condition_z3_result(
        analyzer,
        variable,
        _expected_final_value,
        path_constraints,
    )
    return (result.is_safe, result.issue)


def check_race_condition_z3_result(
    analyzer: ConcurrencyAnalyzerState,
    variable: str,
    _expected_final_value: object,
    path_constraints: list[z3.BoolRef] | None = None,
) -> RaceCheckResult:
    """Use Z3 to check whether write order can change while preserving UNKNOWN."""
    constraints = list(path_constraints or [])
    ops = [
        (op_id, op) for op_id, op in analyzer.hb_graph.operations.items() if op.address == variable
    ]
    if not ops:
        return RaceCheckResult(RaceCheckStatus.NOT_FOUND)
    order_vars = {op_id: z3.Int(f"order_{op_id}") for op_id, _op in ops}
    for from_op, to_op in analyzer.hb_graph.edges_set:
        if from_op in order_vars and to_op in order_vars:
            constraints.append(order_vars[from_op] < order_vars[to_op])
    if len(order_vars) > 1:
        constraints.append(z3.Distinct(list(order_vars.values())))
    writes = [(op_id, op) for op_id, op in ops if op.is_write()]
    if len(writes) > 1:
        w1_id, w1 = writes[0]
        w2_id, w2 = writes[1]
        reorder_result = analyzer.solver.check_sat_result(
            [*constraints, order_vars[w2_id] < order_vars[w1_id]]
        )
        if reorder_result.is_sat:
            return RaceCheckResult(
                RaceCheckStatus.FOUND,
                issue=ConcurrencyIssue(
                    kind=ConcurrencyIssueKind.RACE_CONDITION,
                    message=f"Race condition: writes to '{variable}' can occur in different orders",
                    threads_involved=[w1.thread_id, w2.thread_id],
                    shared_resource=variable,
                ),
            )
        if reorder_result.is_unknown:
            reason = "Race condition check inconclusive: solver returned unknown"
            return RaceCheckResult(
                RaceCheckStatus.INCONCLUSIVE,
                issue=ConcurrencyIssue(
                    kind=ConcurrencyIssueKind.RACE_CONDITION,
                    message="Race condition check inconclusive: solver returned unknown for "
                    f"writes to '{variable}'",
                    threads_involved=[w1.thread_id, w2.thread_id],
                    shared_resource=variable,
                    constraints=list(constraints),
                    severity="warning",
                ),
                reason=reason,
            )
    return RaceCheckResult(RaceCheckStatus.NOT_FOUND)


def find_problematic_schedule(
    analyzer: ConcurrencyAnalyzerState,
    assertion: z3.BoolRef,
    path_constraints: list[z3.BoolRef] | None = None,
) -> list[tuple[str, str]] | None:
    """Find a schedule that violates an assertion."""
    return find_problematic_schedule_result(analyzer, assertion, path_constraints).schedule


def find_problematic_schedule_result(
    analyzer: ConcurrencyAnalyzerState,
    assertion: z3.BoolRef,
    path_constraints: list[z3.BoolRef] | None = None,
) -> ScheduleSearchResult:
    """Find a violating schedule while preserving solver inconclusiveness."""
    constraints = list(path_constraints or [])
    all_ops = list(analyzer.hb_graph.operations.items())
    order_vars = {op_id: z3.Int(f"order_{op_id}") for op_id, _ in all_ops}
    for from_op, to_op in analyzer.hb_graph.edges_set:
        if from_op in order_vars and to_op in order_vars:
            constraints.append(order_vars[from_op] < order_vars[to_op])
    if len(order_vars) > 1:
        constraints.append(z3.Distinct(*order_vars.values()))

    query_constraints = [*constraints, z3.Not(assertion)]
    result = analyzer.solver.check_sat_result(query_constraints)
    if result.is_unknown:
        return ScheduleSearchResult(
            ScheduleSearchStatus.INCONCLUSIVE,
            reason="Problematic schedule search inconclusive: solver returned unknown",
        )
    if result.is_unsat:
        return ScheduleSearchResult(ScheduleSearchStatus.NOT_FOUND)
    model = result.model
    if model is None:
        model = analyzer.solver.get_model(query_constraints)
    if model is None:
        return ScheduleSearchResult(
            ScheduleSearchStatus.INCONCLUSIVE,
            reason="Problematic schedule search was satisfiable but produced no model",
        )
    schedule: list[tuple[int, str, str]] = []
    for op_id, op in all_ops:
        try:
            order = model.eval(order_vars[op_id], model_completion=True).as_long()
        except _SCHEDULE_MODEL_ERRORS:
            logger.debug("Problematic schedule model evaluation failed", exc_info=True)
            return ScheduleSearchResult(
                ScheduleSearchStatus.INCONCLUSIVE,
                reason="Problematic schedule search was satisfiable but model evaluation failed",
            )
        schedule.append((order, op.thread_id, op.operation.name))
    schedule.sort(key=lambda x: x[0])
    return ScheduleSearchResult(
        ScheduleSearchStatus.FOUND,
        schedule=[(thread_id, operation) for _, thread_id, operation in schedule],
    )


__all__ = [
    "RaceCheckResult",
    "RaceCheckStatus",
    "ScheduleSearchResult",
    "ScheduleSearchStatus",
    "check_race_condition_z3",
    "check_race_condition_z3_result",
    "detect_atomicity_violations",
    "detect_await_cycles",
    "find_problematic_schedule",
    "find_problematic_schedule_result",
]
