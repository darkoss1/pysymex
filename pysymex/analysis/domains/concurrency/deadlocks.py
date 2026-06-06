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

"""Deadlock detection and Z3 verification helpers."""

from __future__ import annotations

from enum import Enum
from itertools import pairwise

import z3

from pysymex.analysis.domains.concurrency.enums import ConcurrencyIssueKind, OperationKind
from pysymex.analysis.domains.concurrency.models import ConcurrencyIssue
from pysymex.analysis.domains.concurrency.protocols import ConcurrencyAnalyzerState
from pysymex.logger import get_logger

logger = get_logger(__name__)


class DeadlockVerificationStatus(Enum):
    """Structured outcome of Z3-backed lock-cycle verification."""

    VERIFIED = "verified"
    POTENTIAL = "potential"
    INCONCLUSIVE = "inconclusive"


def _find_cycle(lock_order_graph: dict[str, set[str]], start: str) -> list[str] | None:
    """Find a cycle in the lock-ordering graph using Depth First Search (DFS).

    Args:
        lock_order_graph (dict[str, set[str]]): The graph mapping locks to subsequent locks.
        start (str): The starting node.

    Returns:
        list[str] | None: The cycle path as a list of lock names, or None.
    """
    visited: set[str] = set()
    path: list[str] = []

    def dfs(node: str) -> list[str] | None:
        if node in path:
            cycle_start = path.index(node)
            return [*path[cycle_start:], node]
        if node in visited:
            return None
        visited.add(node)
        path.append(node)
        for neighbor in lock_order_graph.get(node, ()):
            result = dfs(neighbor)
            if result:
                return result
        path.pop()
        return None

    return dfs(start)


def _build_lock_order(
    analyzer: ConcurrencyAnalyzerState,
) -> tuple[dict[str, set[str]], dict[tuple[str, str], list[str]]]:
    """Build the lock acquisition order graph from recorded thread operations.

    Args:
        analyzer (ConcurrencyAnalyzerState): The concurrency analyzer state.

    Returns:
        tuple[dict[str, set[str]], dict[tuple[str, str], list[str]]]: A tuple containing the lock order
            graph and thread-pair maps.
    """
    lock_order_graph: dict[str, set[str]] = {}
    lock_pair_threads: dict[tuple[str, str], list[str]] = {}
    for thread_id, thread in analyzer.threads.items():
        held_locks: list[str] = []
        for op in thread.operations:
            if op.operation == OperationKind.LOCK_ACQUIRE:
                for held in held_locks:
                    lock_order_graph.setdefault(held, set()).add(op.address)
                    lock_pair_threads.setdefault((held, op.address), []).append(thread_id)
                held_locks.append(op.address)
            elif op.operation == OperationKind.LOCK_RELEASE and op.address in held_locks:
                held_locks.remove(op.address)
    return lock_order_graph, lock_pair_threads


def detect_deadlocks(analyzer: ConcurrencyAnalyzerState) -> list[ConcurrencyIssue]:
    """Detect potential deadlocks using lock order analysis plus Z3 verification."""
    if not analyzer.has_lock_activity:
        return []

    issues: list[ConcurrencyIssue] = []
    lock_order_graph, lock_pair_threads = _build_lock_order(analyzer)
    checked_cycles: set[tuple[str, ...]] = set()
    for lock in lock_order_graph:
        cycle = _find_cycle(lock_order_graph, lock)
        if cycle is None:
            continue
        cycle_key = tuple(sorted(cycle))
        if cycle_key in checked_cycles:
            continue
        checked_cycles.add(cycle_key)

        verification = verify_deadlock_z3_result(analyzer, cycle, lock_pair_threads)
        verified = verification == DeadlockVerificationStatus.VERIFIED
        kind = (
            ConcurrencyIssueKind.DEADLOCK if verified else ConcurrencyIssueKind.POTENTIAL_DEADLOCK
        )
        label = "Verified" if verified else "Potential"
        severity = "error"
        if verification == DeadlockVerificationStatus.INCONCLUSIVE:
            label = "Inconclusive potential"
            severity = "warning"
        issues.append(
            ConcurrencyIssue(
                kind=kind,
                message=f"{label} deadlock: lock cycle {' -> '.join(cycle)}",
                shared_resource=", ".join(cycle),
                severity=severity,
            )
        )
    return issues


def verify_deadlock_z3(
    analyzer: ConcurrencyAnalyzerState,
    cycle: list[str],
    lock_pair_threads: dict[tuple[str, str], list[str]],
) -> bool:
    """Verify whether a lock-order cycle is feasible via Z3."""
    return (
        verify_deadlock_z3_result(analyzer, cycle, lock_pair_threads)
        == DeadlockVerificationStatus.VERIFIED
    )


def verify_deadlock_z3_result(
    analyzer: ConcurrencyAnalyzerState,
    cycle: list[str],
    lock_pair_threads: dict[tuple[str, str], list[str]],
) -> DeadlockVerificationStatus:
    """Verify a lock-order cycle while preserving solver inconclusiveness."""
    cycle_edges = list(pairwise(cycle))
    if len(cycle_edges) < 2:
        return DeadlockVerificationStatus.POTENTIAL

    thread_names = sorted(
        {thread_id for threads in lock_pair_threads.values() for thread_id in threads}
    )
    thread_indices = {thread_id: index for index, thread_id in enumerate(thread_names)}
    if len(thread_indices) < 2:
        return DeadlockVerificationStatus.POTENTIAL

    edge_thread_vars: list[z3.ArithRef] = []
    constraints: list[z3.BoolRef] = []
    for edge_index, (lock_a, lock_b) in enumerate(cycle_edges):
        threads = lock_pair_threads.get((lock_a, lock_b), [])
        if not threads:
            return DeadlockVerificationStatus.POTENTIAL
        edge_thread = z3.Int(f"deadlock_edge_{edge_index}_thread")
        edge_thread_vars.append(edge_thread)
        constraints.append(
            z3.Or(*(edge_thread == thread_indices[thread_id] for thread_id in threads))
        )

    constraints.append(
        z3.Or(
            *(
                left != right
                for index, left in enumerate(edge_thread_vars)
                for right in edge_thread_vars[index + 1 :]
            )
        )
    )

    try:
        result = analyzer.solver.check_sat_result(constraints)
    except z3.Z3Exception:
        logger.debug("Deadlock solver query failed; treating verification as inconclusive")
        return DeadlockVerificationStatus.INCONCLUSIVE
    if result.is_sat:
        return DeadlockVerificationStatus.VERIFIED
    if result.is_unknown:
        return DeadlockVerificationStatus.INCONCLUSIVE
    return DeadlockVerificationStatus.POTENTIAL


__all__ = [
    "DeadlockVerificationStatus",
    "detect_deadlocks",
    "verify_deadlock_z3",
    "verify_deadlock_z3_result",
]
