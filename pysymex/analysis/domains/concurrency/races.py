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

"""Data race detection via lockset analysis and happens-before concurrency checks."""

from __future__ import annotations

from pysymex.analysis.domains.concurrency.protocols import ConcurrencyAnalyzerState
from pysymex.analysis.domains.concurrency.enums import ConcurrencyIssueKind, OperationKind
from pysymex.analysis.domains.concurrency.models import ConcurrencyIssue, MemoryOperation


def _operation_locksets(analyzer: ConcurrencyAnalyzerState) -> dict[int, frozenset[str]]:
    """Build lockset information for each recorded operation.

    Args:
        analyzer (ConcurrencyAnalyzerState): The concurrency analyzer state.

    Returns:
        dict[int, frozenset[str]]: Map from operation ID to set of locks held at that time.
    """
    op_locksets: dict[int, frozenset[str]] = {}
    for thread_id in analyzer.threads.keys():
        current_locks: set[str] = set()
        ops_for_thread = analyzer.thread_op_ids.get(thread_id, [])
        for op_id in ops_for_thread:
            op = analyzer.hb_graph.operations.get(op_id)
            if op is None:
                continue
            if op.operation == OperationKind.LOCK_ACQUIRE:
                current_locks.add(op.address)
            elif op.operation == OperationKind.LOCK_RELEASE:
                current_locks.discard(op.address)
            op_locksets[op_id] = frozenset(current_locks)
    return op_locksets


def _race_issue(op1: MemoryOperation, op2: MemoryOperation, address: str) -> ConcurrencyIssue:
    """Create a ConcurrencyIssue object representing a data race.

    Args:
        op1 (MemoryOperation): First operation.
        op2 (MemoryOperation): Second operation.
        address (str): Shared variable name.

    Returns:
        ConcurrencyIssue: The data race issue details.
    """
    return ConcurrencyIssue(
        kind=ConcurrencyIssueKind.DATA_RACE,
        message=f"Data race on '{address}' between threads (no common lock held)",
        threads_involved=[op1.thread_id, op2.thread_id],
        shared_resource=address,
        line_number=op1.line_number,
    )


def _append_if_racy(
    analyzer: ConcurrencyAnalyzerState,
    issues: list[ConcurrencyIssue],
    op_locksets: dict[int, frozenset[str]],
    op_id1: int,
    op1: MemoryOperation,
    op_id2: int,
    op2: MemoryOperation,
) -> None:
    """Append a data race issue if two operations are concurrent, conflict, and share no locks.

    Args:
        analyzer (ConcurrencyAnalyzerState): The concurrency analyzer state.
        issues (list[ConcurrencyIssue]): The issues list to append to.
        op_locksets (dict[int, frozenset[str]]): Map of operation locksets.
        op_id1 (int): ID of the first operation.
        op1 (MemoryOperation): First operation.
        op_id2 (int): ID of the second operation.
        op2 (MemoryOperation): Second operation.
    """
    if not (op1.is_write() or op2.is_write()):
        return
    if not analyzer.hb_graph.are_concurrent(op_id1, op_id2):
        return
    locks1 = op_locksets.get(op_id1, frozenset())
    locks2 = op_locksets.get(op_id2, frozenset())
    if locks1 & locks2:
        return
    issues.append(_race_issue(op1, op2, op1.address))


def detect_data_races(analyzer: ConcurrencyAnalyzerState) -> list[ConcurrencyIssue]:
    """Detect data races using combined Lockset + Happens-Before analysis."""
    issues: list[ConcurrencyIssue] = []
    for thread_id, op_ids in analyzer.thread_op_ids.items():
        analyzer.hb_graph.add_program_order(thread_id, op_ids)

    op_locksets = _operation_locksets(analyzer)
    all_ops = list(analyzer.hb_graph.operations.items())
    if len(all_ops) <= 24:
        for i, (op_id1, op1) in enumerate(all_ops):
            for op_id2, op2 in all_ops[i + 1 :]:
                if not op1.conflicts_with(op2):
                    continue
                _append_if_racy(analyzer, issues, op_locksets, op_id1, op1, op_id2, op2)
        return issues

    ops_by_addr: dict[str, list[tuple[int, MemoryOperation]]] = {}
    for op_id, op in all_ops:
        if op.operation in {
            OperationKind.READ,
            OperationKind.WRITE,
            OperationKind.READ_MODIFY_WRITE,
        }:
            ops_by_addr.setdefault(op.address, []).append((op_id, op))

    for _address, addr_ops in ops_by_addr.items():
        if len(addr_ops) < 2 or not any(op.is_write() for _, op in addr_ops):
            continue
        by_thread: dict[str, list[tuple[int, MemoryOperation]]] = {}
        for op_id, op in addr_ops:
            by_thread.setdefault(op.thread_id, []).append((op_id, op))
        thread_groups = list(by_thread.items())
        for i, (_thread1, ops1) in enumerate(thread_groups):
            for _thread2, ops2 in thread_groups[i + 1 :]:
                for op_id1, op1 in ops1:
                    for op_id2, op2 in ops2:
                        _append_if_racy(analyzer, issues, op_locksets, op_id1, op1, op_id2, op2)
    return issues


__all__ = ["detect_data_races"]
