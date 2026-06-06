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

"""Recording operations: thread lifecycle, memory accesses, and lock acquire/release."""

from __future__ import annotations

from pysymex.analysis.domains.concurrency.protocols import ConcurrencyAnalyzerState
from pysymex.analysis.domains.concurrency.enums import (
    ConcurrencyIssueKind,
    MemoryOrder,
    OperationKind,
    ThreadState,
)
from pysymex.analysis.domains.concurrency.models import ConcurrencyIssue, MemoryOperation


def start_thread(
    analyzer: ConcurrencyAnalyzerState,
    thread_id: str,
    parent_thread: str,
    line_number: int | None = None,
) -> ConcurrencyIssue | None:
    """Record thread start and add a synchronises-with edge from the parent."""
    thread = analyzer.threads.get(thread_id)
    if thread is None:
        return None
    thread.state = ThreadState.RUNNING
    if analyzer.thread_op_ids.get(parent_thread):
        parent_last_op = analyzer.thread_op_ids[parent_thread][-1]
        start_op = MemoryOperation(
            thread_id=thread_id,
            operation=OperationKind.THREAD_CREATE,
            address=f"__thread_start_{thread_id}",
            line_number=line_number,
        )
        start_op_id = analyzer.hb_graph.add_operation(start_op)
        analyzer.thread_op_ids[thread_id].append(start_op_id)
        analyzer.hb_graph.add_edge(parent_last_op, start_op_id)
    return None


def join_thread(
    analyzer: ConcurrencyAnalyzerState,
    thread_id: str,
    joining_thread: str,
    line_number: int | None = None,
) -> ConcurrencyIssue | None:
    """Record thread join."""
    if joining_thread not in analyzer.threads:
        return ConcurrencyIssue(
            kind=ConcurrencyIssueKind.JOIN_WITHOUT_START,
            message=f"Thread '{joining_thread}' attempted to join '{thread_id}' without registration",
            threads_involved=[joining_thread, thread_id],
            line_number=line_number,
        )
    thread = analyzer.threads.get(thread_id)
    if thread is None:
        return ConcurrencyIssue(
            kind=ConcurrencyIssueKind.JOIN_WITHOUT_START,
            message=f"Joining thread '{thread_id}' that doesn't exist",
            threads_involved=[joining_thread, thread_id],
            line_number=line_number,
        )
    if thread.state == ThreadState.NOT_STARTED:
        return ConcurrencyIssue(
            kind=ConcurrencyIssueKind.JOIN_WITHOUT_START,
            message=f"Joining thread '{thread_id}' that hasn't started",
            threads_involved=[joining_thread, thread_id],
            line_number=line_number,
        )
    thread.state = ThreadState.TERMINATED
    if analyzer.thread_op_ids.get(thread_id):
        child_last_op = analyzer.thread_op_ids[thread_id][-1]
        join_op = MemoryOperation(
            thread_id=joining_thread,
            operation=OperationKind.THREAD_JOIN,
            address=f"__thread_join_{thread_id}",
            line_number=line_number,
        )
        join_op_id = analyzer.hb_graph.add_operation(join_op)
        analyzer.thread_op_ids.setdefault(joining_thread, []).append(join_op_id)
        analyzer.hb_graph.add_edge(child_last_op, join_op_id)
    return None


def record_memory_operation(
    analyzer: ConcurrencyAnalyzerState,
    thread_id: str,
    variable: str,
    operation: OperationKind,
    value: object = None,
    order: MemoryOrder = MemoryOrder.SEQ_CST,
    line_number: int | None = None,
) -> int:
    """Record a memory operation."""
    op = MemoryOperation(
        thread_id=thread_id,
        operation=operation,
        address=variable,
        value=value,
        order=order,
        line_number=line_number,
        timestamp=len(analyzer.hb_graph.operations),
    )
    op_id = analyzer.hb_graph.add_operation(op)
    thread = analyzer.threads.get(thread_id)
    if thread:
        thread.add_operation(op)
    analyzer.thread_op_ids.setdefault(thread_id, []).append(op_id)
    analyzer.shared_variables.add(variable)
    return op_id


def acquire_lock(
    analyzer: ConcurrencyAnalyzerState,
    thread_id: str,
    lock_name: str,
    line_number: int | None = None,
) -> ConcurrencyIssue | None:
    """Record lock acquisition."""
    current_holder = analyzer.locks.get(lock_name)
    if current_holder == thread_id:
        return ConcurrencyIssue(
            kind=ConcurrencyIssueKind.DEADLOCK,
            message=f"Thread '{thread_id}' attempting to acquire lock it already holds",
            threads_involved=[thread_id],
            shared_resource=lock_name,
            line_number=line_number,
        )
    op = MemoryOperation(
        thread_id=thread_id,
        operation=OperationKind.LOCK_ACQUIRE,
        address=lock_name,
        order=MemoryOrder.ACQUIRE,
        line_number=line_number,
        timestamp=len(analyzer.hb_graph.operations),
    )
    op_id = analyzer.hb_graph.add_operation(op)
    analyzer.thread_op_ids.setdefault(thread_id, []).append(op_id)
    analyzer.has_lock_activity = True
    analyzer.locks[lock_name] = thread_id
    analyzer.lock_acquisitions.setdefault(lock_name, []).append(thread_id)
    thread = analyzer.threads.get(thread_id)
    if thread:
        thread.held_locks.add(lock_name)
        thread.add_operation(op)
    return None


def release_lock(
    analyzer: ConcurrencyAnalyzerState,
    thread_id: str,
    lock_name: str,
    line_number: int | None = None,
) -> ConcurrencyIssue | None:
    """Record lock release."""
    current_holder = analyzer.locks.get(lock_name)
    if current_holder != thread_id:
        return ConcurrencyIssue(
            kind=ConcurrencyIssueKind.LOCK_NOT_HELD,
            message=f"Thread '{thread_id}' releasing lock it doesn't hold",
            threads_involved=[thread_id],
            shared_resource=lock_name,
            line_number=line_number,
        )
    op = MemoryOperation(
        thread_id=thread_id,
        operation=OperationKind.LOCK_RELEASE,
        address=lock_name,
        order=MemoryOrder.RELEASE,
        line_number=line_number,
        timestamp=len(analyzer.hb_graph.operations),
    )
    op_id = analyzer.hb_graph.add_operation(op)
    analyzer.thread_op_ids.setdefault(thread_id, []).append(op_id)
    analyzer.has_lock_activity = True
    analyzer.locks[lock_name] = None
    thread = analyzer.threads.get(thread_id)
    if thread:
        thread.held_locks.discard(lock_name)
        thread.add_operation(op)
    return None


__all__ = ["acquire_lock", "join_thread", "record_memory_operation", "release_lock", "start_thread"]
