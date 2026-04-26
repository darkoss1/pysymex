# pysymex: Python Symbolic Execution & Formal Verification
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

"""Concurrency Analysis with Z3.
This module provides comprehensive concurrency analysis using Z3 SMT solver
for mathematical proofs of thread safety. Covers:
- Thread interleaving model
- Race condition detection
- Deadlock analysis
- Data race detection
- Atomicity violation detection
- Memory ordering issues
- Happens-before relationships
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from itertools import pairwise


class MemoryOrder(Enum):
    """Memory ordering semantics."""

    RELAXED = auto()
    ACQUIRE = auto()
    RELEASE = auto()
    ACQ_REL = auto()
    SEQ_CST = auto()


class OperationKind(Enum):
    """Types of memory operations."""

    READ = auto()
    WRITE = auto()
    READ_MODIFY_WRITE = auto()
    FENCE = auto()
    LOCK_ACQUIRE = auto()
    LOCK_RELEASE = auto()
    THREAD_CREATE = auto()
    THREAD_JOIN = auto()
    BARRIER = auto()


class ThreadState(Enum):
    """Thread execution states."""

    NOT_STARTED = auto()
    RUNNING = auto()
    BLOCKED = auto()
    WAITING = auto()
    TERMINATED = auto()


class ConcurrencyIssueKind(Enum):
    """Types of concurrency issues."""

    DATA_RACE = auto()
    RACE_CONDITION = auto()
    DEADLOCK = auto()
    POTENTIAL_DEADLOCK = auto()
    LIVELOCK = auto()
    ATOMICITY_VIOLATION = auto()
    LOST_UPDATE = auto()
    MEMORY_ORDER_VIOLATION = auto()
    STALE_READ = auto()
    LOCK_NOT_HELD = auto()
    WRONG_LOCK = auto()
    USE_AFTER_JOIN = auto()
    JOIN_WITHOUT_START = auto()
    SPURIOUS_WAKEUP = auto()
    SIGNAL_SAFETY = auto()


@dataclass
class ConcurrencyIssue:
    """Represents a detected concurrency issue."""

    kind: ConcurrencyIssueKind
    message: str
    threads_involved: list[str] = field(default_factory=list[str])
    shared_resource: str | None = None
    location: str | None = None
    line_number: int | None = None
    schedule: list[tuple[str, str]] | None = None
    constraints: list[object] = field(default_factory=list[object])
    counterexample: dict[str, object] = field(default_factory=dict[str, object])
    severity: str = "error"

    def format(self) -> str:
        """Format issue for display."""
        loc = f" at line {self.line_number}" if self.line_number else ""
        threads = f" (threads: {', '.join(self.threads_involved)})" if self.threads_involved else ""
        res = f" on {self.shared_resource}" if self.shared_resource else ""
        return f"[{self.kind.name}]{loc}{threads}{res}: {self.message}"


@dataclass(frozen=True)
class MemoryOperation:
    """Represents a memory operation for analysis."""

    thread_id: str
    operation: OperationKind
    address: str
    value: object | None = None
    order: MemoryOrder = MemoryOrder.SEQ_CST
    line_number: int | None = None
    timestamp: int = 0

    def is_write(self) -> bool:
        return self.operation in {OperationKind.WRITE, OperationKind.READ_MODIFY_WRITE}

    def is_read(self) -> bool:
        return self.operation in {OperationKind.READ, OperationKind.READ_MODIFY_WRITE}

    def conflicts_with(self, other: MemoryOperation) -> bool:
        """Check if this operation conflicts with another."""
        if self.address != other.address:
            return False
        if self.thread_id == other.thread_id:
            return False
        return self.is_write() or other.is_write()


@dataclass
class Thread:
    """Represents a thread for analysis."""

    thread_id: str
    state: ThreadState = ThreadState.NOT_STARTED
    operations: list[MemoryOperation] = field(default_factory=list[MemoryOperation])
    held_locks: set[str] = field(default_factory=set[str])
    waiting_for: str | None = None

    def add_operation(self, op: MemoryOperation) -> None:
        """Add an operation to this thread's history."""
        self.operations.append(op)


class HappensBeforeGraph:
    """
    Tracks happens-before relationships between operations.
    Used to determine if a data race exists (concurrent, conflicting accesses).
    """

    def __init__(self) -> None:
        self._edges: set[tuple[int, int]] = set()
        self._adj: dict[int, set[int]] = {}
        self._operations: dict[int, MemoryOperation] = {}
        self._hb_cache: dict[tuple[int, int], bool] = {}
        self._op_counter = 0

    @property
    def operations(self) -> dict[int, MemoryOperation]:
        """Public accessor for operations."""
        return self._operations

    @property
    def edges_set(self) -> set[tuple[int, int]]:
        """Public accessor for edges."""
        return self._edges

    def add_operation(self, op: MemoryOperation) -> int:
        """Add operation and return its ID."""
        op_id = self._op_counter
        self._op_counter += 1
        self._operations[op_id] = op
        self._hb_cache.clear()
        return op_id

    def add_edge(self, from_op: int, to_op: int) -> None:
        """Add happens-before edge."""
        if (from_op, to_op) in self._edges:
            return
        self._edges.add((from_op, to_op))
        self._adj.setdefault(from_op, set()).add(to_op)
        self._hb_cache.clear()

    def add_program_order(self, thread_id: str, op_ids: list[int]) -> None:
        """Add program order edges for a thread."""
        for a, b in pairwise(op_ids):
            self.add_edge(a, b)

    def add_synchronizes_with(self, release_op: int, acquire_op: int) -> None:
        """Add synchronizes-with edge (release -> acquire)."""
        self.add_edge(release_op, acquire_op)

    def happens_before(self, op1: int, op2: int) -> bool:
        """Check if op1 happens-before op2 (transitive)."""
        key = (op1, op2)
        cached = self._hb_cache.get(key)
        if cached is not None:
            return cached

        visited: set[int] = set()
        queue = deque([op1])
        while queue:
            current = queue.popleft()
            if current == op2:
                self._hb_cache[key] = True
                return True
            if current in visited:
                continue
            visited.add(current)
            for to_op in self._adj.get(current, ()):
                queue.append(to_op)
        self._hb_cache[key] = False
        return False

    def are_concurrent(self, op1: int, op2: int) -> bool:
        """Check if two operations are concurrent (neither happens-before the other)."""
        return not self.happens_before(op1, op2) and not self.happens_before(op2, op1)

    def get_operation(self, op_id: int) -> MemoryOperation | None:
        """Get operation by ID."""
        return self._operations.get(op_id)


from pysymex.analysis.concurrency.core import (
    ConcurrencyAnalyzer,
    LockOrderChecker,
    ThreadSafetyChecker,
)

__all__ = [
    "ConcurrencyAnalyzer",
    "ConcurrencyIssue",
    "ConcurrencyIssueKind",
    "HappensBeforeGraph",
    "LockOrderChecker",
    "MemoryOperation",
    "ThreadSafetyChecker",
    "MemoryOrder",
    "OperationKind",
    "Thread",
    "ThreadState",
]
