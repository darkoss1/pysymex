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

"""Domain models for concurrency analysis: issues, memory operations, and threads."""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex.analysis.domains.concurrency.enums import (
    ConcurrencyIssueKind,
    MemoryOrder,
    OperationKind,
    ThreadState,
)


@dataclass
class ConcurrencyIssue:
    """A detected concurrency bug with location, schedule, and Z3 counterexample metadata."""

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
        """Format the issue as a human-readable diagnostic string."""
        loc = f" at line {self.line_number}" if self.line_number else ""
        threads = f" (threads: {', '.join(self.threads_involved)})" if self.threads_involved else ""
        resource = f" on {self.shared_resource}" if self.shared_resource else ""
        return f"[{self.kind.name}]{loc}{threads}{resource}: {self.message}"


@dataclass(frozen=True)
class MemoryOperation:
    """An immutable record of a single memory access or synchronisation event.

    Two operations *conflict* when they access the same address from
    different threads and at least one is a write.
    """

    thread_id: str
    operation: OperationKind
    address: str
    value: object | None = None
    order: MemoryOrder = MemoryOrder.SEQ_CST
    line_number: int | None = None
    timestamp: int = 0

    def is_write(self) -> bool:
        """Check if this operation performs a memory write.

        Returns:
            bool: True if WRITE or READ_MODIFY_WRITE, False otherwise.
        """
        return self.operation in {OperationKind.WRITE, OperationKind.READ_MODIFY_WRITE}

    def is_read(self) -> bool:
        """Check if this operation performs a memory read.

        Returns:
            bool: True if READ or READ_MODIFY_WRITE, False otherwise.
        """
        return self.operation in {OperationKind.READ, OperationKind.READ_MODIFY_WRITE}

    def conflicts_with(self, other: MemoryOperation) -> bool:
        """Return ``True`` if both operations conflict (same address, different threads, ≥1 write)."""
        if self.address != other.address:
            return False
        if self.thread_id == other.thread_id:
            return False
        return self.is_write() or other.is_write()


@dataclass
class Thread:
    """A modelled thread with lifecycle state, operation history, and held locks."""

    thread_id: str
    state: ThreadState = ThreadState.NOT_STARTED
    operations: list[MemoryOperation] = field(default_factory=list[MemoryOperation])
    held_locks: set[str] = field(default_factory=set[str])
    waiting_for: str | None = None

    def add_operation(self, op: MemoryOperation) -> None:
        """Append *op* to this thread's operation history."""
        self.operations.append(op)


__all__ = ["ConcurrencyIssue", "MemoryOperation", "Thread"]
