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

"""Happens-before relation graph for determining operation concurrency."""

from __future__ import annotations

from collections import deque
from itertools import pairwise

from pysymex.analysis.domains.concurrency.models import MemoryOperation


class HappensBeforeGraph:
    """Directed graph encoding happens-before (HB) relationships between operations.

    Edges represent program-order, synchronises-with, and transitive HB
    relationships.  BFS reachability is cached and invalidated when the
    graph changes.  Two operations are *concurrent* if neither happens
    before the other.
    """

    def __init__(self) -> None:
        """Initialize an empty HappensBeforeGraph instance."""
        self.edge_map: set[tuple[int, int]] = set()
        self._adj: dict[int, set[int]] = {}
        self._operations: dict[int, MemoryOperation] = {}
        self._hb_cache: dict[tuple[int, int], bool] = {}
        self._op_counter = 0

    @property
    def operations(self) -> dict[int, MemoryOperation]:
        """Registered operation mapping (operation ID → ``MemoryOperation``)."""
        return self._operations

    @property
    def edges_set(self) -> set[tuple[int, int]]:
        """Set of directed ``(from_id, to_id)`` HB edges."""
        return self.edge_map

    def add_operation(self, op: MemoryOperation) -> int:
        """Register a memory operation and return its unique integer ID."""
        op_id = self._op_counter
        self._op_counter += 1
        self._operations[op_id] = op
        self._hb_cache.clear()
        return op_id

    def add_edge(self, from_op: int, to_op: int) -> None:
        """Record that *from_op* happens-before *to_op* (invalidates the BFS cache)."""
        if (from_op, to_op) in self.edge_map:
            return
        self.edge_map.add((from_op, to_op))
        self._adj.setdefault(from_op, set()).add(to_op)
        self._hb_cache.clear()

    def add_program_order(self, thread_id: str, op_ids: list[int]) -> None:
        """Add sequential program-order edges for consecutive operations in a thread."""
        for a, b in pairwise(op_ids):
            self.add_edge(a, b)

    def add_synchronizes_with(self, release_op: int, acquire_op: int) -> None:
        """Add a synchronises-with edge from a release to an acquire operation."""
        self.add_edge(release_op, acquire_op)

    def happens_before(self, op1: int, op2: int) -> bool:
        """Return ``True`` if *op1* transitively happens-before *op2* (BFS, cached)."""
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
        """Return ``True`` if *op1* and *op2* are concurrent (no HB ordering in either direction)."""
        return not self.happens_before(op1, op2) and not self.happens_before(op2, op1)

    def get_operation(self, op_id: int) -> MemoryOperation | None:
        """Return the ``MemoryOperation`` for *op_id*, or ``None``."""
        return self._operations.get(op_id)


__all__ = ["HappensBeforeGraph"]
