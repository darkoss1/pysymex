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

"""Persistent branch trace records for execution-path state."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3


@dataclass(frozen=True, slots=True)
class BranchRecord:
    """Record one program-counter branch decision in a path trace."""

    pc: int
    condition: z3.BoolRef
    taken: bool


class BranchChain:
    """Persistent linked list of recorded branch decisions.

    Forking is O(1) because parent and child may retain the same immutable
    chain head.
    """

    __slots__ = ("_length", "parent", "record")

    def __init__(
        self,
        record: BranchRecord | None = None,
        parent: BranchChain | None = None,
    ) -> None:
        """Initialize a chain head with an optional branch record and parent."""
        self.record = record
        self.parent = parent
        if parent is None:
            self._length = 1 if record is not None else 0
        else:
            self._length = parent._length + (1 if record is not None else 0)

    def append(self, record: BranchRecord) -> BranchChain:
        """Append a branch record, returning a new chain head. O(1)."""
        return BranchChain(record, self)

    def to_list(self) -> list[BranchRecord]:
        """Materialize the chain as a Python list. O(n)."""
        result: list[BranchRecord] = []
        node: BranchChain | None = self
        while node is not None and node.record is not None:
            result.append(node.record)
            node = node.parent
        result.reverse()
        return result

    def __len__(self) -> int:
        """Return the depth (number of records) of the branch chain."""
        return self._length

    @staticmethod
    def empty() -> BranchChain:
        """Create an empty branch chain."""
        return BranchChain()
