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

from typing import List, Optional


class BranchHistoryNode:
    """
    Flyweight persistent linked list for tracking execution paths.
    Provides O(1) memory growth per branch by only storing the delta.
    """

    __slots__ = ("pc", "branch_index", "is_true_branch", "parent", "_depth")

    def __init__(
        self,
        pc: int,
        branch_index: int,
        is_true_branch: bool,
        parent: Optional["BranchHistoryNode"] = None,
    ):
        self.pc = pc
        self.branch_index = (
            branch_index  # Unique index representing this specific branch outcome (constraint)
        )
        self.is_true_branch = is_true_branch
        self.parent = parent
        self._depth = 1 if parent is None else parent._depth + 1

    @property
    def depth(self) -> int:
        """Returns the length of the path from root to this node."""
        return self._depth

    def to_list(self) -> List[tuple[int, bool]]:
        """
        Returns the full path as a list of (pc, is_true_branch) tuples.
        Executes in O(D) time where D is the depth of the node.
        """
        path: List[tuple[int, bool]] = []
        current: Optional["BranchHistoryNode"] = self
        while current is not None:
            path.append((current.pc, current.is_true_branch))
            current = current.parent
        path.reverse()
        return path
