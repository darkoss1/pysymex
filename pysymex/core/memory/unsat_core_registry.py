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

from typing import List, Set, FrozenSet


class SparseCoreRegistry:
    """
    Registry for storing and checking sparse UNSAT cores.
    Allows O(|C_MUS|) amortized path pruning via sparse subset operations.
    Replaces dense bit-packing to support V > 100,000 without memory fragmentation.
    """

    __slots__ = ("_cores",)

    def __init__(self) -> None:
        self._cores: Set[FrozenSet[int]] = set()

    def add_core(self, core_indices: List[int]) -> None:
        """
        Registers a list of branch constraint indices as a known Minimum Unsatisfiable Subset (MUS).
        Stores them as a sparse frozenset.
        """
        if not core_indices:
            return
        self._cores.add(frozenset(core_indices))

    def is_feasible(self, path_indices: Set[int]) -> bool:
        """
        Checks if the given path indices are feasible against learned structural contradictions.

        A path is INFEASIBLE if it contains all constraint indices of ANY known UNSAT core.
        Mathematically: CoreSet.issubset(PathSet) -> path is structurally pruned.

        This check executes in O(|C_MUS|) time per core, independent of the total branch
        count (V), ensuring high-performance pruning even in massive programs.

        Returns True if feasible, False if structurally pruned.
        """
        for core_set in self._cores:
            if core_set.issubset(path_indices):
                return False
        return True

    @property
    def num_cores(self) -> int:
        """Returns the number of learned UNSAT cores."""
        return len(self._cores)

    def clear(self) -> None:
        """Clears all learned cores."""
        self._cores.clear()
