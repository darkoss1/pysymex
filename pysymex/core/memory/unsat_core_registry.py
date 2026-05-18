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

from collections.abc import Iterable

CoreKey = frozenset[int]


class SparseCoreRegistry:
    """
    Antichain registry for storing and checking sparse, certified UNSAT cores.

    A path may be pruned only when it contains a learned UNSAT core. The registry
    keeps cores as an antichain under subset ordering: if a smaller core is known,
    larger supersets are redundant and are not retained.
    """

    __slots__ = ("_cores",)

    def __init__(self) -> None:
        self._cores: set[CoreKey] = set()

    def add_core(self, core_indices: Iterable[int]) -> bool:
        """
        Register a solver-certified UNSAT core.

        Returns True when the registry learned a new strongest core. Returns False
        when the candidate is empty or already covered by an existing subset core.
        """
        candidate = frozenset(core_indices)
        if not candidate:
            return False

        for existing in self._cores:
            if existing.issubset(candidate):
                return False

        supersets = {existing for existing in self._cores if candidate.issubset(existing)}
        self._cores.difference_update(supersets)
        self._cores.add(candidate)
        return True

    def contained_core(self, path_indices: set[int]) -> CoreKey | None:
        """
        Return a learned UNSAT core contained in the path, if any.
        """
        for core_set in self._cores:
            if core_set.issubset(path_indices):
                return core_set
        return None

    def is_feasible(self, path_indices: set[int]) -> bool:
        """
        Check if the given path avoids all learned structural contradictions.

        Returns True if feasible, False if structurally pruned.
        """
        return self.contained_core(path_indices) is None

    @property
    def num_cores(self) -> int:
        """Returns the number of learned UNSAT cores."""
        return len(self._cores)

    @property
    def cores(self) -> tuple[CoreKey, ...]:
        """Return a snapshot of learned UNSAT cores for diagnostics and tests."""
        return tuple(self._cores)

    def clear(self) -> None:
        """Clears all learned cores."""
        self._cores.clear()
