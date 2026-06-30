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

"""Constraint-independence adapter for the shared union-find implementation."""

from __future__ import annotations

from pysymex._internal.core.graph.union.find import UnionFind


class ConstraintUnionFind:
    """Solver-facing union-find with auto-creating string keys.

    The disjoint-set algorithm is owned by :mod:`pysymex._internal.core.graph.union.find`.
    Constraint independence keeps its historical API: ``find`` creates singleton
    sets for unseen variables, and ``union`` returns the merged representative.
    """

    __slots__ = ("_sets",)

    def __init__(self) -> None:
        """Create an empty solver-facing disjoint-set wrapper."""
        self._sets: UnionFind[str] = UnionFind()

    def find(self, x: str) -> str:
        """Find the representative of the set containing ``x``.

        Creates a new singleton set if ``x`` has not been seen before.
        """
        self._sets.make_set(x)
        return self._sets.find(x)

    def union(self, a: str, b: str) -> str:
        """Merge the sets containing ``a`` and ``b``.

        Returns the new representative of the merged set.
        """
        self._sets.union(a, b)
        return self._sets.find(a)

    def connected(self, a: str, b: str) -> bool:
        """Return whether ``a`` and ``b`` share a group, creating unseen keys."""
        return self.find(a) == self.find(b)

    def groups(self) -> dict[str, set[str]]:
        """Return all registered groups keyed by their representatives."""
        return self._sets.groups()
