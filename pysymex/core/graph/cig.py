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

"""Disjoint-set and basic variable sharing graph structure."""

from __future__ import annotations
from collections.abc import Hashable, Iterable


class ConstraintInteractionGraph:
    """Constraint interaction graph tracking variable sharing between branch points."""

    def __init__(self, optimizer: object = None) -> None:
        self.optimizer = optimizer
        self.adjacency: dict[int, set[int]] = {}
        self.branch_variables: dict[int, frozenset[Hashable]] = {}

    @property
    def num_branches(self) -> int:
        """Return the number of tracked branches (vertices)."""
        return len(self.branch_variables)

    @property
    def num_edges(self) -> int:
        """Return the number of edges (overlapping variable scopes)."""
        total_deg = sum(len(neighbors) for neighbors in self.adjacency.values())
        return total_deg // 2

    @property
    def estimated_treewidth(self) -> int:
        """Estimated treewidth heuristic (default to 1)."""
        return 1

    def get_degree(self, pc: int) -> int:
        """Return the degree of the branch node at `pc`."""
        neighbors = self.adjacency.get(pc)
        if neighbors is None:
            return 0
        return len(neighbors)

    def add_branch(self, pc: int, vars_set: frozenset[Hashable] | Iterable[Hashable]) -> None:
        """Add a branch vertex and connect edges to overlapping variable scopes."""
        if pc in self.branch_variables:
            return

        normalized = vars_set if isinstance(vars_set, frozenset) else frozenset(vars_set)
        self.branch_variables[pc] = normalized
        self.adjacency[pc] = set()

        for other_pc, other_vars in self.branch_variables.items():
            if other_pc == pc:
                continue
            if normalized.intersection(other_vars):
                self.adjacency[pc].add(other_pc)
                self.adjacency[other_pc].add(pc)

    def reset(self) -> None:
        """Reset the graph vertices and edges."""
        self.adjacency.clear()
        self.branch_variables.clear()


__all__ = ["ConstraintInteractionGraph"]
