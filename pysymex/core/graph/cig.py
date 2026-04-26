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

from typing import Dict, FrozenSet, Hashable, Set


class ConstraintInteractionGraph:
    """
    Simple Constraint Interaction Graph (CIG) for pysymex v2.

    This is a lightweight CIG implementation for basic variable-sharing tracking
    between branch points. It provides a simple interface that works with
    variable sets rather than Z3 conditions, making it suitable for
    production code that doesn't need full CHTD treewidth analysis.

    For advanced treewidth analysis and CHTD features, use the full-featured
    ConstraintInteractionGraph in treewidth.py instead.
    """

    __slots__ = ("_adjacency", "_branch_vars", "_num_edges")

    def __init__(self) -> None:
        # Maps pc -> set of connected pcs
        self._adjacency: Dict[int, Set[int]] = {}
        self._branch_vars: Dict[int, FrozenSet[Hashable]] = {}
        self._num_edges: int = 0

    def add_branch(self, pc: int, variables: FrozenSet[Hashable]) -> None:
        """
        Registers a new branch point and its associated symbolic variables.
        Incrementally builds edges to all existing branches that share at least one variable.
        O(V) worst-case insertion time, optimized via set intersection.
        """
        if pc in self._adjacency:
            return

        self._adjacency[pc] = set()
        self._branch_vars[pc] = variables

        for other_pc, other_vars in self._branch_vars.items():
            if other_pc != pc and not variables.isdisjoint(other_vars):
                self._add_edge(pc, other_pc)

    def _add_edge(self, pc1: int, pc2: int) -> None:
        """Adds an undirected edge between two branch PCs."""
        self._adjacency[pc1].add(pc2)
        self._adjacency[pc2].add(pc1)
        self._num_edges += 1

    def get_degree(self, pc: int) -> int:
        """Returns the degree of the branch PC in the CIG."""
        return len(self._adjacency.get(pc, set()))

    def get_neighbors(self, pc: int) -> Set[int]:
        """Returns the neighbors of the branch PC."""
        return self._adjacency.get(pc, set())

    @property
    def num_vertices(self) -> int:
        return len(self._adjacency)

    @property
    def num_edges(self) -> int:
        return self._num_edges

    def clear(self) -> None:
        """Clears the graph."""
        self._adjacency.clear()
        self._branch_vars.clear()
        self._num_edges = 0
