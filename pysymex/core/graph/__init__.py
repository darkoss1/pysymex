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

"""Constraint Interaction Graph and Treewidth Analysis for pysymex.

Implements the Constraint Hypergraph Treewidth Decomposition (CHTD)
infrastructure: builds a graph where branch points are vertices and
edges connect branches that share symbolic variables, then computes
an approximate tree decomposition.

This enables a complexity-class transition for symbolic execution:
instead of exploring 2^B paths (exponential in total branches B),
CHTD achieves O(N · 2^w) structural path exploration via dynamic
programming (message passing) over the tree decomposition, where
w = treewidth and w << B for structured programs.
"""

from __future__ import annotations

from .treewidth import (
    BranchInfo,
    ConstraintInteractionGraph,
    TreeDecomposition,
)

__all__ = [
    "BranchInfo",
    "ConstraintInteractionGraph",
    "TreeDecomposition",
]
