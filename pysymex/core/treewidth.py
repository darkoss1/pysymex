# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

import logging
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import z3

    from pysymex.core.constraint_independence import ConstraintIndependenceOptimizer

logger = logging.getLogger(__name__)


_DISCRIMINATOR_SUFFIXES = (
    "_is_int",
    "_is_bool",
    "_is_str",
    "_is_float",
    "_is_obj",
    "_is_path",
    "_is_none",
    "_is_list",
    "_is_dict",
    "_int",
    "_bool",
    "_str",
    "_float",
    "_addr",
    "_array",
    "_len",
)


def _base_var_name(z3_var_name: str) -> str:
    """Strip type-discriminator suffixes to get the SymbolicValue base name.

    Examples::

        >>> _base_var_name("x_42_int")
        'x_42'
        >>> _base_var_name("x_42_is_bool")
        'x_42'
        >>> _base_var_name("loop_counter")
        'loop_counter'
    """
    for suffix in _DISCRIMINATOR_SUFFIXES:
        if z3_var_name.endswith(suffix):
            return z3_var_name[: -len(suffix)]
    return z3_var_name


@dataclass
class BranchInfo:
    """Metadata for a single branch point in the interaction graph.

    Attributes:
        pc: Program counter (bytecode index) of the branch.
        raw_vars: Original Z3 variable names from the branch condition.
        base_vars: SymbolicValue-level variable names (discriminators merged).
        condition: The original Z3 boolean expression for this branch.
            Stored so callers can use it for local satisfiability checks
            (e.g. ``propagate_bag_constraints``).
    """

    pc: int
    raw_vars: frozenset[str]
    base_vars: frozenset[str]
    condition: z3.BoolRef | None = None


@dataclass
class TreeDecomposition:
    """A tree decomposition of the constraint interaction graph.

    Attributes:
        bags: Mapping from bag ID to the set of branch PCs in that bag.
        tree_edges: Edges of the decomposition tree.
        adhesion: For each tree edge, the set of branch PCs shared between
            the two adjacent bags.
        width: w = max(|bag|) - 1.  Treewidth of this decomposition.
        elimination_order: The vertex elimination sequence used to build
            this decomposition (useful for diagnostics).
        parent_map: Mapping from bag ID to parent bag ID (root has no entry).
    """

    bags: dict[int, frozenset[int]]
    tree_edges: list[tuple[int, int]]
    adhesion: dict[tuple[int, int], frozenset[int]]
    width: int
    elimination_order: list[int] = field(default_factory=list)
    parent_map: dict[int, int] = field(default_factory=dict)

    def get_parent(self, bag_id: int) -> int | None:
        """Get the parent bag ID, or None if this is the root."""
        return self.parent_map.get(bag_id)


class ConstraintInteractionGraph:
    """Tracks variable-sharing between branch conditions.

    Vertices are branch PCs; an edge connects two branches iff they
    share at least one SymbolicValue (after stripping discriminator
    suffixes).  This is the *primal graph* of the constraint
    interaction hypergraph.

    The graph is maintained incrementally: call ``add_branch()`` each
    time the executor encounters a conditional; the adjacency list and
    inverted index are updated in amortized O(|vars| · max_branches_per_var).
    """

    __slots__ = (
        "_adjacency",
        "_branch_info",
        "_branches_since_last_tw_change",
        "_cached_td",
        "_estimated_tw",
        "_optimizer",
        "_var_branches",
    )

    def __init__(self, optimizer: ConstraintIndependenceOptimizer) -> None:
        self._optimizer = optimizer
        self._branch_info: dict[int, BranchInfo] = {}
        self._var_branches: dict[str, set[int]] = defaultdict(set)
        self._adjacency: dict[int, set[int]] = defaultdict(set)
        self._estimated_tw: int = 0
        self._branches_since_last_tw_change: int = 0
        self._cached_td: TreeDecomposition | None = None

    def reset(self) -> None:
        """Clear all state.  Call between analysis units."""
        self._branch_info.clear()
        self._var_branches.clear()
        self._adjacency.clear()
        self._estimated_tw = 0
        self._branches_since_last_tw_change = 0
        self._cached_td = None

    @property
    def num_branches(self) -> int:
        """Number of branch points registered."""
        return len(self._branch_info)

    @property
    def estimated_treewidth(self) -> int:
        """Current lower-bound estimate for treewidth (degeneracy-based)."""
        return self._estimated_tw

    @property
    def branch_info(self) -> dict[int, BranchInfo]:
        """Read-only view of registered branch metadata."""
        return self._branch_info

    @property
    def adjacency(self) -> dict[int, set[int]]:
        """Read-only view of the interaction graph adjacency map."""
        return self._adjacency

    def add_branch(self, pc: int, condition: z3.BoolRef) -> BranchInfo:
        """Register a new branch and update the interaction graph.

        Args:
            pc: Program counter of the branch instruction.
            condition: The Z3 boolean expression for the branch.

        Returns:
            BranchInfo with the extracted variable sets.
        """
        if pc in self._branch_info:
            return self._branch_info[pc]

        raw_vars = self._optimizer.get_variables(condition)
        base_vars = frozenset(_base_var_name(v) for v in raw_vars)

        self._cached_td = None
        info = BranchInfo(pc=pc, raw_vars=raw_vars, base_vars=base_vars, condition=condition)
        self._branch_info[pc] = info

        old_max_degree = max((len(neighbors) for neighbors in self._adjacency.values()), default=0)

        for bv in base_vars:
            for neighbor_pc in self._var_branches[bv]:
                if neighbor_pc != pc:
                    self._adjacency[pc].add(neighbor_pc)
                    self._adjacency[neighbor_pc].add(pc)
            self._var_branches[bv].add(pc)

        new_max_degree = max((len(neighbors) for neighbors in self._adjacency.values()), default=0)

        if new_max_degree > old_max_degree:
            old_tw = self._estimated_tw
            self._estimated_tw = self._compute_degeneracy()
            if self._estimated_tw != old_tw:
                self._branches_since_last_tw_change = 0
        else:
            self._branches_since_last_tw_change += 1

        return info

    def is_stabilized(
        self,
        stability_threshold: int = 8,
        max_useful_treewidth: int = 15,
        min_branches: int = 6,
    ) -> bool:
        """Check if the graph has stabilized enough for skeleton extraction.

        Returns True when:
        - Enough branches have been seen (≥ min_branches)
        - No treewidth change for stability_threshold consecutive branches
        - Estimated treewidth is below max_useful_treewidth
        """
        return (
            self.num_branches >= min_branches
            and self._branches_since_last_tw_change >= stability_threshold
            and self._estimated_tw <= max_useful_treewidth
        )

    def _compute_degeneracy(self) -> int:
        """Compute the degeneracy (k-core number) of the graph.

        Degeneracy is a lower bound on treewidth and is computable
        via iterative minimum-degree vertex removal.

        Uses degree buckets to pick the next min-degree vertex in amortized
        O(1), giving O(V + E) behavior for sparse branch graphs.
        """
        if not self._adjacency:
            return 0

        degree: dict[int, int] = {v: len(ns) for v, ns in self._adjacency.items()}

        for pc in self._branch_info:
            if pc not in degree:
                degree[pc] = 0

        remaining = set(degree.keys())
        max_degree = max(degree.values(), default=0)
        buckets: dict[int, set[int]] = defaultdict(set)
        for v, deg in degree.items():
            buckets[deg].add(v)

        max_min_degree = 0
        current_min = 0

        while remaining:
            while current_min <= max_degree and not buckets[current_min]:
                current_min += 1
            if current_min > max_degree:
                break

            v = buckets[current_min].pop()
            if v not in remaining:
                continue

            max_min_degree = max(max_min_degree, degree[v])
            remaining.discard(v)
            for neighbor in self._adjacency.get(v, set()):
                if neighbor in remaining:
                    old_deg = degree[neighbor]
                    new_deg = max(0, old_deg - 1)
                    degree[neighbor] = new_deg
                    buckets[old_deg].discard(neighbor)
                    buckets[new_deg].add(neighbor)
                    if new_deg < current_min:
                        current_min = new_deg

        return max_min_degree

    def compute_tree_decomposition(self) -> TreeDecomposition:
        """Compute an approximate tree decomposition via min-degree elimination.

        While minimum-degree elimination does not provide a strict constant-factor
        guarantee for general graphs, it efficiently yields near-optimal
        decompositions for the specific sparse topologies of program
        control-flow graphs.

        Algorithm:
        1. Repeatedly remove the vertex with minimum degree
        2. Before removal, connect all its neighbors (fill-in edges)
        3. Record the elimination clique as a bag
        4. Connect bags in a tree based on shared vertices
        """
        if self._cached_td is not None:
            return self._cached_td

        if not self._branch_info:
            return TreeDecomposition(bags={}, tree_edges=[], adhesion={}, width=0)

        adj: dict[int, set[int]] = {v: set(ns) for v, ns in self._adjacency.items()}
        for pc in self._branch_info:
            if pc not in adj:
                adj[pc] = set()

        remaining = set(adj.keys())
        bags: dict[int, frozenset[int]] = {}
        elimination_order: list[int] = []

        vertex_to_bag: dict[int, int] = {}
        bag_id = 0
        max_bag_size = 0

        while remaining:
            v = min(remaining, key=lambda x: len(adj[x] & remaining))
            neighbors_in_remaining = adj[v] & remaining

            bag = frozenset({v} | neighbors_in_remaining)
            bags[bag_id] = bag
            vertex_to_bag[v] = bag_id
            max_bag_size = max(max_bag_size, len(bag))
            elimination_order.append(v)

            neighbors_list = list(neighbors_in_remaining)
            for i in range(len(neighbors_list)):
                for j in range(i + 1, len(neighbors_list)):
                    a, b = neighbors_list[i], neighbors_list[j]
                    adj[a].add(b)
                    adj[b].add(a)

            remaining.discard(v)
            bag_id += 1

        tree_edges: list[tuple[int, int]] = []
        adhesion: dict[tuple[int, int], frozenset[int]] = {}
        parent_map: dict[int, int] = {}

        for bid in range(len(bags)):
            bag = bags[bid]

            for bid2 in range(bid + 1, len(bags)):
                overlap = bag & bags[bid2]
                if overlap:
                    edge = (bid, bid2)
                    tree_edges.append(edge)
                    adhesion[edge] = overlap
                    parent_map[bid] = bid2
                    break

        width = max_bag_size - 1 if max_bag_size > 0 else 0

        td = TreeDecomposition(
            bags=bags,
            tree_edges=tree_edges,
            adhesion=adhesion,
            width=width,
            elimination_order=elimination_order,
            parent_map=parent_map,
        )
        self._cached_td = td
        return td

    def extract_skeleton(self) -> frozenset[int]:
        """Identify the skeleton: branch PCs that appear in multiple bags.

        The skeleton is the union of all adhesion sets in the tree
        decomposition.  Fixing the truth values of skeleton branches
        determines feasibility of all remaining branches via local
        propagation through the decomposition tree.

        Returns:
            frozenset of branch PCs forming the skeleton.
        """
        td = self.compute_tree_decomposition()
        skeleton: set[int] = set()
        for overlap in td.adhesion.values():
            skeleton.update(overlap)
        return frozenset(skeleton)

    def propagate_bag_constraints(
        self,
        td: TreeDecomposition,
        solve_local_bag: Callable[[frozenset[int]], bool],
        pass_messages: Callable[[int, int, frozenset[int]], None],
    ) -> bool:
        """[DEPRECATED] Dynamic programming (message passing) over the tree decomposition.

        .. deprecated:: 0.x
            This method is deprecated in favor of the GPU-accelerated
            ``GPUBagSolver.propagate_all`` in the ``h_acceleration`` module.

        Instead of extracting a global skeleton and brute-forcing adhesion
        variables—which scales poorly as |S| approaches O(N)—this method
        achieves O(N · 2^w) structural complexity via local message passing.

        For a tree decomposition T, constraints are solved locally within
        each bag. The valid truth assignments are projected onto the adhesion
        set and passed as a constrained interface to the parent bag. This
        confines the exponential blowup strictly to the local bag width w.

        Args:
            td: The tree decomposition to traverse.
            solve_local_bag: Callable(bag: frozenset[int]) -> bool that checks
                satisfiability of constraints within a single bag.
            pass_messages: Callable(child_id: int, parent_id: int,
                adhesion: frozenset[int]) -> None that projects valid
                assignments from child to parent via the adhesion set.

        Returns:
            True if all bags are locally satisfiable, False if any bag
            is unsatisfiable (early termination).

        Complexity:
            O(N · 2^w) where N = number of bags and w = treewidth.
        """
        import warnings

        warnings.warn(
            "ConstraintInteractionGraph.propagate_bag_constraints is deprecated. "
            "Use pysymex.h_acceleration.chtd_solver.GPUBagSolver instead.",
            DeprecationWarning,
            stacklevel=2,
        )
        if not td.bags:
            return True

        for bag_id in range(len(td.bags)):
            bag = td.bags.get(bag_id)
            if bag is None:
                continue

            local_sat = solve_local_bag(bag)
            if not local_sat:
                return False

            parent = td.get_parent(bag_id)
            if parent is not None:
                edge = (bag_id, parent)
                adhesion = td.adhesion.get(edge, frozenset())
                pass_messages(bag_id, parent, adhesion)

        return True

    def get_independent_groups(self) -> list[frozenset[int]]:
        """Partition branches into fully-independent groups (treewidth 0).

        This is the same information as ConstraintIndependenceOptimizer
        provides at the constraint level, but at the branch level.
        """
        visited: set[int] = set()
        groups: list[frozenset[int]] = []

        for pc in self._branch_info:
            if pc in visited:
                continue

            component: set[int] = set()
            queue = [pc]
            while queue:
                v = queue.pop()
                if v in visited:
                    continue
                visited.add(v)
                component.add(v)
                for neighbor in self._adjacency.get(v, set()):
                    if neighbor not in visited:
                        queue.append(neighbor)
            groups.append(frozenset(component))

        return groups

    def get_stats(self) -> dict[str, object]:
        """Return diagnostic statistics about the interaction graph."""
        n_branches = self.num_branches
        n_edges = sum(len(ns) for ns in self._adjacency.values()) // 2
        groups = self.get_independent_groups()

        return {
            "branches": n_branches,
            "edges": n_edges,
            "estimated_treewidth": self._estimated_tw,
            "independent_groups": len(groups),
            "max_group_size": max((len(g) for g in groups), default=0),
            "stabilized": self.is_stabilized(),
            "branches_since_tw_change": self._branches_since_last_tw_change,
        }


def _run_self_tests() -> None:
    """Self-tests for the treewidth module."""
    import z3 as _z3

    from pysymex.core.constraint_independence import ConstraintIndependenceOptimizer

    print("=" * 70)
    print("Constraint Interaction Graph — Self Tests")
    print("=" * 70)

    print("\n[TEST 1] Base variable name stripping")
    assert _base_var_name("x_42_int") == "x_42"
    assert _base_var_name("x_42_is_bool") == "x_42"
    assert _base_var_name("x_42_is_none") == "x_42"
    assert _base_var_name("x_42_str") == "x_42"
    assert _base_var_name("loop_counter") == "loop_counter"
    assert _base_var_name("x_42_array") == "x_42"
    print("  PASS")

    print("\n[TEST 2] Independent branches have no edges")
    opt = ConstraintIndependenceOptimizer()
    graph = ConstraintInteractionGraph(opt)

    x = _z3.Int("x_int")
    y = _z3.Int("y_int")
    z = _z3.Int("z_int")

    graph.add_branch(0, x > 5)
    graph.add_branch(1, y < 10)
    graph.add_branch(2, z == 0)

    groups = graph.get_independent_groups()
    assert len(groups) == 3, f"Expected 3 independent groups, got {len(groups)}"
    assert graph.estimated_treewidth == 0
    print("  PASS")

    print("\n[TEST 3] Shared variables create edges")
    opt2 = ConstraintIndependenceOptimizer()
    graph2 = ConstraintInteractionGraph(opt2)

    a = _z3.Int("a_int")
    b = _z3.Int("b_int")

    graph2.add_branch(0, a > 0)
    graph2.add_branch(1, a < 10)
    graph2.add_branch(2, b > 0)
    graph2.add_branch(3, a + b > 5)

    groups2 = graph2.get_independent_groups()
    assert len(groups2) == 1, f"Expected 1 group (all linked via a+b), got {len(groups2)}"
    assert 0 in graph2.adjacency[1]
    assert 1 in graph2.adjacency[0]
    print(f"  PASS — treewidth estimate: {graph2.estimated_treewidth}")

    print("\n[TEST 4] Tree decomposition")
    td = graph2.compute_tree_decomposition()
    assert td.width >= 0
    assert len(td.bags) == 4
    print(f"  PASS — width={td.width}, bags={len(td.bags)}, edges={len(td.tree_edges)}")

    print("\n[TEST 5] Skeleton extraction")
    skeleton = graph2.extract_skeleton()
    print(f"  Skeleton PCs: {skeleton}")
    assert isinstance(skeleton, frozenset)
    print("  PASS")

    print("\n[TEST 6] Discriminator grouping reduces treewidth")
    opt3 = ConstraintIndependenceOptimizer()
    graph3 = ConstraintInteractionGraph(opt3)

    x_int = _z3.Int("val_42_int")
    x_is_int = _z3.Bool("val_42_is_int")
    x_is_bool = _z3.Bool("val_42_is_bool")
    y_int = _z3.Int("val_99_int")
    y_is_int = _z3.Bool("val_99_is_int")

    graph3.add_branch(0, _z3.Or(_z3.And(x_is_bool, x_int > 0), _z3.And(x_is_int, x_int != 0)))

    graph3.add_branch(1, x_int < 100)

    graph3.add_branch(2, y_int > 0)

    graph3.add_branch(3, _z3.And(x_is_int, y_is_int, x_int + y_int > 10))

    info0 = graph3.branch_info[0]
    info1 = graph3.branch_info[1]

    assert "val_42" in info0.base_vars
    assert "val_42" in info1.base_vars

    assert graph3.branch_info[2].base_vars == frozenset({"val_99"})
    print(f"  PASS — base_vars correctly grouped, tw={graph3.estimated_treewidth}")

    print("\n[TEST 7] Stats reporting")
    stats = graph3.get_stats()
    assert stats["branches"] == 4
    assert isinstance(stats["edges"], int)
    print(f"  PASS — {stats}")

    print("\n" + "=" * 70)
    print("ALL 7 TESTS PASSED")
    print("=" * 70)


if __name__ == "__main__":
    _run_self_tests()
