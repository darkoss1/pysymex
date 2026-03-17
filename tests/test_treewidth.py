"""Tests for pysymex.core.treewidth — Constraint Interaction Graph and
Tree Decomposition.

Covers: _base_var_name, BranchInfo, ConstraintInteractionGraph (add_branch,
compute_tree_decomposition, extract_skeleton, get_independent_groups,
is_stabilized, reset, get_stats), and TreeDecomposition structure.
"""

from __future__ import annotations

import z3
import pytest

from pysymex.core.constraint_independence import ConstraintIndependenceOptimizer
from pysymex.core.treewidth import (
    BranchInfo,
    ConstraintInteractionGraph,
    TreeDecomposition,
    _base_var_name,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_graph() -> ConstraintInteractionGraph:
    """Create a fresh graph backed by a fresh optimizer."""
    return ConstraintInteractionGraph(ConstraintIndependenceOptimizer())


# ---------------------------------------------------------------------------
# _base_var_name
# ---------------------------------------------------------------------------

class TestBaseVarName:

    def test_strip_int_suffix(self):
        assert _base_var_name("x_42_int") == "x_42"

    def test_strip_bool_suffix(self):
        assert _base_var_name("x_42_bool") == "x_42"

    def test_strip_is_bool_suffix(self):
        assert _base_var_name("x_42_is_bool") == "x_42"

    def test_strip_is_int_suffix(self):
        assert _base_var_name("x_42_is_int") == "x_42"

    def test_strip_is_none_suffix(self):
        assert _base_var_name("x_42_is_none") == "x_42"

    def test_strip_str_suffix(self):
        assert _base_var_name("x_42_str") == "x_42"

    def test_strip_is_str_suffix(self):
        assert _base_var_name("x_42_is_str") == "x_42"

    def test_strip_float_suffix(self):
        assert _base_var_name("x_42_float") == "x_42"

    def test_strip_addr_suffix(self):
        assert _base_var_name("x_42_addr") == "x_42"

    def test_strip_array_suffix(self):
        assert _base_var_name("x_42_array") == "x_42"

    def test_strip_len_suffix(self):
        assert _base_var_name("x_42_len") == "x_42"

    def test_strip_is_list_suffix(self):
        assert _base_var_name("x_42_is_list") == "x_42"

    def test_strip_is_dict_suffix(self):
        assert _base_var_name("x_42_is_dict") == "x_42"

    def test_no_suffix_unchanged(self):
        assert _base_var_name("loop_counter") == "loop_counter"

    def test_empty_string(self):
        assert _base_var_name("") == ""

    def test_longest_match_first(self):
        """'_is_bool' should match before '_bool'."""
        assert _base_var_name("v_is_bool") == "v"


# ---------------------------------------------------------------------------
# BranchInfo dataclass
# ---------------------------------------------------------------------------

class TestBranchInfo:

    def test_basic_fields(self):
        info = BranchInfo(pc=10, raw_vars=frozenset({"a_int"}), base_vars=frozenset({"a"}))
        assert info.pc == 10
        assert "a_int" in info.raw_vars
        assert "a" in info.base_vars

    def test_empty_vars(self):
        info = BranchInfo(pc=0, raw_vars=frozenset(), base_vars=frozenset())
        assert len(info.raw_vars) == 0
        assert len(info.base_vars) == 0


# ---------------------------------------------------------------------------
# ConstraintInteractionGraph — add_branch
# ---------------------------------------------------------------------------

class TestAddBranch:

    def test_single_branch(self):
        g = _make_graph()
        x = z3.Int("x_int")
        info = g.add_branch(0, x > 5)
        assert info.pc == 0
        assert "x" in info.base_vars
        assert g.num_branches == 1

    def test_duplicate_pc_returns_existing(self):
        g = _make_graph()
        x = z3.Int("x_int")
        info1 = g.add_branch(0, x > 5)
        info2 = g.add_branch(0, x < 10)  # same pc, different condition
        assert info1 is info2

    def test_shared_variable_creates_edge(self):
        g = _make_graph()
        a = z3.Int("a_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a < 10)
        assert 1 in g._adjacency[0]
        assert 0 in g._adjacency[1]

    def test_independent_branches_no_edge(self):
        g = _make_graph()
        x = z3.Int("x_int")
        y = z3.Int("y_int")
        g.add_branch(0, x > 0)
        g.add_branch(1, y > 0)
        assert 1 not in g._adjacency.get(0, set())
        assert 0 not in g._adjacency.get(1, set())

    def test_transitive_edge_via_shared_variable(self):
        g = _make_graph()
        a = z3.Int("a_int")
        b = z3.Int("b_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a + b > 5)
        g.add_branch(2, b < 10)
        # 0 and 1 share 'a', 1 and 2 share 'b'
        assert 1 in g._adjacency[0]
        assert 2 in g._adjacency[1]

    def test_base_var_grouping(self):
        """Discriminator vars for the same SymbolicValue merge into one base var."""
        g = _make_graph()
        x_int = z3.Int("val_42_int")
        x_is_int = z3.Bool("val_42_is_int")
        g.add_branch(0, z3.And(x_is_int, x_int > 0))
        g.add_branch(1, x_int < 100)
        info0 = g._branch_info[0]
        info1 = g._branch_info[1]
        assert "val_42" in info0.base_vars
        assert "val_42" in info1.base_vars
        # They should be connected
        assert 1 in g._adjacency[0]


# ---------------------------------------------------------------------------
# num_branches / estimated_treewidth
# ---------------------------------------------------------------------------

class TestProperties:

    def test_num_branches_empty(self):
        g = _make_graph()
        assert g.num_branches == 0

    def test_num_branches_after_adds(self):
        g = _make_graph()
        for i in range(5):
            v = z3.Int(f"v{i}_int")
            g.add_branch(i, v > 0)
        assert g.num_branches == 5

    def test_estimated_treewidth_independent(self):
        g = _make_graph()
        x = z3.Int("x_int")
        y = z3.Int("y_int")
        g.add_branch(0, x > 0)
        g.add_branch(1, y > 0)
        assert g.estimated_treewidth == 0

    def test_estimated_treewidth_chain(self):
        g = _make_graph()
        a = z3.Int("a_int")
        b = z3.Int("b_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a < 10)
        g.add_branch(2, a + b > 5)
        assert g.estimated_treewidth >= 1


# ---------------------------------------------------------------------------
# reset
# ---------------------------------------------------------------------------

class TestReset:

    def test_reset_clears_everything(self):
        g = _make_graph()
        x = z3.Int("x_int")
        g.add_branch(0, x > 0)
        g.add_branch(1, x < 10)
        g.reset()
        assert g.num_branches == 0
        assert g.estimated_treewidth == 0
        assert len(g._adjacency) == 0
        assert len(g._var_branches) == 0


# ---------------------------------------------------------------------------
# is_stabilized
# ---------------------------------------------------------------------------

class TestIsStabilized:

    def test_not_stabilized_too_few_branches(self):
        g = _make_graph()
        for i in range(3):
            v = z3.Int(f"ind{i}_int")
            g.add_branch(i, v > 0)
        assert not g.is_stabilized(min_branches=6)

    def test_stabilized_enough_branches_no_tw_change(self):
        g = _make_graph()
        # Add enough independent branches so tw stays at 0
        for i in range(12):
            v = z3.Int(f"ind{i}_int")
            g.add_branch(i, v > 0)
        # All independent -> tw=0, no changes for many consecutive adds
        assert g.is_stabilized(stability_threshold=4, min_branches=6, max_useful_treewidth=15)

    def test_not_stabilized_high_treewidth(self):
        g = _make_graph()
        # Create a clique — high treewidth
        shared = z3.Int("shared_int")
        for i in range(8):
            g.add_branch(i, shared > z3.IntVal(i))
        # Even if it is stabilized count-wise, tw could exceed max
        result = g.is_stabilized(stability_threshold=0, min_branches=1, max_useful_treewidth=0)
        assert not result


# ---------------------------------------------------------------------------
# compute_tree_decomposition
# ---------------------------------------------------------------------------

class TestTreeDecomposition:

    def test_empty_graph(self):
        g = _make_graph()
        td = g.compute_tree_decomposition()
        assert td.bags == {}
        assert td.tree_edges == []
        assert td.adhesion == {}
        assert td.width == 0

    def test_single_branch(self):
        g = _make_graph()
        x = z3.Int("x_int")
        g.add_branch(0, x > 0)
        td = g.compute_tree_decomposition()
        assert len(td.bags) == 1
        assert td.width == 0  # single vertex bag size 1, width = 1-1 = 0

    def test_two_connected_branches(self):
        g = _make_graph()
        a = z3.Int("a_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a < 10)
        td = g.compute_tree_decomposition()
        assert len(td.bags) == 2
        assert td.width >= 1  # bag contains both, width = 2-1 = 1

    def test_bags_cover_all_branches(self):
        g = _make_graph()
        a = z3.Int("a_int")
        b = z3.Int("b_int")
        for i in range(4):
            g.add_branch(i, a + b > z3.IntVal(i))
        td = g.compute_tree_decomposition()
        all_vertices = set()
        for bag in td.bags.values():
            all_vertices.update(bag)
        assert all_vertices == {0, 1, 2, 3}

    def test_elimination_order_length(self):
        g = _make_graph()
        a = z3.Int("a_int")
        for i in range(5):
            g.add_branch(i, a > z3.IntVal(i))
        td = g.compute_tree_decomposition()
        assert len(td.elimination_order) == 5

    def test_tree_edges_form_tree(self):
        """A tree on n bags has at most n-1 edges."""
        g = _make_graph()
        a = z3.Int("a_int")
        b = z3.Int("b_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a < 10)
        g.add_branch(2, b > 0)
        g.add_branch(3, a + b > 5)
        td = g.compute_tree_decomposition()
        assert len(td.tree_edges) <= len(td.bags) - 1

    def test_adhesion_sets_are_subsets_of_adjacent_bags(self):
        g = _make_graph()
        a = z3.Int("a_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a < 10)
        g.add_branch(2, a > 5)
        td = g.compute_tree_decomposition()
        for (bid1, bid2), overlap in td.adhesion.items():
            assert overlap <= td.bags[bid1]
            assert overlap <= td.bags[bid2]

    def test_width_is_max_bag_minus_one(self):
        g = _make_graph()
        a = z3.Int("a_int")
        for i in range(3):
            g.add_branch(i, a > z3.IntVal(i))
        td = g.compute_tree_decomposition()
        max_bag = max(len(bag) for bag in td.bags.values())
        assert td.width == max_bag - 1


# ---------------------------------------------------------------------------
# extract_skeleton
# ---------------------------------------------------------------------------

class TestExtractSkeleton:

    def test_independent_branches_empty_skeleton(self):
        g = _make_graph()
        x = z3.Int("x_int")
        y = z3.Int("y_int")
        g.add_branch(0, x > 0)
        g.add_branch(1, y > 0)
        skeleton = g.extract_skeleton()
        # Independent branches -> no adhesion sets -> empty skeleton
        assert skeleton == frozenset()

    def test_connected_branches_nonempty_skeleton(self):
        g = _make_graph()
        a = z3.Int("a_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a < 10)
        g.add_branch(2, a > 5)
        skeleton = g.extract_skeleton()
        assert isinstance(skeleton, frozenset)
        # With overlapping bags, skeleton should have some entries
        assert len(skeleton) >= 1

    def test_skeleton_returns_frozenset(self):
        g = _make_graph()
        x = z3.Int("x_int")
        g.add_branch(0, x > 0)
        skeleton = g.extract_skeleton()
        assert isinstance(skeleton, frozenset)

    def test_empty_graph_skeleton(self):
        g = _make_graph()
        skeleton = g.extract_skeleton()
        assert skeleton == frozenset()


# ---------------------------------------------------------------------------
# get_independent_groups
# ---------------------------------------------------------------------------

class TestGetIndependentGroups:

    def test_all_independent(self):
        g = _make_graph()
        x = z3.Int("x_int")
        y = z3.Int("y_int")
        z_var = z3.Int("z_int")
        g.add_branch(0, x > 0)
        g.add_branch(1, y > 0)
        g.add_branch(2, z_var > 0)
        groups = g.get_independent_groups()
        assert len(groups) == 3

    def test_single_connected_component(self):
        g = _make_graph()
        a = z3.Int("a_int")
        b = z3.Int("b_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a < 10)
        g.add_branch(2, b > 0)
        g.add_branch(3, a + b > 5)
        groups = g.get_independent_groups()
        assert len(groups) == 1
        assert groups[0] == frozenset({0, 1, 2, 3})

    def test_two_components(self):
        g = _make_graph()
        a = z3.Int("a_int")
        b = z3.Int("b_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a < 10)
        g.add_branch(2, b > 0)
        g.add_branch(3, b < 10)
        groups = g.get_independent_groups()
        assert len(groups) == 2
        pcs_in_groups = {frozenset(g) for g in groups}
        assert frozenset({0, 1}) in pcs_in_groups
        assert frozenset({2, 3}) in pcs_in_groups

    def test_empty_graph(self):
        g = _make_graph()
        groups = g.get_independent_groups()
        assert groups == []


# ---------------------------------------------------------------------------
# get_stats
# ---------------------------------------------------------------------------

class TestGetStats:

    def test_stats_keys(self):
        g = _make_graph()
        stats = g.get_stats()
        expected_keys = {
            "branches", "edges", "estimated_treewidth",
            "independent_groups", "max_group_size", "stabilized",
            "branches_since_tw_change",
        }
        assert set(stats.keys()) == expected_keys

    def test_stats_values_empty(self):
        g = _make_graph()
        stats = g.get_stats()
        assert stats["branches"] == 0
        assert stats["edges"] == 0
        assert stats["estimated_treewidth"] == 0
        assert stats["independent_groups"] == 0
        assert stats["max_group_size"] == 0

    def test_stats_values_with_branches(self):
        g = _make_graph()
        a = z3.Int("a_int")
        g.add_branch(0, a > 0)
        g.add_branch(1, a < 10)
        stats = g.get_stats()
        assert stats["branches"] == 2
        assert stats["edges"] == 1
        assert stats["independent_groups"] == 1
        assert stats["max_group_size"] == 2
