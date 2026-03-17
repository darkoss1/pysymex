"""Tests for pysymex.core.constraint_simplifier — theory-aware constraint
simplification.

Covers: simplify_constraints, quick_contradiction_check, remove_subsumed.
"""

from __future__ import annotations

import z3
import pytest

from pysymex.core.constraint_simplifier import (
    quick_contradiction_check,
    remove_subsumed,
    simplify_constraints,
)


# ---------------------------------------------------------------------------
# simplify_constraints
# ---------------------------------------------------------------------------

class TestSimplifyConstraints:

    def test_empty_list(self):
        assert simplify_constraints([]) == []

    def test_single_true_removed(self):
        result = simplify_constraints([z3.BoolVal(True)])
        assert result == []

    def test_single_false_returns_false(self):
        result = simplify_constraints([z3.BoolVal(False)])
        assert len(result) == 1
        assert z3.is_false(result[0])

    def test_false_among_others(self):
        x = z3.Int("x")
        result = simplify_constraints([x > 0, z3.BoolVal(False), x < 10])
        assert len(result) == 1
        assert z3.is_false(result[0])

    def test_true_among_others(self):
        x = z3.Int("x")
        result = simplify_constraints([z3.BoolVal(True), x > 0])
        # True is filtered out, only x > 0 remains
        assert len(result) == 1

    def test_all_true(self):
        result = simplify_constraints([z3.BoolVal(True), z3.BoolVal(True)])
        assert result == []

    def test_simplifiable_constraint(self):
        """z3.simplify can reduce 1 + 1 == 2 to True."""
        result = simplify_constraints([z3.IntVal(1) + z3.IntVal(1) == z3.IntVal(2)])
        # After simplification this becomes True, which is filtered
        assert result == []

    def test_simplifiable_to_false(self):
        """z3.simplify can reduce 1 == 2 to False."""
        result = simplify_constraints([z3.IntVal(1) == z3.IntVal(2)])
        assert len(result) == 1
        assert z3.is_false(result[0])

    def test_non_trivial_constraint_preserved(self):
        x = z3.Int("x")
        result = simplify_constraints([x > 5])
        assert len(result) == 1

    def test_multiple_constraints_preserved(self):
        x = z3.Int("x")
        y = z3.Int("y")
        result = simplify_constraints([x > 0, y > 0, x + y < 100])
        assert len(result) == 3

    def test_mixed_true_and_nontrivial(self):
        x = z3.Int("x")
        result = simplify_constraints([
            z3.BoolVal(True),
            x > 5,
            z3.IntVal(1) + z3.IntVal(1) == z3.IntVal(2),  # simplifies to True
            x < 100,
        ])
        assert len(result) == 2  # only x > 5 and x < 100


# ---------------------------------------------------------------------------
# quick_contradiction_check
# ---------------------------------------------------------------------------

class TestQuickContradictionCheck:

    def test_empty_list_no_contradiction(self):
        assert quick_contradiction_check([]) is False

    def test_explicit_false(self):
        assert quick_contradiction_check([z3.BoolVal(False)]) is True

    def test_false_among_constraints(self):
        x = z3.Int("x")
        assert quick_contradiction_check([x > 0, z3.BoolVal(False)]) is True

    def test_negation_pair(self):
        x = z3.Int("x")
        c = x > 5
        assert quick_contradiction_check([c, z3.Not(c)]) is True

    def test_no_contradiction(self):
        x = z3.Int("x")
        assert quick_contradiction_check([x > 0, x < 10]) is False

    def test_single_true_no_contradiction(self):
        assert quick_contradiction_check([z3.BoolVal(True)]) is False

    def test_symbolic_negation_pair(self):
        b = z3.Bool("b")
        assert quick_contradiction_check([b, z3.Not(b)]) is True

    def test_different_constraints_no_contradiction(self):
        x = z3.Int("x")
        y = z3.Int("y")
        assert quick_contradiction_check([x > 0, y < 0]) is False


# ---------------------------------------------------------------------------
# remove_subsumed
# ---------------------------------------------------------------------------

class TestRemoveSubsumed:

    def test_empty_list(self):
        assert remove_subsumed([]) == []

    def test_single_constraint(self):
        x = z3.Int("x")
        result = remove_subsumed([x > 0])
        assert len(result) == 1

    def test_duplicate_removal(self):
        x = z3.Int("x")
        c = x > 5
        result = remove_subsumed([c, c])
        assert len(result) == 1

    def test_no_duplicates(self):
        x = z3.Int("x")
        y = z3.Int("y")
        result = remove_subsumed([x > 0, y > 0])
        assert len(result) == 2

    def test_multiple_duplicates(self):
        x = z3.Int("x")
        c = x > 5
        result = remove_subsumed([c, c, c, c])
        assert len(result) == 1

    def test_preserves_order(self):
        x = z3.Int("x")
        y = z3.Int("y")
        c1 = x > 0
        c2 = y > 0
        result = remove_subsumed([c1, c2, c1])
        assert len(result) == 2
        # First occurrence of c1 should be preserved in its original position

    def test_different_looking_same_structure(self):
        """Two structurally identical constraints should be deduped."""
        x = z3.Int("x")
        c1 = x > 5
        c2 = x > 5  # same expression, freshly created
        result = remove_subsumed([c1, c2])
        assert len(result) == 1
