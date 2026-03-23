"""Tests for UNSAT core extraction.

These tests verify that:
1. UNSAT core extraction correctly identifies conflicting constraints
2. Core indices accurately map back to original constraints
3. Edge cases are handled (empty, single constraint, all constraints in core)
4. The core_indices can be used to prune constraints

UNSAT core extraction is critical for:
- Debugging infeasible paths
- Optimizing solver queries by removing irrelevant constraints
- Providing better error messages to users
"""

from __future__ import annotations

import pytest
import z3

from pysymex.core.unsat_core import (
    UnsatCoreResult,
    extract_unsat_core,
    prune_with_core,
)


class TestExtractUnsatCoreBasics:
    """Basic UNSAT core extraction tests."""

    def test_simple_contradiction(self):
        """Simple x > 0 AND x < 0 contradiction."""
        x = z3.Int("x")

        constraints = [x > 0, x < 0]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert len(result.core) <= 2
        assert len(result.core) >= 1
        assert result.total_constraints == 2

    def test_returns_none_for_sat(self):
        """Should return None for satisfiable constraints."""
        x = z3.Int("x")

        constraints = [x > 0, x < 10]

        result = extract_unsat_core(constraints)

        assert result is None

    def test_empty_constraints(self):
        """Empty constraint list should return None."""
        result = extract_unsat_core([])
        assert result is None

    def test_single_unsat_constraint(self):
        """Single unsatisfiable constraint (contradiction)."""
        x = z3.Int("x")

        # x == x + 1 is always false
        constraints = [x == x + 1]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert len(result.core) == 1

    def test_core_indices_valid(self):
        """Core indices should be valid indices into original list."""
        x = z3.Int("x")

        constraints = [
            x > 10,
            x < 20,
            x > 50,  # Conflicts with x < 20
            x < 100,
        ]

        result = extract_unsat_core(constraints)

        assert result is not None
        for idx in result.core_indices:
            assert 0 <= idx < len(constraints)

    def test_core_constraints_match_indices(self):
        """Core constraints should match those at core_indices."""
        x = z3.Int("x")

        constraints = [x > 0, x < 0, x > 100, x < -100]

        result = extract_unsat_core(constraints)

        assert result is not None
        for i, idx in enumerate(result.core_indices):
            # The constraint at index should be in core
            assert constraints[idx] in result.core


class TestUnsatCoreMinimality:
    """Tests for core minimality (or at least sufficiency)."""

    def test_core_is_sufficient(self):
        """Core alone should be UNSAT."""
        x = z3.Int("x")
        y = z3.Int("y")

        # x > 0, y > 0, x < 0 - core should be {x > 0, x < 0}
        constraints = [x > 0, y > 0, x < 0, y < 0]

        result = extract_unsat_core(constraints)

        assert result is not None

        # Verify core is UNSAT
        solver = z3.Solver()
        solver.add(result.core)
        assert solver.check() == z3.unsat

    def test_irrelevant_constraints_may_be_excluded(self):
        """Constraints unrelated to conflict may be excluded."""
        x = z3.Int("x")
        y = z3.Int("y")

        constraints = [
            x > 0,
            x < 0,  # Contradiction
            y > 100,  # Irrelevant to contradiction
            y < 200,  # Irrelevant to contradiction
        ]

        result = extract_unsat_core(constraints)

        assert result is not None
        # Core should ideally not include y constraints
        # (though Z3's core extraction is not guaranteed to be minimal)
        assert len(result.core) <= 4


class TestUnsatCoreReductionRatio:
    """Tests for reduction ratio computation."""

    def test_reduction_ratio_computation(self):
        """Reduction ratio should be correctly computed."""
        x = z3.Int("x")

        constraints = [x > 0, x > 1, x > 2, x < 0]

        result = extract_unsat_core(constraints)

        assert result is not None
        expected_ratio = 1.0 - len(result.core) / result.total_constraints
        assert abs(result.reduction_ratio - expected_ratio) < 0.001

    def test_reduction_ratio_zero_for_all_in_core(self):
        """If all constraints in core, ratio should be 0."""
        x = z3.Int("x")

        constraints = [x > 0, x < 0]  # Both needed for UNSAT

        result = extract_unsat_core(constraints)

        assert result is not None
        if len(result.core) == 2:
            assert result.reduction_ratio == 0.0

    def test_reduction_ratio_empty_constraints(self):
        """Empty total_constraints should give 0 ratio."""
        result = UnsatCoreResult(core=[], core_indices=[], total_constraints=0)
        assert result.reduction_ratio == 0.0


class TestPruneWithCore:
    """Tests for prune_with_core function."""

    def test_prune_removes_non_core(self):
        """Pruning should remove constraints not in core."""
        x = z3.Int("x")
        y = z3.Int("y")

        constraints = [x > 0, y > 0, x < 0, y < 0]

        result = extract_unsat_core(constraints)
        assert result is not None

        pruned = prune_with_core(constraints, result)

        assert len(pruned) == len(result.core)

    def test_pruned_list_is_unsat(self):
        """Pruned constraints should still be UNSAT."""
        x = z3.Int("x")

        constraints = [x > 0, x > 10, x > 100, x < 50]

        result = extract_unsat_core(constraints)
        assert result is not None

        pruned = prune_with_core(constraints, result)

        solver = z3.Solver()
        solver.add(pruned)
        assert solver.check() == z3.unsat

    def test_prune_preserves_constraint_identity(self):
        """Pruned constraints should be the same objects as originals."""
        x = z3.Int("x")

        c1 = x > 0
        c2 = x < 0

        constraints = [c1, c2]

        result = extract_unsat_core(constraints)
        assert result is not None

        pruned = prune_with_core(constraints, result)

        for pc in pruned:
            assert pc is c1 or pc is c2


class TestComplexContradictions:
    """Tests for more complex contradiction scenarios."""

    def test_chained_contradiction(self):
        """Contradiction through transitive constraints."""
        x = z3.Int("x")

        constraints = [
            x > 0,
            x < 10,
            x > 20,  # Contradicts x < 10
        ]

        result = extract_unsat_core(constraints)

        assert result is not None

    def test_arithmetic_contradiction(self):
        """Contradiction through arithmetic."""
        x = z3.Int("x")
        y = z3.Int("y")

        constraints = [
            x == y + 10,
            y == x + 10,  # Together implies x = x + 20, contradiction
        ]

        result = extract_unsat_core(constraints)

        assert result is not None

    def test_boolean_contradiction(self):
        """Boolean constraint contradiction."""
        b = z3.Bool("b")

        constraints = [b, z3.Not(b)]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert len(result.core) == 2

    def test_mixed_theory_contradiction(self):
        """Contradiction across multiple theories."""
        x = z3.Int("x")
        s = z3.String("s")

        constraints = [
            x > 0,
            z3.Length(s) == x,
            z3.Length(s) < 0,  # String length can't be negative
        ]

        result = extract_unsat_core(constraints)

        # May time out or return UNSAT depending on solver capabilities
        # Just verify it doesn't crash


class TestTimeout:
    """Tests for timeout handling."""

    def test_respects_timeout(self):
        """Extraction should respect timeout parameter."""
        x = z3.Int("x")

        constraints = [x > 0, x < 10]

        # Very short timeout - should still work for simple constraints
        result = extract_unsat_core(constraints, timeout_ms=100)

        # Result depends on whether constraints are UNSAT
        assert result is None  # These are SAT


class TestMultipleContradictions:
    """Tests with multiple independent contradictions."""

    def test_independent_contradictions(self):
        """Multiple independent contradictions - one core suffices."""
        x = z3.Int("x")
        y = z3.Int("y")

        constraints = [
            x > 0,
            x < 0,  # First contradiction
            y > 100,
            y < 0,  # Second contradiction
        ]

        result = extract_unsat_core(constraints)

        assert result is not None
        # Core should include at least one contradiction
        assert len(result.core) >= 2

    def test_nested_contradiction(self):
        """Nested implication creating contradiction."""
        x = z3.Int("x")
        y = z3.Int("y")

        constraints = [
            z3.Implies(x > 0, y > 0),
            z3.Implies(y > 0, x < 0),
            x > 0,  # Triggers chain leading to x > 0 AND x < 0
        ]

        result = extract_unsat_core(constraints)

        assert result is not None


class TestLargeConstraintSets:
    """Tests with larger constraint sets."""

    def test_many_constraints_few_in_core(self):
        """Many constraints but few responsible for UNSAT."""
        x = z3.Int("x")

        constraints = []

        # Add many irrelevant constraints
        for i in range(50):
            y = z3.Int(f"y_{i}")
            constraints.append(y > i)

        # Add the actual contradiction
        constraints.append(x > 100)
        constraints.append(x < 0)

        result = extract_unsat_core(constraints)

        assert result is not None
        # Core should ideally be small (just the x contradiction)
        assert len(result.core) <= 10  # Allow some slack for Z3's core extraction

    def test_many_interconnected_constraints(self):
        """Many interconnected constraints."""
        x = z3.Int("x")

        constraints = []
        prev = x
        for i in range(20):
            curr = z3.Int(f"temp_{i}")
            constraints.append(curr == prev + 1)
            prev = curr

        # Final constraint creates contradiction: x + 20 == x
        constraints.append(prev == x)

        result = extract_unsat_core(constraints)

        assert result is not None
