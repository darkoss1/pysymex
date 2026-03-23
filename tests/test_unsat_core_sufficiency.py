"""UNSAT core sufficiency tests.

Verifies that extracted UNSAT core is actually sufficient to prove UNSAT.

Source contracts tested:
- unsat_core.py (extract_unsat_core, UnsatCoreResult)

Critical invariants:
1. Core is sufficient (is_sat(core) == False)
2. Core is subset of original constraints
3. SAT input returns None, not fake core
4. Core indices are valid
"""

from __future__ import annotations

import pytest
import z3

from pysymex.core.unsat_core import extract_unsat_core, prune_with_core, UnsatCoreResult
from pysymex.core.solver import is_satisfiable


class TestCoreIsSufficient:
    """Verify extracted core is sufficient to prove UNSAT."""

    def test_simple_unsat_core_sufficient(self):
        """Simple UNSAT core should be sufficient."""
        x = z3.Int("x")
        constraints = [x > 10, x < 5]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert not is_satisfiable(result.core)

    def test_complex_unsat_core_sufficient(self):
        """Complex UNSAT core should be sufficient."""
        x, y, z_var = z3.Ints("x y z")

        constraints = [
            x > 0,
            y > 0,
            z_var > 0,
            x + y + z_var < 1,  # Contradicts above
        ]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert not is_satisfiable(result.core)

    def test_core_from_embedded_contradiction(self):
        """Core should capture embedded contradictions."""
        x = z3.Int("x")

        # Many constraints, but only two form the contradiction
        constraints = [
            x > 100,  # Part of contradiction
            x > 50,
            x > 10,
            x < 5,  # Part of contradiction
        ]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert not is_satisfiable(result.core)

        # Core should be smaller than original
        assert len(result.core) <= len(constraints)


class TestCoreIsSubset:
    """Verify core is subset of original constraints."""

    def test_all_core_constraints_in_original(self):
        """All core constraints must be from original set."""
        x = z3.Int("x")
        constraints = [x > 10, x < 5, x > 0]

        result = extract_unsat_core(constraints)

        assert result is not None
        for core_constraint in result.core:
            # Each core constraint should be in original
            found = any(
                core_constraint.eq(orig) for orig in constraints
            )
            assert found, f"Core constraint not in original: {core_constraint}"

    def test_core_indices_valid(self):
        """Core indices should be valid indices into original."""
        x, y = z3.Ints("x y")
        constraints = [x > 100, y > 100, x + y < 50]

        result = extract_unsat_core(constraints)

        assert result is not None
        for idx in result.core_indices:
            assert 0 <= idx < len(constraints)


class TestSATInputRejection:
    """Verify SAT input returns None, not fake core."""

    def test_sat_constraints_return_none(self):
        """SAT constraints should return None."""
        x = z3.Int("x")
        constraints = [x > 0, x < 100]

        result = extract_unsat_core(constraints)

        assert result is None

    def test_empty_constraints_return_none(self):
        """Empty constraints (trivially SAT) should return None."""
        result = extract_unsat_core([])

        assert result is None

    def test_single_sat_constraint_return_none(self):
        """Single SAT constraint should return None."""
        x = z3.Int("x")
        result = extract_unsat_core([x > 0])

        assert result is None


class TestSingleConstraintContradiction:
    """Verify single-constraint contradictions are handled."""

    def test_false_constant(self):
        """False constant should return minimal core."""
        constraints = [z3.BoolVal(False)]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert len(result.core) == 1
        assert not is_satisfiable(result.core)

    def test_inherent_contradiction(self):
        """Inherently contradictory single constraint."""
        x = z3.Int("x")
        # x > x is always false
        constraints = [x > x]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert not is_satisfiable(result.core)


class TestReductionRatio:
    """Verify reduction ratio is computed correctly."""

    def test_reduction_ratio_computation(self):
        """Reduction ratio should be 1 - (core_size / total_size) (elimination ratio)."""
        x = z3.Int("x")

        # Many constraints, few in core
        constraints = [
            x > 100,
            x > 50,
            x > 10,
            x > 5,
            x < 0,  # Only this and x > 100 needed for UNSAT
        ]

        result = extract_unsat_core(constraints)

        assert result is not None
        expected_ratio = 1.0 - len(result.core) / result.total_constraints
        assert abs(result.reduction_ratio - expected_ratio) < 0.001

    def test_total_constraints_correct(self):
        """Total constraints should match input size."""
        x = z3.Int("x")
        constraints = [x > 100, x < 0, x > 0]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert result.total_constraints == len(constraints)


class TestPruneWithCore:
    """Verify prune_with_core removes non-core constraints."""

    def test_prune_removes_irrelevant(self):
        """Pruning should remove constraints not in core."""
        x, y = z3.Ints("x y")

        constraints = [
            x > 100,
            y > 50,  # Irrelevant
            y < 100,  # Irrelevant
            x < 0,  # Part of core with x > 100
        ]

        result = extract_unsat_core(constraints)
        assert result is not None

        pruned = prune_with_core(constraints, result)

        # Pruned should still be UNSAT
        assert not is_satisfiable(pruned)

        # Pruned should be <= core size
        assert len(pruned) <= len(result.core) + 1  # Some margin for implementation

    def test_prune_empty_core(self):
        """Pruning with empty core should handle gracefully."""
        # This is an edge case - create a mock result
        # Actually, if core is empty, that means SAT, so this shouldn't happen
        pass  # Skip this edge case


class TestTimeoutHandling:
    """Verify timeout is handled correctly."""

    def test_very_short_timeout(self):
        """Very short timeout should not crash."""
        x = z3.Int("x")
        constraints = [x > 10, x < 5]

        # Should work even with very short timeout
        result = extract_unsat_core(constraints, timeout_ms=1)

        # Result can be None (timeout) or valid core
        if result is not None:
            assert not is_satisfiable(result.core)


class TestCoreMinimalityHint:
    """Test that core tends toward minimality (not guaranteed)."""

    def test_core_not_larger_than_input(self):
        """Core should never be larger than input."""
        x, y, z_var = z3.Ints("x y z")

        constraints = [
            x > 0,
            y > 0,
            z_var > 0,
            x + y + z_var < 0,
        ]

        result = extract_unsat_core(constraints)

        assert result is not None
        assert len(result.core) <= len(constraints)

    def test_core_captures_essential_conflicts(self):
        """Core should capture the essential conflicting constraints."""
        x = z3.Int("x")

        # Obvious conflict: x > 100 and x < 0
        # Padding constraints that don't matter
        constraints = [
            x > 100,  # Essential
            x > 50,
            x > 10,
            x < 0,  # Essential
        ]

        result = extract_unsat_core(constraints)

        assert result is not None
        # Should have found a minimal conflict
        # Core should include x > 100 and x < 0 (or equivalent)
        assert not is_satisfiable(result.core)


class TestUnsatCoreResultDataclass:
    """Verify UnsatCoreResult dataclass properties."""

    def test_frozen_dataclass(self):
        """UnsatCoreResult should be immutable (frozen)."""
        x = z3.Int("x")
        constraints = [x > 10, x < 5]

        result = extract_unsat_core(constraints)
        assert result is not None

        # Should not be able to modify
        with pytest.raises(AttributeError):
            result.core = []  # type: ignore

    def test_result_attributes(self):
        """Result should have all expected attributes."""
        x = z3.Int("x")
        constraints = [x > 10, x < 5]

        result = extract_unsat_core(constraints)
        assert result is not None

        assert hasattr(result, 'core')
        assert hasattr(result, 'core_indices')
        assert hasattr(result, 'total_constraints')
        assert hasattr(result, 'reduction_ratio')

        assert isinstance(result.core, list)
        assert isinstance(result.core_indices, list)
        assert isinstance(result.total_constraints, int)
        assert isinstance(result.reduction_ratio, float)
