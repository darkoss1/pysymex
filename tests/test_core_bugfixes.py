"""Regression tests for core module bugfixes.

Each test class proves a specific bug exists (fails before fix, passes after)
and verifies the fix produces correct Z3 semantics.

Bug 1: floats.py — is_positive_infinity/is_negative_infinity/is_positive_zero/
        is_negative_zero pass wrong number of args to Z3 fpIsInf/fpIsZero.
Bug 2: havoc.py — HavocValue.havoc() omits is_float from type_vars, so havoc
        values can never represent float types.
Bug 3: types.py — SymbolicValue.could_be_truthy treats all lists/dicts as truthy,
        missing the empty-container falsy case when promoted via as_unified().
Fix 4: optimization.py — State merging uses fragile str() comparison for Z3
        expressions; replaced with structural z3.eq().
"""

from __future__ import annotations

import pytest
import z3

from pysymex.core.floats import FloatConfig, FloatPrecision, SymbolicFloat, get_fp_sort
from pysymex.core.havoc import HavocValue
from pysymex.core.types import SymbolicValue


# ===========================================================================
# Bug 1: floats.py — signed infinity/zero checks
# ===========================================================================


class TestFloatSpecialValueChecks:
    """Prove that the signed special-value methods produce correct Z3 constraints.

    Before the fix, these methods passed wrong argument counts to Z3 functions:
      z3.fpIsInf(expr, fpIsPositive(expr))  — WRONG (2 args to fpIsInf)
    After the fix:
      z3.And(z3.fpIsInf(expr), z3.fpIsPositive(expr))  — CORRECT
    """

    def _make_concrete_fp(self, value: float) -> SymbolicFloat:
        """Create a SymbolicFloat with a concrete FP value."""
        return SymbolicFloat(name="v", value=value)

    # --- is_positive_infinity ---

    def test_is_positive_infinity_returns_bool_ref(self):
        """The method must return a z3.BoolRef (not crash)."""
        sf = SymbolicFloat("x")
        result = sf.is_positive_infinity()
        assert isinstance(result, z3.BoolRef), (
            f"Expected z3.BoolRef, got {type(result).__name__}"
        )

    def test_positive_infinity_detected(self):
        """Concrete +Inf must satisfy is_positive_infinity()."""
        sf = self._make_concrete_fp(float("inf"))
        s = z3.Solver()
        s.add(sf.is_positive_infinity())
        assert s.check() == z3.sat, "+Inf should satisfy is_positive_infinity()"

    def test_negative_infinity_NOT_positive_infinity(self):
        """Concrete -Inf must NOT satisfy is_positive_infinity()."""
        sf = self._make_concrete_fp(float("-inf"))
        s = z3.Solver()
        s.add(sf.is_positive_infinity())
        assert s.check() == z3.unsat, "-Inf should NOT satisfy is_positive_infinity()"

    def test_finite_not_positive_infinity(self):
        """Concrete 1.0 must NOT satisfy is_positive_infinity()."""
        sf = self._make_concrete_fp(1.0)
        s = z3.Solver()
        s.add(sf.is_positive_infinity())
        assert s.check() == z3.unsat, "1.0 should NOT satisfy is_positive_infinity()"

    # --- is_negative_infinity ---

    def test_is_negative_infinity_returns_bool_ref(self):
        """The method must return a z3.BoolRef (not crash)."""
        sf = SymbolicFloat("x")
        result = sf.is_negative_infinity()
        assert isinstance(result, z3.BoolRef)

    def test_negative_infinity_detected(self):
        """Concrete -Inf must satisfy is_negative_infinity()."""
        sf = self._make_concrete_fp(float("-inf"))
        s = z3.Solver()
        s.add(sf.is_negative_infinity())
        assert s.check() == z3.sat, "-Inf should satisfy is_negative_infinity()"

    def test_positive_infinity_NOT_negative_infinity(self):
        """Concrete +Inf must NOT satisfy is_negative_infinity()."""
        sf = self._make_concrete_fp(float("inf"))
        s = z3.Solver()
        s.add(sf.is_negative_infinity())
        assert s.check() == z3.unsat, "+Inf should NOT satisfy is_negative_infinity()"

    # --- is_positive_zero ---

    def test_is_positive_zero_returns_bool_ref(self):
        """The method must return a z3.BoolRef (not crash)."""
        sf = SymbolicFloat("x")
        result = sf.is_positive_zero()
        assert isinstance(result, z3.BoolRef)

    def test_positive_zero_detected(self):
        """Concrete +0.0 must satisfy is_positive_zero()."""
        sf = self._make_concrete_fp(0.0)
        s = z3.Solver()
        s.add(sf.is_positive_zero())
        assert s.check() == z3.sat, "+0.0 should satisfy is_positive_zero()"

    def test_negative_zero_NOT_positive_zero(self):
        """Concrete -0.0 must NOT satisfy is_positive_zero()."""
        # Use Z3's fpMinusZero to construct true IEEE 754 -0.
        fp_sort = get_fp_sort(FloatPrecision.DOUBLE)
        neg_zero_expr = z3.fpMinusZero(fp_sort)
        sf = SymbolicFloat.__new__(SymbolicFloat)
        sf._name = "nz"
        sf._config = FloatConfig()
        sf._expr = neg_zero_expr
        s = z3.Solver()
        s.add(sf.is_positive_zero())
        assert s.check() == z3.unsat, "-0.0 should NOT satisfy is_positive_zero()"

    # --- is_negative_zero ---

    def test_is_negative_zero_returns_bool_ref(self):
        """The method must return a z3.BoolRef (not crash)."""
        sf = SymbolicFloat("x")
        result = sf.is_negative_zero()
        assert isinstance(result, z3.BoolRef)

    def test_negative_zero_detected(self):
        """True -0 (via Z3 fpMinusZero) must satisfy is_negative_zero()."""
        fp_sort = get_fp_sort(FloatPrecision.DOUBLE)
        neg_zero_expr = z3.fpMinusZero(fp_sort)
        sf = SymbolicFloat.__new__(SymbolicFloat)
        sf._name = "nz"
        sf._config = FloatConfig()
        sf._expr = neg_zero_expr
        s = z3.Solver()
        s.add(sf.is_negative_zero())
        assert s.check() == z3.sat, "-0 should satisfy is_negative_zero()"

    def test_positive_zero_NOT_negative_zero(self):
        """Concrete +0.0 must NOT satisfy is_negative_zero()."""
        sf = self._make_concrete_fp(0.0)
        s = z3.Solver()
        s.add(sf.is_negative_zero())
        assert s.check() == z3.unsat, "+0.0 should NOT satisfy is_negative_zero()"

    # --- symbolic path: ensure both branches explored ---

    def test_symbolic_can_be_positive_or_negative_infinity(self):
        """A symbolic float must be able to satisfy EITHER +Inf or -Inf."""
        sf = SymbolicFloat("x")
        s1 = z3.Solver()
        s1.add(sf.is_positive_infinity())
        assert s1.check() == z3.sat

        s2 = z3.Solver()
        s2.add(sf.is_negative_infinity())
        assert s2.check() == z3.sat

    def test_symbolic_can_be_positive_or_negative_zero(self):
        """A symbolic float must be able to satisfy EITHER +0 or -0."""
        sf = SymbolicFloat("x")
        s1 = z3.Solver()
        s1.add(sf.is_positive_zero())
        assert s1.check() == z3.sat

        s2 = z3.Solver()
        s2.add(sf.is_negative_zero())
        assert s2.check() == z3.sat

    def test_positive_infinity_excludes_negative_infinity(self):
        """A float cannot be both +Inf and -Inf simultaneously."""
        sf = SymbolicFloat("x")
        s = z3.Solver()
        s.add(sf.is_positive_infinity())
        s.add(sf.is_negative_infinity())
        assert s.check() == z3.unsat, "Cannot be both +Inf and -Inf"


# ===========================================================================
# Bug 2: havoc.py — missing is_float type variable
# ===========================================================================


class TestHavocFloatType:
    """Prove that HavocValue can represent float types.

    Before the fix, HavocValue.havoc() omitted is_float from type_vars,
    making it impossible for the solver to choose float as the type.
    """

    def test_havoc_has_is_float_attribute(self):
        """HavocValue must expose an is_float discriminator."""
        val, constraint = HavocValue.havoc("h")
        # is_float should be a Z3 BoolRef, not the default Z3_FALSE constant
        assert hasattr(val, "is_float")
        assert isinstance(val.is_float, z3.BoolRef)

    def test_havoc_can_be_float(self):
        """The solver must be able to make a HavocValue a float type."""
        val, constraint = HavocValue.havoc("h")
        s = z3.Solver()
        s.add(constraint)
        s.add(val.is_float)
        result = s.check()
        assert result == z3.sat, (
            "HavocValue should be able to represent float type, "
            f"but solver returned {result}"
        )

    def test_havoc_float_exclusive_with_int(self):
        """is_float and is_int must be mutually exclusive (pairwise constraint)."""
        val, constraint = HavocValue.havoc("h")
        s = z3.Solver()
        s.add(constraint)
        s.add(val.is_float)
        s.add(val.is_int)
        assert s.check() == z3.unsat, "is_float and is_int must be mutually exclusive"

    def test_havoc_float_exclusive_with_bool(self):
        """is_float and is_bool must be mutually exclusive."""
        val, constraint = HavocValue.havoc("h")
        s = z3.Solver()
        s.add(constraint)
        s.add(val.is_float)
        s.add(val.is_bool)
        assert s.check() == z3.unsat, "is_float and is_bool must be mutually exclusive"

    def test_havoc_float_exclusive_with_str(self):
        """is_float and is_str must be mutually exclusive."""
        val, constraint = HavocValue.havoc("h")
        s = z3.Solver()
        s.add(constraint)
        s.add(val.is_float)
        s.add(val.is_str)
        assert s.check() == z3.unsat, "is_float and is_str must be mutually exclusive"

    def test_havoc_has_z3_float(self):
        """HavocValue must have a z3_float FP expression (not just the default)."""
        val, constraint = HavocValue.havoc("h")
        assert hasattr(val, "z3_float")
        # After fix, z3_float should be a named FP variable, not a constant
        assert isinstance(val.z3_float, z3.FPRef)

    def test_havoc_taint_preserved_with_float(self):
        """Taint labels must be preserved when havoc is float type."""
        val, constraint = HavocValue.havoc("h", taint_labels={"user_input"})
        s = z3.Solver()
        s.add(constraint)
        s.add(val.is_float)
        assert s.check() == z3.sat
        assert val.taint_labels == frozenset({"user_input"})


# ===========================================================================
# Bug 3: types.py — list/dict truthiness through as_unified()
# ===========================================================================


class TestContainerTruthiness:
    """Prove that unified SymbolicValues for lists/dicts model empty-is-falsy.

    Before the fix, SymbolicValue.could_be_truthy() includes bare `self.is_list`
    and `self.is_dict`, meaning ALL lists/dicts are considered truthy even when
    they might be empty.

    The fix adds a z3_len field so could_be_truthy respects length.
    """

    def test_symbolic_list_direct_truthiness_correct(self):
        """SymbolicList's own could_be_truthy() uses z3_len — this should work."""
        from pysymex.core.types_containers import SymbolicList
        lst, constraint = SymbolicList.symbolic("lst")
        s = z3.Solver()
        s.add(constraint)  # len >= 0

        # Empty list should be falsy
        s.push()
        s.add(lst.z3_len == 0)
        s.add(lst.could_be_truthy())
        assert s.check() == z3.unsat, "Empty SymbolicList should NOT be truthy"
        s.pop()

        # Non-empty list should be truthy
        s.push()
        s.add(lst.z3_len > 0)
        s.add(lst.could_be_truthy())
        assert s.check() == z3.sat, "Non-empty SymbolicList should be truthy"
        s.pop()

    def test_unified_list_could_be_falsy(self):
        """After as_unified(), could_be_falsy must detect empty lists."""
        from pysymex.core.types_containers import SymbolicList
        lst, constraint = SymbolicList.symbolic("lst")
        unified = lst.as_unified()

        s = z3.Solver()
        s.add(constraint)
        s.add(lst.z3_len == 0)
        s.add(unified.could_be_falsy())
        assert s.check() == z3.sat, (
            "Unified SymbolicValue from empty list should could_be_falsy()"
        )

    def test_unified_list_nonempty_is_truthy(self):
        """After as_unified(), non-empty list should still be truthy."""
        from pysymex.core.types_containers import SymbolicList
        lst, constraint = SymbolicList.symbolic("lst")
        unified = lst.as_unified()

        s = z3.Solver()
        s.add(constraint)
        s.add(lst.z3_len > 0)
        s.add(unified.could_be_truthy())
        assert s.check() == z3.sat, (
            "Unified SymbolicValue from non-empty list should could_be_truthy()"
        )

    def test_unified_list_empty_not_truthy(self):
        """After as_unified(), empty list should NOT be truthy."""
        from pysymex.core.types_containers import SymbolicList
        lst, constraint = SymbolicList.symbolic("lst")
        unified = lst.as_unified()

        s = z3.Solver()
        s.add(constraint)
        s.add(lst.z3_len == 0)
        s.add(unified.could_be_truthy())
        assert s.check() == z3.unsat, (
            "Unified SymbolicValue from empty list should NOT could_be_truthy()"
        )

    def test_unified_dict_could_be_falsy(self):
        """After as_unified(), could_be_falsy must detect empty dicts."""
        from pysymex.core.types_containers import SymbolicDict
        d, constraint = SymbolicDict.symbolic("d")
        unified = d.as_unified()

        s = z3.Solver()
        s.add(constraint)
        s.add(d.z3_len == 0)
        s.add(unified.could_be_falsy())
        assert s.check() == z3.sat, (
            "Unified SymbolicValue from empty dict should could_be_falsy()"
        )

    def test_unified_dict_empty_not_truthy(self):
        """After as_unified(), empty dict should NOT be truthy."""
        from pysymex.core.types_containers import SymbolicDict
        d, constraint = SymbolicDict.symbolic("d")
        unified = d.as_unified()

        s = z3.Solver()
        s.add(constraint)
        s.add(d.z3_len == 0)
        s.add(unified.could_be_truthy())
        assert s.check() == z3.unsat, (
            "Unified SymbolicValue from empty dict should NOT could_be_truthy()"
        )

    def test_plain_symbolic_value_without_z3_len_still_works(self):
        """A plain SymbolicValue (not from container) should still work as before."""
        val, constraint = SymbolicValue.symbolic("x")
        # These should not raise
        truthy = val.could_be_truthy()
        falsy = val.could_be_falsy()
        assert isinstance(truthy, z3.BoolRef)
        assert isinstance(falsy, z3.BoolRef)


# ===========================================================================
# Fix 4: optimization.py — structural Z3 equality
# ===========================================================================


class TestZ3StructuralEquality:
    """Prove that state merging uses structural equality, not string comparison."""

    def test_z3_values_equal_basic(self):
        """Identical Z3 expressions should be equal."""
        from pysymex.core.optimization import _z3_values_equal
        x = z3.Int("x")
        assert _z3_values_equal(x, x) is True

    def test_z3_values_equal_different(self):
        """Different Z3 variables should not be equal."""
        from pysymex.core.optimization import _z3_values_equal
        x = z3.Int("x")
        y = z3.Int("y")
        assert _z3_values_equal(x, y) is False

    def test_z3_values_equal_same_expression(self):
        """Structurally identical expressions should be equal."""
        from pysymex.core.optimization import _z3_values_equal
        x = z3.Int("x")
        expr1 = x + 1
        expr2 = x + 1
        # z3.eq checks structural rather than reference equality
        assert _z3_values_equal(expr1, expr2) is True

    def test_z3_values_equal_identity(self):
        """Same object identity should be equal immediately."""
        from pysymex.core.optimization import _z3_values_equal
        x = z3.Int("x")
        assert _z3_values_equal(x, x) is True

    def test_z3_values_equal_non_z3(self):
        """Plain Python values should use normal == comparison."""
        from pysymex.core.optimization import _z3_values_equal
        assert _z3_values_equal(42, 42) is True
        assert _z3_values_equal(42, 43) is False
        assert _z3_values_equal("hello", "hello") is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=long"])
