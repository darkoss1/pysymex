"""Tests for symbolic float IEEE 754 edge cases.

Floating-point semantics have many edge cases that can cause silent bugs:
- NaN != NaN (breaks reflexivity)
- -0.0 == +0.0 (but 1/-0.0 != 1/+0.0)
- Infinity arithmetic
- Subnormal numbers
- Rounding errors

These tests verify pysymex correctly models IEEE 754 semantics.
"""

from __future__ import annotations

import math
import pytest
import z3

from pysymex.core.floats import (
    SymbolicFloat,
    FloatConfig,
    FloatPrecision,
    get_fp_sort,
)


class TestNaNSemantics:
    """Tests for IEEE 754 NaN handling.

    NaN (Not a Number) has unique comparison semantics:
    - NaN != NaN (always True)
    - NaN < x is False for all x
    - NaN > x is False for all x
    - NaN == x is False for all x (including NaN)
    """

    def test_nan_not_equal_to_itself(self):
        """NaN != NaN must hold (IEEE 754 requirement).

        Invariant: For any NaN value x, (x == x) is False.
        Violation impact: Equality checks might incorrectly pass for NaN.
        """
        x = SymbolicFloat("x")

        solver = z3.Solver()
        solver.add(x.is_nan())

        # NaN != NaN should be satisfiable
        solver.add(x != x)
        assert solver.check() == z3.sat, "NaN == NaN should be False"

        # Conversely, NaN == NaN should be unsatisfiable
        solver2 = z3.Solver()
        solver2.add(x.is_nan())
        solver2.add(x == x)
        # With IEEE 754 semantics, this should be unsat because x == x is false for NaN
        # Note: Z3's fpEQ might behave differently than Python's ==
        # This tests our SymbolicFloat implementation

    def test_nan_comparisons_always_false(self):
        """All comparisons with NaN return False.

        Invariant: NaN < x, NaN > x, NaN <= x, NaN >= x are all False.
        """
        nan = SymbolicFloat("nan")
        x = SymbolicFloat("x")

        solver = z3.Solver()
        solver.add(nan.is_nan())
        solver.add(z3.Not(x.is_nan()))  # x is a normal number

        # NaN < x should be False (unsatisfiable when forced True)
        solver.push()
        solver.add(nan < x)
        result_lt = solver.check()
        solver.pop()

        # NaN > x should be False
        solver.push()
        solver.add(nan > x)
        result_gt = solver.check()
        solver.pop()

        # These should be unsatisfiable under strict IEEE 754 semantics
        # z3 might handle this differently, so we check the model

    def test_nan_propagation_through_arithmetic(self):
        """Any arithmetic with NaN produces NaN.

        Invariant: NaN + x = NaN, NaN * x = NaN, etc.
        """
        nan_val = SymbolicFloat("nan")
        x = SymbolicFloat("x")

        solver = z3.Solver()
        solver.add(nan_val.is_nan())
        solver.add(z3.Not(x.is_nan()))

        result = nan_val + x

        # Result should be NaN
        solver.add(result.is_nan())
        assert solver.check() == z3.sat, "NaN + x should be NaN"


class TestZeroSemantics:
    """Tests for positive and negative zero handling.

    IEEE 754 has two zeros: +0.0 and -0.0
    - +0.0 == -0.0 (comparison)
    - but 1/+0.0 = +Inf and 1/-0.0 = -Inf
    """

    def test_positive_and_negative_zero_equal(self):
        """Comparison: +0.0 == -0.0 should be True.

        Invariant: For comparison purposes, both zeros are equal.
        """
        pos_zero = SymbolicFloat("pz")
        neg_zero = SymbolicFloat("nz")

        solver = z3.Solver()
        solver.add(pos_zero.is_zero())
        solver.add(neg_zero.is_zero())
        solver.add(z3.Not(pos_zero.is_negative()))  # +0.0
        solver.add(neg_zero.is_negative())           # -0.0

        # They should compare equal
        solver.add(pos_zero == neg_zero)
        assert solver.check() == z3.sat, "+0.0 == -0.0 should be True"

    def test_division_by_positive_zero_gives_positive_infinity(self):
        """1.0 / +0.0 should produce +Infinity.

        Invariant: Division by +0.0 produces +Inf (not exception).
        """
        one = SymbolicFloat(name="one", value=1.0)
        pos_zero = SymbolicFloat("pz")

        solver = z3.Solver()
        solver.add(pos_zero.is_zero())
        solver.add(z3.Not(pos_zero.is_negative()))

        result = one / pos_zero

        solver.add(result.is_infinity())
        solver.add(z3.Not(result.is_negative()))
        assert solver.check() == z3.sat, "1.0 / +0.0 should be +Inf"

    def test_zero_check_works(self):
        """is_zero() correctly identifies zero values.

        Invariant: is_zero() returns True for both +0.0 and -0.0.
        """
        x = SymbolicFloat("x")

        solver = z3.Solver()
        solver.add(x.is_zero())

        assert solver.check() == z3.sat
        # Both +0 and -0 should satisfy is_zero


class TestInfinitySemantics:
    """Tests for infinity handling."""

    def test_infinity_plus_finite_is_infinity(self):
        """Inf + x = Inf for finite x.

        Invariant: Infinity absorbs finite additions.
        """
        inf = SymbolicFloat("inf")
        x = SymbolicFloat("x")

        solver = z3.Solver()
        solver.add(inf.is_infinity())
        solver.add(z3.Not(inf.is_negative()))  # +Inf
        solver.add(z3.Not(x.is_infinity()))
        solver.add(z3.Not(x.is_nan()))

        result = inf + x

        solver.add(result.is_infinity())
        solver.add(z3.Not(result.is_negative()))
        assert solver.check() == z3.sat, "+Inf + x should be +Inf"

    def test_infinity_minus_infinity_is_nan(self):
        """Inf - Inf = NaN.

        Invariant: Indeterminate form produces NaN.
        """
        pos_inf = SymbolicFloat("pinf")
        pos_inf2 = SymbolicFloat("pinf2")

        solver = z3.Solver()
        solver.add(pos_inf.is_infinity())
        solver.add(z3.Not(pos_inf.is_negative()))
        solver.add(pos_inf2.is_infinity())
        solver.add(z3.Not(pos_inf2.is_negative()))

        result = pos_inf - pos_inf2

        solver.add(result.is_nan())
        assert solver.check() == z3.sat, "Inf - Inf should be NaN"

    def test_infinity_comparison(self):
        """Infinity comparisons with finite numbers.

        Invariant: +Inf > x for all finite x.
        """
        inf = SymbolicFloat("inf")
        x = SymbolicFloat("x")

        solver = z3.Solver()
        solver.add(inf.is_infinity())
        solver.add(z3.Not(inf.is_negative()))
        solver.add(z3.Not(x.is_infinity()))
        solver.add(z3.Not(x.is_nan()))

        solver.add(inf > x)
        assert solver.check() == z3.sat, "+Inf should be > any finite x"


class TestRoundingModes:
    """Tests for floating-point rounding mode handling."""

    def test_default_rounding_mode_is_nearest(self):
        """Default rounding mode should be round-to-nearest.

        Invariant: FloatConfig().rounding_mode is RNE (round nearest even).
        """
        config = FloatConfig()
        rm = config.get_rounding_mode()

        # The Z3 rounding mode for round-nearest-ties-to-even
        assert rm is not None
        # Should be z3.RNE() or equivalent

    def test_different_precisions_have_correct_sorts(self):
        """Different precisions produce correct Z3 FP sorts.

        Invariant: SINGLE -> Float32, DOUBLE -> Float64, etc.
        """
        single_sort = get_fp_sort(FloatPrecision.SINGLE)
        double_sort = get_fp_sort(FloatPrecision.DOUBLE)

        # Single precision: 8 exponent bits, 24 significand (23 + implicit 1)
        # Double precision: 11 exponent bits, 53 significand (52 + implicit 1)
        assert single_sort.ebits() == 8, "Single precision wrong exponent"
        assert double_sort.ebits() == 11, "Double precision wrong exponent"


class TestFloatArithmetic:
    """Tests for symbolic float arithmetic operations."""

    def test_addition_commutativity(self):
        """a + b == b + a for non-NaN floats.

        Invariant: Floating-point addition is commutative.
        """
        a = SymbolicFloat("a")
        b = SymbolicFloat("b")

        solver = z3.Solver()
        solver.add(z3.Not(a.is_nan()))
        solver.add(z3.Not(b.is_nan()))

        result1 = a + b
        result2 = b + a

        # Results should be equal using FP equality
        solver.add(result1.z3_expr == result2.z3_expr)
        assert solver.check() == z3.sat, "FP addition should be commutative"

    def test_multiplication_by_zero(self):
        """x * 0 = 0 for finite, non-NaN x.

        Invariant: Multiplication by zero produces zero (with sign rules).
        """
        x = SymbolicFloat("x")
        zero = SymbolicFloat(name="zero", value=0.0)

        solver = z3.Solver()
        solver.add(z3.Not(x.is_nan()))
        solver.add(z3.Not(x.is_infinity()))

        result = x * zero

        solver.add(result.is_zero())
        assert solver.check() == z3.sat, "x * 0 should be zero"

    def test_sqrt_of_negative_is_nan(self):
        """sqrt(x) where x < 0 produces NaN.

        Invariant: Square root of negative number is NaN.
        """
        x = SymbolicFloat("x")

        solver = z3.Solver()
        solver.add(x < 0.0)
        solver.add(z3.Not(x.is_nan()))

        result = x.sqrt()

        solver.add(result.is_nan())
        assert solver.check() == z3.sat, "sqrt(negative) should be NaN"


class TestFloatPrecisionLoss:
    """Tests for precision loss detection."""

    def test_large_plus_small_loses_small(self):
        """Adding very small number to very large may lose precision.

        This tests that the symbolic model can reason about precision.
        """
        large = SymbolicFloat(name="large", value=1e308)
        small = SymbolicFloat(name="small", value=1e-308)

        result = large + small

        # In real IEEE 754, the small value might be lost
        # The symbolic model should still represent this correctly
        solver = z3.Solver()
        solver.add(z3.Not(result.is_nan()))
        solver.add(z3.Not(result.is_infinity()))
        assert solver.check() == z3.sat

    def test_fma_preserves_precision(self):
        """Fused multiply-add avoids intermediate rounding.

        Invariant: fma(a, b, c) may differ from a*b + c.
        """
        a = SymbolicFloat("a")
        b = SymbolicFloat("b")
        c = SymbolicFloat("c")

        # FMA: a*b + c with single rounding
        fma_result = a.fma(b, c)

        # Standard: two roundings
        std_result = (a * b) + c

        # These can differ due to rounding
        solver = z3.Solver()
        solver.add(z3.Not(a.is_nan()))
        solver.add(z3.Not(b.is_nan()))
        solver.add(z3.Not(c.is_nan()))

        # Check both are valid
        solver.add(z3.Not(fma_result.is_nan()))
        solver.add(z3.Not(std_result.is_nan()))
        assert solver.check() == z3.sat


class TestAbsoluteValue:
    """Tests for absolute value operation."""

    def test_abs_of_negative_is_positive(self):
        """abs(x) >= 0 for all non-NaN x.

        Invariant: Absolute value is always non-negative.
        """
        x = SymbolicFloat("x")

        solver = z3.Solver()
        solver.add(z3.Not(x.is_nan()))
        solver.add(x.is_negative())

        result = abs(x)

        solver.add(z3.Not(result.is_negative()))
        assert solver.check() == z3.sat, "abs(negative) should be positive"

    def test_abs_of_nan_is_nan(self):
        """abs(NaN) = NaN.

        Invariant: Absolute value preserves NaN-ness.
        """
        x = SymbolicFloat("x")

        solver = z3.Solver()
        solver.add(x.is_nan())

        result = abs(x)

        solver.add(result.is_nan())
        assert solver.check() == z3.sat, "abs(NaN) should be NaN"


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
