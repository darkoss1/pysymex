"""Tests for arithmetic safety analysis with Z3."""

import pytest
import z3

from pysymex.analysis.arithmetic_safety import (
    ArithmeticIssue,
    ArithmeticIssueKind,
    ArithmeticMode,
    ArithmeticSafetyAnalyzer,
    IntegerBounds,
    IntegerWidth,
    SafeArithmetic,
)


class TestIntegerBounds:
    """Tests for IntegerBounds."""

    def test_signed_8bit_bounds(self):
        bounds = IntegerBounds.for_width(IntegerWidth.INT8, signed=True)
        assert bounds.min_val == -128
        assert bounds.max_val == 127
        assert bounds.signed is True

    def test_signed_32bit_bounds(self):
        bounds = IntegerBounds.for_width(IntegerWidth.INT32, signed=True)
        assert bounds.min_val == -(2**31)
        assert bounds.max_val == 2**31 - 1

    def test_unsigned_8bit_bounds(self):
        bounds = IntegerBounds.for_width(IntegerWidth.INT8, signed=False)
        assert bounds.min_val == 0
        assert bounds.max_val == 255

    def test_unsigned_64bit_bounds(self):
        bounds = IntegerBounds.for_width(IntegerWidth.INT64, signed=False)
        assert bounds.min_val == 0
        assert bounds.max_val == 2**64 - 1

    def test_contains_in_bounds(self):
        bounds = IntegerBounds.for_width(IntegerWidth.INT8, signed=True)
        assert bounds.contains(0) is True
        assert bounds.contains(127) is True
        assert bounds.contains(-128) is True

    def test_contains_out_of_bounds(self):
        bounds = IntegerBounds.for_width(IntegerWidth.INT8, signed=True)
        assert bounds.contains(128) is False
        assert bounds.contains(-129) is False


class TestArithmeticSafetyAnalyzer:
    """Tests for ArithmeticSafetyAnalyzer."""

    @pytest.fixture
    def analyzer(self):
        return ArithmeticSafetyAnalyzer(
            mode=ArithmeticMode.CHECKED, default_width=IntegerWidth.INT32, signed=True
        )

    def test_analyzer_creation(self, analyzer):
        """Test analyzer can be created."""
        assert analyzer is not None
        assert analyzer.mode == ArithmeticMode.CHECKED
        assert analyzer.default_width == IntegerWidth.INT32

    def test_addition_overflow_detected(self, analyzer):
        """Test that addition overflow is detected with unconstrained symbolic vars."""
        a = z3.Int("a")
        b = z3.Int("b")

        # Check if overflow is possible with unconstrained inputs
        issue = analyzer.check_addition_overflow(a, b)

        # With unconstrained inputs, overflow should be possible
        assert issue is not None
        assert issue.kind in (
            ArithmeticIssueKind.SIGNED_OVERFLOW,
            ArithmeticIssueKind.SIGNED_UNDERFLOW,
        )

    def test_addition_safe_with_constraints(self, analyzer):
        """Test addition is safe with proper constraints."""
        a = z3.Int("a")
        b = z3.Int("b")

        # Add constraints that prevent overflow
        constraints = [
            a >= 0,
            a <= 1000,
            b >= 0,
            b <= 1000,
        ]

        issue = analyzer.check_addition_overflow(a, b, path_constraints=constraints)

        # With bounded inputs, no overflow should be detected
        assert issue is None

    def test_subtraction_overflow_detected(self, analyzer):
        """Test that subtraction overflow can be detected."""
        a = z3.Int("a")
        b = z3.Int("b")

        issue = analyzer.check_subtraction_overflow(a, b)

        # With unconstrained inputs, overflow/underflow should be possible
        assert issue is not None

    def test_multiplication_overflow_detected(self, analyzer):
        """Test that multiplication overflow is detected."""
        a = z3.Int("a")
        b = z3.Int("b")

        issue = analyzer.check_multiplication_overflow(a, b)

        # With unconstrained inputs, overflow should be possible
        assert issue is not None

    def test_division_by_zero_detected(self, analyzer):
        """Test that division by zero is detected."""
        a = z3.Int("a")
        b = z3.Int("b")

        issues = analyzer.check_division_safety(a, b)

        # Division by zero should be detected
        assert len(issues) > 0
        assert any(issue.kind == ArithmeticIssueKind.DIVISION_BY_ZERO for issue in issues)

    def test_division_safe_with_nonzero_constraint(self, analyzer):
        """Test division is safe when divisor constrained to nonzero."""
        a = z3.Int("a")
        b = z3.Int("b")

        constraints = [b != 0, b > 0, b < 100]  # Positive nonzero divisor
        issues = analyzer.check_division_safety(a, b, path_constraints=constraints)

        div_zero_issues = [i for i in issues if i.kind == ArithmeticIssueKind.DIVISION_BY_ZERO]
        assert len(div_zero_issues) == 0

    def test_shift_safety_detected(self, analyzer):
        """Test that shift issues are detected."""
        value = z3.Int("value")
        shift = z3.Int("shift")

        issues = analyzer.check_shift_safety(value, shift)

        # Shift by negative or >= bitwidth should be detected
        assert len(issues) > 0

    def test_modulo_by_zero_detected(self, analyzer):
        """Test modulo by zero detection."""
        a = z3.Int("a")
        b = z3.Int("b")

        issue = analyzer.check_modulo_safety(a, b)

        assert issue is not None
        assert issue.kind == ArithmeticIssueKind.MODULO_BY_ZERO


class TestSafeArithmetic:
    """Tests for SafeArithmetic operations."""

    @pytest.fixture
    def safe_arith(self):
        return SafeArithmetic()

    def test_safe_add_with_constraints(self, safe_arith):
        """Test safe addition with bounded symbolic values."""
        a = z3.Int("a")
        b = z3.Int("b")

        # Constrain to small values that won't overflow
        constraints = [a >= 0, a <= 100, b >= 0, b <= 100]

        result, is_safe, issue = safe_arith.safe_add(a, b, constraints)
        assert is_safe is True
        assert issue is None

    def test_safe_add_overflow_possible(self, safe_arith):
        """Test safe addition detects potential overflow."""
        a = z3.Int("a")
        b = z3.Int("b")

        # No constraints - overflow is possible
        result, is_safe, issue = safe_arith.safe_add(a, b)
        assert is_safe is False
        assert issue is not None

    def test_safe_sub_with_constraints(self, safe_arith):
        """Test safe subtraction with bounded values."""
        a = z3.Int("a")
        b = z3.Int("b")

        # Constrain so a >= b, no underflow possible
        constraints = [a >= 0, a <= 1000, b >= 0, b <= a]

        result, is_safe, issue = safe_arith.safe_sub(a, b, constraints)
        assert is_safe is True
        assert issue is None

    def test_safe_sub_underflow_possible(self, safe_arith):
        """Test safe subtraction detects potential underflow."""
        a = z3.Int("a")
        b = z3.Int("b")

        result, is_safe, issue = safe_arith.safe_sub(a, b)
        assert is_safe is False
        assert issue is not None

    def test_safe_mul_with_constraints(self, safe_arith):
        """Test safe multiplication with bounded values."""
        a = z3.Int("a")
        b = z3.Int("b")

        # Small values won't overflow
        constraints = [a >= 0, a <= 100, b >= 0, b <= 100]

        result, is_safe, issue = safe_arith.safe_mul(a, b, constraints)
        assert is_safe is True
        assert issue is None

    def test_safe_mul_overflow_possible(self, safe_arith):
        """Test safe multiplication detects potential overflow."""
        a = z3.Int("a")
        b = z3.Int("b")

        result, is_safe, issue = safe_arith.safe_mul(a, b)
        assert is_safe is False
        assert issue is not None

    def test_safe_div_with_constraints(self, safe_arith):
        """Test safe division with nonzero divisor."""
        a = z3.Int("a")
        b = z3.Int("b")

        # Constrain divisor to be positive and nonzero
        constraints = [b > 0, b <= 100]

        result, is_safe, issues = safe_arith.safe_div(a, b, constraints)
        # Filter out INT_MIN / -1 issues since b > 0
        div_zero_issues = [i for i in issues if i.kind == ArithmeticIssueKind.DIVISION_BY_ZERO]
        assert len(div_zero_issues) == 0

    def test_safe_div_by_zero_possible(self, safe_arith):
        """Test safe division detects potential division by zero."""
        a = z3.Int("a")
        b = z3.Int("b")

        result, is_safe, issues = safe_arith.safe_div(a, b)
        assert is_safe is False
        assert len(issues) > 0


class TestArithmeticIssue:
    """Tests for ArithmeticIssue dataclass."""

    def test_issue_creation(self):
        issue = ArithmeticIssue(
            kind=ArithmeticIssueKind.SIGNED_OVERFLOW,
            message="Addition may overflow",
            counterexample={"a": 2147483647, "b": 1},
        )

        assert issue.kind == ArithmeticIssueKind.SIGNED_OVERFLOW
        assert "overflow" in issue.message.lower()
        assert issue.counterexample is not None

    def test_issue_format(self):
        issue = ArithmeticIssue(
            kind=ArithmeticIssueKind.DIVISION_BY_ZERO,
            message="Division by zero possible",
            line_number=42,
        )

        formatted = issue.format()
        assert "DIVISION_BY_ZERO" in formatted
        assert "42" in formatted


class TestEdgeCases:
    """Tests for edge cases."""

    @pytest.fixture
    def analyzer(self):
        return ArithmeticSafetyAnalyzer(default_width=IntegerWidth.INT32)

    def test_power_safety(self, analyzer):
        """Test power safety analysis."""
        base = z3.Int("base")
        exp = z3.Int("exp")

        issues = analyzer.check_power_safety(base, exp)

        # Power can overflow or have 0**negative
        assert len(issues) > 0

    def test_abs_safety(self, analyzer):
        """Test abs safety (INT_MIN case)."""
        value = z3.Int("value")

        issue = analyzer.check_abs_safety(value)

        # abs(INT_MIN) overflows
        assert issue is not None

    def test_narrowing_conversion(self, analyzer):
        """Test narrowing conversion detection."""
        value = z3.Int("value")

        # Convert from 64-bit to 32-bit - no constraints so value can overflow
        issues = analyzer.check_narrowing_conversion(
            value,
            target_width=IntegerWidth.INT32,
            target_signed=True,
        )

        # Without constraints, value might not fit
        assert len(issues) > 0  # Returns list of issues


class TestArithmeticModes:
    """Tests for different arithmetic modes."""

    def test_wrapping_mode(self):
        """Test wrapping arithmetic mode."""
        analyzer = ArithmeticSafetyAnalyzer(mode=ArithmeticMode.WRAPPING)
        assert analyzer.mode == ArithmeticMode.WRAPPING

    def test_saturating_mode(self):
        """Test saturating arithmetic mode."""
        analyzer = ArithmeticSafetyAnalyzer(mode=ArithmeticMode.SATURATING)
        assert analyzer.mode == ArithmeticMode.SATURATING

    def test_checked_mode(self):
        """Test checked arithmetic mode."""
        analyzer = ArithmeticSafetyAnalyzer(mode=ArithmeticMode.CHECKED)
        assert analyzer.mode == ArithmeticMode.CHECKED

    def test_arbitrary_precision_mode(self):
        """Test arbitrary precision mode (Python-style)."""
        analyzer = ArithmeticSafetyAnalyzer(
            mode=ArithmeticMode.ARBITRARY, default_width=IntegerWidth.ARBITRARY
        )
        assert analyzer.mode == ArithmeticMode.ARBITRARY
