import pytest
import z3
from unittest.mock import Mock, patch
from pysymex.analysis.specialized.arithmetic import (
    ArithmeticMode,
    IntegerWidth,
    IntegerBounds,
    ArithmeticIssueKind,
    ArithmeticIssue,
    ArithmeticSafetyAnalyzer,
    SafeArithmetic,
)


class TestArithmeticMode:
    """Test suite for pysymex.analysis.specialized.arithmetic.ArithmeticMode."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ArithmeticMode.WRAPPING.name == "WRAPPING"
        assert ArithmeticMode.SATURATING.name == "SATURATING"


class TestIntegerWidth:
    """Test suite for pysymex.analysis.specialized.arithmetic.IntegerWidth."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert IntegerWidth.INT32.value == 32
        assert IntegerWidth.ARBITRARY.value == 0


class TestIntegerBounds:
    """Test suite for pysymex.analysis.specialized.arithmetic.IntegerBounds."""

    def test_for_width(self) -> None:
        """Test for_width behavior."""
        b8 = IntegerBounds.for_width(IntegerWidth.INT8, signed=True)
        assert b8.min_val == -128
        assert b8.max_val == 127

        u8 = IntegerBounds.for_width(IntegerWidth.INT8, signed=False)
        assert u8.min_val == 0
        assert u8.max_val == 255

        arb = IntegerBounds.for_width(IntegerWidth.ARBITRARY)
        assert arb.min_val < -1000

    def test_contains(self) -> None:
        """Test contains behavior."""
        b8 = IntegerBounds.for_width(IntegerWidth.INT8, signed=True)
        assert b8.contains(0) is True
        assert b8.contains(127) is True
        assert b8.contains(128) is False
        assert b8.contains(-129) is False

    def test_to_z3_constraints(self) -> None:
        """Test to_z3_constraints behavior."""
        b8 = IntegerBounds.for_width(IntegerWidth.INT8, signed=True)
        var = z3.Int("x")
        constraints = b8.to_z3_constraints(var)
        assert len(constraints) == 2


class TestArithmeticIssueKind:
    """Test suite for pysymex.analysis.specialized.arithmetic.ArithmeticIssueKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ArithmeticIssueKind.SIGNED_OVERFLOW.name == "SIGNED_OVERFLOW"


class TestArithmeticIssue:
    """Test suite for pysymex.analysis.specialized.arithmetic.ArithmeticIssue."""

    def test_format(self) -> None:
        """Test format behavior."""
        issue = ArithmeticIssue(
            kind=ArithmeticIssueKind.SIGNED_OVERFLOW,
            message="overflow",
            line_number=10,
            counterexample={"x": 5},
        )
        fmt = issue.format()
        assert "[SIGNED_OVERFLOW]" in fmt
        assert "line 10" in fmt
        assert "overflow" in fmt
        assert "x=5" in fmt


class TestArithmeticSafetyAnalyzer:
    """Test suite for pysymex.analysis.specialized.arithmetic.ArithmeticSafetyAnalyzer."""

    def test_reset(self) -> None:
        """Test reset behavior."""
        a = ArithmeticSafetyAnalyzer()
        a._issues.append(Mock())
        a.reset()
        assert len(a._issues) == 0

    def test_check_addition_overflow(self) -> None:
        """Test check_addition_overflow behavior."""
        a = ArithmeticSafetyAnalyzer(default_width=IntegerWidth.INT8)
        x = z3.IntVal(100)
        y = z3.IntVal(50)
        issue = a.check_addition_overflow(x, y)
        assert issue is not None
        assert issue.kind == ArithmeticIssueKind.SIGNED_OVERFLOW

        issue_safe = a.check_addition_overflow(z3.IntVal(10), z3.IntVal(20))
        assert issue_safe is None

    def test_check_subtraction_overflow(self) -> None:
        """Test check_subtraction_overflow behavior."""
        a = ArithmeticSafetyAnalyzer(default_width=IntegerWidth.INT8)
        x = z3.IntVal(-100)
        y = z3.IntVal(50)
        issue = a.check_subtraction_overflow(x, y)
        assert issue is not None
        assert issue.kind == ArithmeticIssueKind.SIGNED_UNDERFLOW

    def test_check_multiplication_overflow(self) -> None:
        """Test check_multiplication_overflow behavior."""
        a = ArithmeticSafetyAnalyzer(default_width=IntegerWidth.INT8)
        x = z3.IntVal(20)
        y = z3.IntVal(10)
        issue = a.check_multiplication_overflow(x, y)
        assert issue is not None
        assert issue.kind == ArithmeticIssueKind.SIGNED_OVERFLOW

    def test_check_division_safety(self) -> None:
        """Test check_division_safety behavior."""
        a = ArithmeticSafetyAnalyzer(default_width=IntegerWidth.INT8)
        x = z3.IntVal(-128)
        y = z3.IntVal(-1)
        issues = a.check_division_safety(x, y)
        assert len(issues) == 1
        assert issues[0].kind == ArithmeticIssueKind.DIVISION_OVERFLOW

        y2 = z3.IntVal(0)
        issues2 = a.check_division_safety(x, y2)
        assert len(issues2) == 1
        assert issues2[0].kind == ArithmeticIssueKind.DIVISION_BY_ZERO

    def test_check_modulo_safety(self) -> None:
        """Test check_modulo_safety behavior."""
        a = ArithmeticSafetyAnalyzer()
        issue = a.check_modulo_safety(z3.IntVal(5), z3.IntVal(0))
        assert issue is not None
        assert issue.kind == ArithmeticIssueKind.MODULO_BY_ZERO

    def test_check_shift_safety(self) -> None:
        """Test check_shift_safety behavior."""
        a = ArithmeticSafetyAnalyzer(default_width=IntegerWidth.INT32)
        issues_neg = a.check_shift_safety(z3.IntVal(1), z3.IntVal(-1))
        assert len(issues_neg) == 1
        assert issues_neg[0].kind == ArithmeticIssueKind.NEGATIVE_SHIFT

        issues_over = a.check_shift_safety(z3.IntVal(1), z3.IntVal(32))
        assert len(issues_over) == 1
        assert issues_over[0].kind == ArithmeticIssueKind.SHIFT_OVERFLOW

    def test_check_power_safety(self) -> None:
        """Test check_power_safety behavior."""
        a = ArithmeticSafetyAnalyzer(default_width=IntegerWidth.INT32)
        issues_div0 = a.check_power_safety(z3.IntVal(0), z3.IntVal(-1))
        assert any(i.kind == ArithmeticIssueKind.DIVISION_BY_ZERO for i in issues_div0)

        issues_over = a.check_power_safety(z3.IntVal(2), z3.IntVal(35))
        assert any(i.kind == ArithmeticIssueKind.POWER_OVERFLOW for i in issues_over)

    def test_check_abs_safety(self) -> None:
        """Test check_abs_safety behavior."""
        a = ArithmeticSafetyAnalyzer(default_width=IntegerWidth.INT8)
        issue = a.check_abs_safety(z3.IntVal(-128))
        assert issue is not None
        assert issue.kind == ArithmeticIssueKind.ABS_OVERFLOW

    def test_check_narrowing_conversion(self) -> None:
        """Test check_narrowing_conversion behavior."""
        a = ArithmeticSafetyAnalyzer()
        issues_trunc = a.check_narrowing_conversion(z3.IntVal(300), IntegerWidth.INT8)
        assert len(issues_trunc) == 1
        assert issues_trunc[0].kind == ArithmeticIssueKind.TRUNCATION

        issues_sign = a.check_narrowing_conversion(
            z3.IntVal(-5), IntegerWidth.INT32, target_signed=False
        )
        assert any(i.kind == ArithmeticIssueKind.SIGN_LOSS for i in issues_sign)

    def test_check_float_division_safety(self) -> None:
        """Test check_float_division_safety behavior."""
        a = ArithmeticSafetyAnalyzer()
        issues_inf = a.check_float_division_safety(z3.RealVal(1.0), z3.RealVal(0.0))
        assert any(i.kind == ArithmeticIssueKind.FLOAT_INFINITY for i in issues_inf)

        issues_nan = a.check_float_division_safety(z3.RealVal(0.0), z3.RealVal(0.0))
        assert any(i.kind == ArithmeticIssueKind.FLOAT_NAN for i in issues_nan)

    def test_analyze_expression(self) -> None:
        """Test analyze_expression behavior."""
        a = ArithmeticSafetyAnalyzer(default_width=IntegerWidth.INT8)
        x = z3.Int("x")
        expr = x / 0
        issues = a.analyze_expression(expr)
        assert any(i.kind == ArithmeticIssueKind.DIVISION_BY_ZERO for i in issues)


class TestSafeArithmetic:
    """Test suite for pysymex.analysis.specialized.arithmetic.SafeArithmetic."""

    def test_safe_add(self) -> None:
        """Test safe_add behavior."""
        sa = SafeArithmetic()
        res, is_safe, issue = sa.safe_add(z3.IntVal(1), z3.IntVal(2))
        assert is_safe is True
        assert issue is None

    def test_safe_sub(self) -> None:
        """Test safe_sub behavior."""
        sa = SafeArithmetic()
        res, is_safe, issue = sa.safe_sub(z3.IntVal(1), z3.IntVal(2))
        assert is_safe is True
        assert issue is None

    def test_safe_mul(self) -> None:
        """Test safe_mul behavior."""
        sa = SafeArithmetic()
        res, is_safe, issue = sa.safe_mul(z3.IntVal(1), z3.IntVal(2))
        assert is_safe is True
        assert issue is None

    def test_safe_div(self) -> None:
        """Test safe_div behavior."""
        sa = SafeArithmetic()
        res, is_safe, issues = sa.safe_div(z3.IntVal(1), z3.IntVal(0))
        assert is_safe is False
        assert len(issues) > 0
