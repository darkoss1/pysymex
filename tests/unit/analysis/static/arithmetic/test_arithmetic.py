import z3
from pysymex.analysis.static.arithmetic.conditions import (
    bounded_integer_overflow_condition,
    divisor_zero_condition,
    expression_below_bound_condition,
    expression_outside_bounds_condition,
    normalize_assignment_operator,
    symbolic_numeric_zero_condition,
)
from pysymex.analysis.static.arithmetic.types import (
    ArithmeticIssueKind,
    ArithmeticIssue,
)


class TestArithmeticConditions:
    """Tests for shared Z3 arithmetic safety predicates."""

    def test_symbolic_numeric_zero_condition_eliminates_inactive_float_branch(self) -> None:
        """A definitely integer value does not introduce unused FP theory."""
        divisor = z3.Int("definite_int_divisor")
        condition = symbolic_numeric_zero_condition(
            z3.BoolVal(True),
            divisor,
            z3.BoolVal(False),
            z3.FP("unused_float_divisor", z3.Float64()),
            include_float=True,
        )
        assert z3.eq(condition, divisor == 0)

    def test_normalize_assignment_operator(self) -> None:
        """Normalize assignment-form operators before overflow analysis."""
        assert normalize_assignment_operator("+=") == "+"
        assert normalize_assignment_operator("<<=") == "<<"
        assert normalize_assignment_operator("*") == "*"

    def test_bounded_integer_overflow_condition_tracks_addition_bounds(self) -> None:
        """Build one satisfiable predicate for additions that exceed configured bounds."""
        x = z3.Int("x")
        y = z3.Int("y")
        condition = bounded_integer_overflow_condition(x, y, "+", 0, 10)
        assert condition is not None

        solver = z3.Solver()
        solver.add(x == 6, y == 5, condition)
        assert solver.check() == z3.sat

        solver = z3.Solver()
        solver.add(x == 2, y == 3, condition)
        assert solver.check() == z3.unsat

    def test_bounded_integer_overflow_condition_rejects_untracked_operator(self) -> None:
        """Return no predicate for operators this bounded overflow rule does not own."""
        assert bounded_integer_overflow_condition(z3.Int("x"), z3.Int("y"), "/", 0, 10) is None

    def test_divisor_zero_condition_is_shared_by_z3_arithmetic_callers(self) -> None:
        """Build a satisfiable zero-divisor predicate for arithmetic safety checks."""
        divisor = z3.Int("divisor")
        condition = divisor_zero_condition(divisor)

        solver = z3.Solver()
        solver.add(divisor == 0, condition)
        assert solver.check() == z3.sat

        solver = z3.Solver()
        solver.add(divisor == 1, condition)
        assert solver.check() == z3.unsat

    def test_expression_outside_bounds_condition_handles_bitvecs_as_signed_ints(self) -> None:
        """Use the same property-verifier bound predicate for signed bit-vector values."""
        value = z3.BitVec("value", 8)
        condition = expression_outside_bounds_condition(value, -10, 10)

        solver = z3.Solver()
        solver.add(value == z3.BitVecVal(20, 8), condition)
        assert solver.check() == z3.sat

    def test_expression_below_bound_condition_ignores_upper_bound_violations(self) -> None:
        """Underflow predicates should only classify values below the lower bound."""
        value = z3.Int("below_bound_value")
        condition = expression_below_bound_condition(value, -10)

        solver = z3.Solver()
        solver.add(value == 20, condition)
        assert solver.check() == z3.unsat

        solver = z3.Solver()
        solver.add(value == -20, condition)
        assert solver.check() == z3.sat


class TestArithmeticIssueKind:
    """Test suite for pysymex.analysis.static.arithmetic.ArithmeticIssueKind."""

    def test_initialization(self) -> None:
        """Test basic initialization."""
        assert ArithmeticIssueKind.SIGNED_OVERFLOW.name == "SIGNED_OVERFLOW"


class TestArithmeticIssue:
    """Test suite for pysymex.analysis.static.arithmetic.ArithmeticIssue."""

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
