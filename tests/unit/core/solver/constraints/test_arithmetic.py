import z3

from pysymex._internal.core.solver.constraints.arithmetic import (
    bounded_integer_overflow_condition,
    divisor_zero_condition,
    normalize_assignment_operator,
    symbolic_numeric_zero_condition,
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
