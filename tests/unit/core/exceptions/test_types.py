from importlib import import_module

import z3
from pytest import MonkeyPatch

from pysymex._internal.core.exceptions.categories import ExceptionCategory, get_exception_category
from pysymex._internal.core.exceptions.objects import (
    ExceptionOccurrenceResult,
    ExceptionOccurrenceStatus,
    SymbolicException,
)


def test_core_exception_exports_use_direct_owners() -> None:
    import pysymex

    assert not hasattr(pysymex, "SymbolicException")


class TestExceptionCategory:
    """Test suite for ExceptionCategory."""

    def test_initialization(self) -> None:
        """Scenario: category enum exists; expected RUNTIME member name."""
        assert ExceptionCategory.RUNTIME.name == "RUNTIME"


def test_get_exception_category() -> None:
    """Scenario: ZeroDivisionError category lookup; expected arithmetic category."""
    assert get_exception_category(ZeroDivisionError) == ExceptionCategory.ARITHMETIC


def test_exception_package_exports_canonical_symbols() -> None:
    """Scenario: exception package exports resolve to canonical exception modules."""
    categories = import_module("pysymex._internal.core.exceptions.categories")
    objects = import_module("pysymex._internal.core.exceptions.objects")

    assert ExceptionCategory is categories.ExceptionCategory
    assert SymbolicException is objects.SymbolicException
    assert ExceptionOccurrenceResult is objects.ExceptionOccurrenceResult
    assert ExceptionOccurrenceStatus is objects.ExceptionOccurrenceStatus


class TestSymbolicException:
    """Test suite for SymbolicException."""

    def test_concrete(self) -> None:
        """Scenario: concrete constructor; expected unconditional condition."""
        exc = SymbolicException.concrete(ValueError, "bad")
        assert exc.is_unconditional() is True

    def test_symbolic(self) -> None:
        """Scenario: symbolic constructor with condition; expected stored condition expression."""
        cond = z3.Bool("c")
        exc = SymbolicException.symbolic("e", ValueError, cond)
        assert exc.condition == cond

    def test_type_name(self) -> None:
        """Scenario: concrete ValueError type name; expected class name string."""
        exc = SymbolicException.concrete(ValueError)
        assert exc.type_name == "ValueError"

    def test_is_unconditional(self) -> None:
        """Scenario: symbolic exception with non-constant condition; expected not unconditional."""
        exc = SymbolicException.symbolic("e", ValueError, z3.Bool("maybe"))
        assert exc.is_unconditional() is False

    def test_may_occur(self) -> None:
        """Scenario: satisfiable condition; expected may_occur true."""
        solver = z3.Solver()
        exc = SymbolicException.symbolic("e", ValueError, z3.BoolVal(True))
        result = exc.may_occur_result(solver)
        assert result.status is ExceptionOccurrenceStatus.ESTABLISHED
        assert result.is_established
        assert exc.may_occur(solver) is True

    def test_may_occur_result_refutes_unsatisfiable_condition(self) -> None:
        """Scenario: unsatisfiable condition; expected may_occur_result refuted."""
        solver = z3.Solver()
        exc = SymbolicException.symbolic("e", ValueError, z3.BoolVal(False))

        result = exc.may_occur_result(solver)

        assert result.status is ExceptionOccurrenceStatus.REFUTED
        assert result.reason == "condition_unsat"
        assert exc.may_occur(solver) is False

    def test_may_occur_is_conservative_on_solver_unknown(self) -> None:
        """Scenario: solver returns unknown; expected may_occur remains true."""
        solver = z3.Solver()
        solver.set("rlimit", 1)
        x = z3.Int("exception_unknown_may_x")
        exc = SymbolicException.symbolic("e", ValueError, x > 0)
        assert solver.check(x > 1) == z3.unknown

        result = exc.may_occur_result(solver)

        assert result.status is ExceptionOccurrenceStatus.UNKNOWN
        assert result.reason == "solver_unknown"
        assert result.is_unknown
        assert exc.may_occur(solver) is True

    def test_may_occur_is_conservative_on_solver_add_failure(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Scenario: solver add fails; expected may_occur remains conservative."""
        solver = z3.Solver()
        exc = SymbolicException.symbolic("e", ValueError, z3.Bool("exc_add"))

        def raising_add(*constraints: z3.BoolRef) -> None:
            _ = constraints
            raise z3.Z3Exception("forced exception occurrence add failure")

        monkeypatch.setattr(solver, "add", raising_add)

        result = exc.may_occur_result(solver)

        assert result.status is ExceptionOccurrenceStatus.UNKNOWN
        assert exc.may_occur(solver) is True

    def test_must_occur(self) -> None:
        """Scenario: true condition; expected must_occur true."""
        solver = z3.Solver()
        exc = SymbolicException.symbolic("e", ValueError, z3.BoolVal(True))
        result = exc.must_occur_result(solver)
        assert result.status is ExceptionOccurrenceStatus.ESTABLISHED
        assert result.is_established
        assert exc.must_occur(solver) is True

    def test_must_occur_result_refutes_optional_condition(self) -> None:
        """Scenario: satisfiable negated condition; expected must_occur_result refuted."""
        solver = z3.Solver()
        cond = z3.Bool("exception_optional_condition")
        exc = SymbolicException.symbolic("e", ValueError, cond)

        result = exc.must_occur_result(solver)

        assert result.status is ExceptionOccurrenceStatus.REFUTED
        assert result.reason == "negated_condition_sat"
        assert exc.must_occur(solver) is False

    def test_must_occur_is_false_on_solver_unknown(self) -> None:
        """Scenario: solver returns unknown; expected must_occur remains false."""
        solver = z3.Solver()
        solver.set("rlimit", 1)
        x = z3.Int("exception_unknown_must_x")
        exc = SymbolicException.symbolic("e", ValueError, x > 0)
        assert solver.check(x > 1) == z3.unknown

        result = exc.must_occur_result(solver)

        assert result.status is ExceptionOccurrenceStatus.UNKNOWN
        assert result.reason == "solver_unknown"
        assert result.is_unknown
        assert exc.must_occur(solver) is False

    def test_must_occur_is_false_on_solver_check_failure(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Scenario: solver check fails; expected must_occur remains unproven."""
        solver = z3.Solver()
        exc = SymbolicException.symbolic("e", ValueError, z3.Bool("exc_check"))

        def raising_check(*assumptions: z3.BoolRef) -> z3.CheckSatResult:
            _ = assumptions
            raise z3.Z3Exception("forced exception occurrence check failure")

        monkeypatch.setattr(solver, "check", raising_check)

        result = exc.must_occur_result(solver)

        assert result.status is ExceptionOccurrenceStatus.UNKNOWN
        assert exc.must_occur(solver) is False
