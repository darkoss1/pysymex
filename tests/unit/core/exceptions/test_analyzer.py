import time

from pytest import MonkeyPatch
import z3

from pysymex.core.exceptions.analyzer.core import ExceptionAnalyzer
from pysymex.core.exceptions.contracts import RaisesContract
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.exceptions.state import ExceptionState
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.solver.engine.results import SolverResult


class TestExceptionAnalyzer:
    """Test suite for pysymex.core.exceptions.analyzer.ExceptionAnalyzer."""

    def test_add_potential_exception(self) -> None:
        """Scenario: add potential exception; expected list contains it."""
        analyzer = ExceptionAnalyzer()
        exc = SymbolicException.concrete(ValueError)
        analyzer.add_potential_exception(exc)
        assert analyzer.get_potential_exceptions() == [exc]

    def test_get_potential_exceptions(self) -> None:
        """Scenario: no exceptions added; expected empty list."""
        analyzer = ExceptionAnalyzer()
        assert analyzer.get_potential_exceptions() == []

    def test_get_exceptions_of_type(self) -> None:
        """Scenario: filter by ValueError type; expected matching exception returned."""
        analyzer = ExceptionAnalyzer()
        exc = SymbolicException.concrete(ValueError)
        analyzer.add_potential_exception(exc)
        assert analyzer.get_exceptions_of_type(ValueError) == [exc]

    def test_verify_raises_contract(self) -> None:
        """Scenario: matching potential exception and contract; expected satisfied result."""
        analyzer = ExceptionAnalyzer()
        analyzer.add_potential_exception(SymbolicException.concrete(ValueError))
        ok, message = analyzer.verify_raises_contract(RaisesContract(ValueError))
        assert (ok, message) == (True, None)

    def test_verify_raises_contract_with_feasible_symbolic_exception(self) -> None:
        """Scenario: symbolic exception feasible in context; expected contract satisfied."""
        analyzer = ExceptionAnalyzer()
        x = z3.Int("raises_contract_feasible_x")
        analyzer.add_potential_exception(SymbolicException.symbolic("e", ValueError, x > 0))

        ok, message = analyzer.verify_raises_contract(
            RaisesContract(ValueError),
            [x > 1],
        )

        assert (ok, message) == (True, None)

    def test_verify_raises_contract_with_infeasible_symbolic_exception(self) -> None:
        """Scenario: symbolic exception impossible in context; expected explicit failure."""
        analyzer = ExceptionAnalyzer()
        x = z3.Int("raises_contract_infeasible_x")
        analyzer.add_potential_exception(SymbolicException.symbolic("e", ValueError, x > 0))

        ok, message = analyzer.verify_raises_contract(
            RaisesContract(ValueError),
            [x < 0],
        )

        assert ok is False
        assert message is not None
        assert "No ValueError exceptions are feasible" in message

    def test_verify_raises_contract_reports_solver_unknown_as_inconclusive(self) -> None:
        """Scenario: feasibility solver returns unknown; expected inconclusive diagnostic."""
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        analyzer = ExceptionAnalyzer(solver)
        x = z3.Int("raises_contract_unknown_x")
        analyzer.add_potential_exception(SymbolicException.symbolic("e", ValueError, x > 0))

        ok, message = analyzer.verify_raises_contract(
            RaisesContract(ValueError),
            [x > -10],
        )

        assert ok is False
        assert message is not None
        assert "inconclusive" in message
        assert "unknown" in message

    def test_verify_raises_contract_check_failure_is_inconclusive(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Scenario: solver check fails; expected inconclusive diagnostic."""
        analyzer = ExceptionAnalyzer()
        x = z3.Int("raises_contract_add_failure_x")
        analyzer.add_potential_exception(SymbolicException.symbolic("e", ValueError, x > 0))

        def raising_check(*assumptions: z3.BoolRef, need_model: bool = False) -> SolverResult:
            _ = assumptions, need_model
            raise z3.Z3Exception("forced raises-contract check failure")

        monkeypatch.setattr(analyzer.solver, "check", raising_check)

        ok, message = analyzer.verify_raises_contract(
            RaisesContract(ValueError),
            [x > -10],
        )

        assert ok is False
        assert message is not None
        assert "inconclusive" in message
        assert "unknown" in message
        assert getattr(analyzer.solver, "_scope_depth") == 0

    def test_verify_raises_contract_check_unknown_is_inconclusive(
        self,
        monkeypatch: MonkeyPatch,
    ) -> None:
        """Scenario: solver check returns UNKNOWN; expected inconclusive diagnostic."""
        analyzer = ExceptionAnalyzer()
        x = z3.Int("raises_contract_pop_failure_x")
        analyzer.add_potential_exception(SymbolicException.symbolic("e", ValueError, x > 0))

        def unknown_check(*assumptions: z3.BoolRef, need_model: bool = False) -> SolverResult:
            _ = assumptions, need_model
            return SolverResult.unknown()

        monkeypatch.setattr(analyzer.solver, "check", unknown_check)

        ok, message = analyzer.verify_raises_contract(
            RaisesContract(ValueError),
            [x > -10],
        )

        assert ok is False
        assert message is not None
        assert "inconclusive" in message
        assert "unknown" in message

    def test_check_unhandled_exceptions(self) -> None:
        """Scenario: one propagated exception path; expected one unhandled exception."""
        analyzer = ExceptionAnalyzer()
        state = ExceptionState()
        exc = SymbolicException.concrete(ValueError)
        path = state.raise_exception(exc)
        path.propagated = True
        assert analyzer.check_unhandled_exceptions(state) == [exc]

    def test_analyze_division(self) -> None:
        """Scenario: concrete divisor zero; expected concrete ZeroDivisionError exception."""
        analyzer = ExceptionAnalyzer()
        exc = analyzer.analyze_division(0, pc=1)
        assert exc is not None and exc.type_name == "ZeroDivisionError"

    def test_analyze_index_access(self) -> None:
        """Scenario: index access with unknown object shape; expected no synthesized exception."""
        analyzer = ExceptionAnalyzer()
        assert analyzer.analyze_index_access(object(), 0, pc=1) is None

    def test_analyze_key_access(self) -> None:
        """Scenario: key access without known container semantics; expected symbolic KeyError."""
        analyzer = ExceptionAnalyzer()
        exc = analyzer.analyze_key_access({}, "k", pc=2)
        assert exc is not None and exc.type_name == "KeyError"

    def test_analyze_attribute_access(self) -> None:
        """Scenario: attribute access on None; expected concrete AttributeError."""
        analyzer = ExceptionAnalyzer()
        exc = analyzer.analyze_attribute_access(None, "x", pc=2)
        assert exc is not None and exc.type_name == "AttributeError"

    def test_analyze_assertion(self) -> None:
        """Scenario: false assertion condition; expected concrete AssertionError."""
        analyzer = ExceptionAnalyzer()
        exc = analyzer.analyze_assertion(False, "boom", pc=3)
        assert exc is not None and exc.type_name == "AssertionError"
