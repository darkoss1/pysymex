from importlib import import_module

from pytest import MonkeyPatch
import z3

from pysymex.core.exceptions.analyzer.core import ExceptionAnalyzer
from pysymex.core.exceptions.categories import ExceptionCategory, get_exception_category
from pysymex.core.exceptions.contracts import RaisesContract, raises
from pysymex.core.exceptions.objects import (
    ExceptionHandler,
    ExceptionOccurrenceResult,
    ExceptionOccurrenceStatus,
    FinallyHandler,
    SymbolicException,
    TryBlock,
)
from pysymex.core.exceptions.state import ExceptionState


def test_core_exception_exports_use_direct_owners() -> None:
    import pysymex.core as core

    assert core.ExceptionAnalyzer is ExceptionAnalyzer
    assert core.ExceptionHandler is ExceptionHandler
    assert core.ExceptionState is ExceptionState
    assert core.SymbolicException is SymbolicException


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
    categories = import_module("pysymex.core.exceptions.categories")
    contracts = import_module("pysymex.core.exceptions.contracts")
    objects = import_module("pysymex.core.exceptions.objects")
    state = import_module("pysymex.core.exceptions.state")

    assert ExceptionCategory is categories.ExceptionCategory
    assert SymbolicException is objects.SymbolicException
    assert ExceptionOccurrenceResult is objects.ExceptionOccurrenceResult
    assert ExceptionOccurrenceStatus is objects.ExceptionOccurrenceStatus
    assert ExceptionState is state.ExceptionState
    assert RaisesContract is contracts.RaisesContract


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


class TestExceptionHandler:
    """Test suite for ExceptionHandler."""

    def test_catches(self) -> None:
        """Scenario: broad handler catches specific exception instance."""
        handler = ExceptionHandler((Exception,), target_pc=1)
        exc = SymbolicException.concrete(ValueError)
        assert handler.catches(exc) is True

    def test_catches_type(self) -> None:
        """Scenario: Exception handler catches ValueError type."""
        handler = ExceptionHandler((Exception,), target_pc=1)
        assert handler.catches_type(ValueError) is True


class TestFinallyHandler:
    """Test suite for FinallyHandler."""

    def test_initialization(self) -> None:
        """Scenario: finally handler stores target and exit PCs."""
        fh = FinallyHandler(target_pc=10, exit_pc=20)
        assert (fh.target_pc, fh.exit_pc) == (10, 20)


class TestExceptionState:
    """Test suite for ExceptionState."""

    def test_push_try(self) -> None:
        """Scenario: push try block; expected stack size increments."""
        state = ExceptionState()
        block = TryBlock(0, 1)
        state.push_try(block)
        assert len(state.try_stack) == 1

    def test_pop_try(self) -> None:
        """Scenario: pop after push; expected same try block returned."""
        state = ExceptionState()
        block = TryBlock(0, 1)
        state.push_try(block)
        assert state.pop_try() == block

    def test_current_try(self) -> None:
        """Scenario: one stacked try block; expected current_try returns it."""
        state = ExceptionState()
        block = TryBlock(0, 1)
        state.push_try(block)
        assert state.current_try() == block

    def test_raise_exception(self) -> None:
        """Scenario: raise exception in state; expected current_exception updated."""
        state = ExceptionState()
        exc = SymbolicException.concrete(ValueError)
        _ = state.raise_exception(exc)
        assert state.current_exception == exc

    def test_handle_exception(self) -> None:
        """Scenario: matching handler in try stack; expected returned target PC."""
        state = ExceptionState()
        handler = ExceptionHandler((ValueError,), target_pc=7)
        state.push_try(TryBlock(0, 10, handlers=[handler]))
        handled, pc = state.handle_exception(SymbolicException.concrete(ValueError))
        assert (handled, pc) == (handler, 7)

    def test_clear_exception(self) -> None:
        """Scenario: clear existing current exception; expected None."""
        state = ExceptionState(current_exception=SymbolicException.concrete(ValueError))
        state.clear_exception()
        assert state.current_exception is None

    def test_suppress(self) -> None:
        """Scenario: suppress current exception; expected exception added to suppressed list."""
        exc = SymbolicException.concrete(ValueError)
        state = ExceptionState(current_exception=exc)
        state.suppress(exc)
        assert state.suppressed == [exc]

    def test_clone(self) -> None:
        """Scenario: clone state; expected separate object with copied stack."""
        state = ExceptionState(try_stack=[TryBlock(0, 1)])
        clone = state.clone()
        assert clone is not state


class TestRaisesContract:
    """Test suite for RaisesContract."""

    def test_type_name(self) -> None:
        """Scenario: contract from type class; expected class name."""
        contract = RaisesContract(ValueError)
        assert contract.type_name == "ValueError"

    def test_matches(self) -> None:
        """Scenario: ValueError contract and matching concrete exception; expected true."""
        contract = RaisesContract(ValueError)
        exc = SymbolicException.concrete(ValueError)
        assert contract.matches(exc) is True


def test_raises() -> None:
    """Scenario: @raises decorator application; expected __raises__ contract list attached."""

    @raises(ValueError)
    def f() -> None:
        return None

    assert hasattr(f, "__raises__")
