"""Tests for pysymex/analysis/detectors/runtime/division_by_zero.py."""

from __future__ import annotations

import dis
import time

import pytest
import z3

from pysymex.analysis.detectors.runtime.division_by_zero import (
    DivisionByZeroDetector,
    pure_check_division_by_zero,
)
from pysymex.core.solver.engine.context import active_incremental_solver
from pysymex.core.solver.engine.incremental import IncrementalSolver
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue


class _RecordingZ3Checker:
    """Run real Z3 checks while recording detector query routing."""

    def __init__(self) -> None:
        self.calls: list[list[z3.BoolRef]] = []

    def __call__(self, constraints: list[z3.BoolRef]) -> bool:
        self.calls.append(constraints)
        solver = z3.Solver()
        solver.add(*constraints)
        return solver.check() == z3.sat


def _template_instruction() -> dis.Instruction:
    """Return a stable instruction template for synthetic test instructions."""

    def _sentinel() -> None:
        """Provide a function that yields at least one bytecode instruction."""
        return None

    return next(dis.get_instructions(_sentinel))


def _make_instruction(
    opname: str,
    *,
    argval: object = None,
    argrepr: str = "",
    arg: int = 0,
    offset: int = 10,
) -> dis.Instruction:
    """Create a deterministic synthetic dis.Instruction for detector tests."""
    template = _template_instruction()
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


class TestDivisionByZeroDetector:
    """Validate division-by-zero detector behavior for division opcode patterns."""

    def test_check_reports_issue_for_true_division_symbol(self) -> None:
        """Report an issue when BINARY_OP uses '/' and divisor is concrete zero."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="/")
        state = VMState(stack=[1, 0], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    @pytest.mark.parametrize("binary_arg", [2, 6, 11, 15, 19, 24])
    def test_check_reports_issue_for_division_binary_args(self, binary_arg: int) -> None:
        """Report an issue for division/modulo BINARY_OP args even without argrepr."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("BINARY_OP", arg=binary_arg, argrepr="")
        state = VMState(stack=[3, 0], path_constraints=[], pc=8)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_non_division_binary_arg(self) -> None:
        """Return None when BINARY_OP arg does not represent division or modulo."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("BINARY_OP", arg=0, argrepr="")
        state = VMState(stack=[3, 0], path_constraints=[], pc=8)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_string_modulo_formatting(self) -> None:
        """Return None for '%' operations where the dividend is a concrete string."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="%")
        state = VMState(stack=["%s", 0], path_constraints=[], pc=4)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_issue_for_operator_truediv_call(self) -> None:
        """Report an issue for operator.truediv call indirection with zero divisor."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)

        class _TrueDivCallable:
            __name__ = "global_operator.truediv"

            def __call__(self, dividend: object, divisor: object) -> object:
                return dividend

        state = VMState(stack=[_TrueDivCallable(), None, 10.0, 0], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_routes_symbolic_binary_query_through_supplied_solver(self) -> None:
        """Use the executor-provided solver hook for symbolic BINARY_OP checks."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="/")
        divisor, type_constraint = SymbolicValue.symbolic("divisor")
        checker = _RecordingZ3Checker()
        state = VMState(stack=[10, divisor], path_constraints=[type_constraint], pc=1)

        issue = detector.check(state, instruction, checker)

        assert issue is not None
        assert len(checker.calls) == 1

    def test_check_reports_possible_issue_for_inconclusive_prefix(self) -> None:
        """An reached zero-divisor query over an inconclusive prefix remains reportable."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="/")
        divisor, type_constraint = SymbolicValue.symbolic("inconclusive_divisor")
        state = VMState(
            stack=[10, divisor],
            path_constraints=[type_constraint],
            last_inconclusive_feasibility_len=1,
            pc=9,
        )

        issue = detector.check(state, instruction, lambda _constraints: False)

        assert issue is not None
        assert issue.kind.name == "DIVISION_BY_ZERO"
        assert issue.model is None
        assert issue.confidence == 0.5
        assert "Path feasibility inconclusive" in issue.message

    def test_check_does_not_report_known_nonzero_symbolic_constant_prefix(self) -> None:
        """A locally nonzero divisor is not reportable even under an inconclusive prefix."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="%")
        prefix = z3.Bool("nonzero_constant_inconclusive_prefix")
        state = VMState(
            stack=[10, SymbolicValue.from_const(13)],
            path_constraints=[prefix],
            last_inconclusive_feasibility_len=1,
            pc=9,
        )

        issue = detector.check(state, instruction, lambda _constraints: False)

        assert issue is None

    def test_check_routes_symbolic_call_query_through_supplied_solver(self) -> None:
        """Use the executor-provided solver hook for symbolic operator-call checks."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)

        class _TrueDivCallable:
            __name__ = "operator.truediv"

            def __call__(self, dividend: object, divisor: object) -> object:
                return dividend

        divisor, type_constraint = SymbolicValue.symbolic("call_divisor")
        checker = _RecordingZ3Checker()
        state = VMState(
            stack=[_TrueDivCallable(), None, 10, divisor],
            path_constraints=[type_constraint],
            pc=1,
        )

        issue = detector.check(state, instruction, checker)

        assert issue is not None
        assert len(checker.calls) == 1

    def test_check_ignores_non_binary_operator_division_call(self) -> None:
        """Do not treat extra arguments to a binary division callable as divisors."""
        detector = DivisionByZeroDetector()
        instruction = _make_instruction("CALL", arg=3, argval=3)

        class _TrueDivCallable:
            __name__ = "operator.truediv"

            def __call__(self, dividend: object, divisor: object, extra: object) -> object:
                return dividend if extra is None else divisor

        checker = _RecordingZ3Checker()
        state = VMState(stack=[_TrueDivCallable(), None, 10, 2, 0], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, checker)

        assert issue is None
        assert checker.calls == []


def test_pure_check_division_by_zero_reports_issue_for_concrete_zero() -> None:
    """Return an issue when the divisor is a concrete zero."""
    issue = pure_check_division_by_zero(divisor=0, dividend=10, path_constraints=[], pc=5)
    assert issue is not None


def test_pure_check_division_by_zero_reports_issue_for_concrete_float_zero() -> None:
    """CPython raises ZeroDivisionError for true division by concrete float zero."""
    issue = pure_check_division_by_zero(
        divisor=0.0,
        dividend=10.0,
        path_constraints=[],
        pc=5,
        is_truediv=True,
    )
    assert issue is not None


def test_pure_check_division_by_zero_ignores_concrete_string_zero() -> None:
    """A concrete string divisor is a TypeError case, not division by zero."""
    issue = pure_check_division_by_zero(divisor="0", dividend=10, path_constraints=[], pc=5)
    assert issue is None


def test_pure_check_division_by_zero_returns_none_for_concrete_nonzero() -> None:
    """Return None when the divisor is a concrete non-zero value."""
    issue = pure_check_division_by_zero(divisor=2, dividend=10, path_constraints=[], pc=5)
    assert issue is None


def test_pure_check_division_by_zero_reports_symbolic_bool_false() -> None:
    """CPython treats False as integer zero in division and modulo operations."""
    divisor, constraint = SymbolicValue.symbolic_bool("denom")

    issue = pure_check_division_by_zero(
        divisor=divisor,
        dividend=10,
        path_constraints=[constraint],
        pc=5,
    )

    assert issue is not None


def test_pure_check_division_by_zero_does_not_report_definite_issue_on_solver_unknown() -> None:
    """Direct pure-helper use must not turn solver UNKNOWN into a definite issue."""
    divisor, type_constraint = SymbolicValue.symbolic("unknown_direct_divisor")
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        issue = pure_check_division_by_zero(divisor, 10, [type_constraint], pc=5)
    finally:
        active_incremental_solver.reset(token)

    assert issue is None


def test_pure_check_division_by_zero_reports_inconclusive_prefix_issue() -> None:
    """Explicit inconclusive-prefix evidence permits only a model-less possible issue."""
    divisor, type_constraint = SymbolicValue.symbolic("inconclusive_direct_divisor")

    issue = pure_check_division_by_zero(
        divisor=divisor,
        dividend=10,
        path_constraints=[type_constraint],
        pc=5,
        is_satisfiable_fn=lambda _constraints: False,
        last_inconclusive_feasibility_len=1,
    )

    assert issue is not None
    assert issue.kind.name == "DIVISION_BY_ZERO"
    assert issue.model is None
    assert issue.confidence == 0.5
    assert "Path feasibility inconclusive" in issue.message


def test_pure_check_division_by_zero_ignores_known_nonzero_symbolic_constant() -> None:
    """A constant symbolic wrapper around a nonzero divisor is locally safe."""
    prefix = z3.Bool("direct_nonzero_constant_inconclusive_prefix")

    issue = pure_check_division_by_zero(
        divisor=SymbolicValue.from_const(17),
        dividend=10,
        path_constraints=[prefix],
        pc=5,
        is_satisfiable_fn=lambda _constraints: False,
        last_inconclusive_feasibility_len=1,
    )

    assert issue is None


def test_pure_check_division_by_zero_ignores_guarded_nonzero_symbolic_int_prefix() -> None:
    """An inconclusive prefix must not report a locally contradicted zero-divisor query."""
    divisor, type_constraint = SymbolicValue.symbolic_int("guarded_nonzero_divisor")
    path_constraints = [type_constraint, divisor.z3_int != 0]

    issue = pure_check_division_by_zero(
        divisor=divisor,
        dividend=10,
        path_constraints=path_constraints,
        pc=5,
        is_satisfiable_fn=lambda _constraints: False,
        last_inconclusive_feasibility_len=len(path_constraints),
    )

    assert issue is None


def test_pure_check_concrete_zero_does_not_report_definite_issue_on_solver_unknown() -> None:
    """Concrete zero still requires a model-backed feasible path."""
    solver = IncrementalSolver(timeout_ms=1000)
    solver.set_deadline(time.perf_counter() - 1.0)
    token = active_incremental_solver.set(solver)
    try:
        issue = pure_check_division_by_zero(
            divisor=0,
            dividend=10,
            path_constraints=[z3.Bool("concrete_zero_path")],
            pc=5,
            is_satisfiable_fn=lambda _constraints: True,
        )
    finally:
        active_incremental_solver.reset(token)

    assert issue is None
