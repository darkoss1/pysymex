"""Tests for pysymex/_internal/analysis/detectors/runtime/value_error.py."""

from __future__ import annotations

import dis
import time

import z3

from pysymex._internal.analysis.detectors.runtime.value.detector import ValueErrorDetector
from pysymex._internal.analysis.detectors.runtime.value.iterable.facts import (
    is_known_empty_iterable,
)
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create a deterministic instruction for detector unit tests."""

    def _dummy() -> None:
        """Provide bytecode for a template instruction."""
        return None

    template = next(dis.get_instructions(_dummy))
    return template._replace(
        opname=opname,
        opcode=dis.opmap.get(opname, 0),
        arg=arg,
        argval=argval,
        argrepr=argrepr,
        offset=offset,
    )


class TestValueErrorDetector:
    """Test suite for pysymex._internal.analysis.detectors.detector.ValueErrorDetector."""

    def test_check_reports_marker_from_locals(self) -> None:
        """Report VALUE_ERROR when local variable carries ValueError marker."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)

        class _Marker:
            _potential_exception = "ValueError"

        state = VMState(stack=[int, "123"], path_constraints=[], pc=1)
        state.set_local("x", _Marker())  # type: ignore[arg-type]  # Test-only marker object for detector signal path.
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_invalid_int_literal(self) -> None:
        """Report VALUE_ERROR for int() conversion with invalid string literal."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        state = VMState(stack=[int, "not-an-int"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_shadowed_int_literal_call(self) -> None:
        """Do not report ValueError when a source callable shadows builtin int."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)

        def shadowed_int(_value: object) -> int:
            return 1

        shadowed_int.__name__ = "int"
        state = VMState(stack=[shadowed_int, "not-an-int"], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_formats_symbolic_string_int_literal_diagnostic(self) -> None:
        """Diagnostics should show the exact string, not the symbolic wrapper repr."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        state = VMState(
            stack=[int, SymbolicString.from_const("12x")],
            path_constraints=[],
            pc=1,
        )

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is not None
        assert "invalid literal '12x'" in issue.message

    def test_check_reports_invalid_float_literal(self) -> None:
        """Report VALUE_ERROR for float() conversion with invalid string literal."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        state = VMState(stack=[float, "not-a-float"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_valid_int_literal(self) -> None:
        """Return None for int() conversion when literal is valid."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        state = VMState(stack=[int, "42"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_symbolic_bool_int_conversion(self) -> None:
        """Symbolic bool values carry an empty z3_str slot but are not string literals."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        value = SymbolicValue.from_const(False)
        state = VMState(stack=[int, value], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_reports_invalid_int_literal_with_base(self) -> None:
        """Report VALUE_ERROR for int() conversion when literal is invalid for explicit base."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)
        state = VMState(stack=[int, "2", 2], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_valid_int_literal_with_base(self) -> None:
        """Do not check explicit-base int() calls as base-10 conversions."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)
        state = VMState(stack=[int, "ff", 16], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_int_call_with_too_many_arguments(self) -> None:
        """Do not report ValueError for int() call shapes CPython rejects as TypeError."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=3, argval=3)
        state = VMState(stack=[int, "bad", 10, 0], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_invalid_fromhex_literal(self) -> None:
        """Report VALUE_ERROR for bytes.fromhex() conversion with invalid hex token."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)

        state = VMState(stack=[bytes.fromhex, "zz"], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_shadowed_fromhex_literal_call(self) -> None:
        """Do not report bytes.fromhex ValueError for a source callable named fromhex."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)

        def shadowed_fromhex(_value: object) -> bytes:
            return b"ok"

        shadowed_fromhex.__name__ = "fromhex"
        state = VMState(stack=[shadowed_fromhex, "zz"], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_ignores_fromhex_call_with_too_many_arguments(self) -> None:
        """Do not report ValueError when bytes.fromhex arity is a TypeError case."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)

        state = VMState(stack=[bytes.fromhex, "zz", 0], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_float_call_with_too_many_arguments(self) -> None:
        """Do not report ValueError for float() call shapes CPython rejects as TypeError."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)
        state = VMState(stack=[float, "bad", 0], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_reports_min_empty_iterable(self) -> None:
        """Report VALUE_ERROR for min([]), matching CPython empty-sequence behavior."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        state = VMState(stack=[min, []], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is not None
        assert issue.kind.name == "VALUE_ERROR"

    def test_check_reports_min_symbolic_length_proven_empty(self) -> None:
        """Report VALUE_ERROR when constraints prove a symbolic list is empty."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        symbolic_list, len_constraint = SymbolicList.symbolic("min_items")
        state = VMState(
            stack=[min, symbolic_list],
            path_constraints=[len_constraint, symbolic_list.z3_len == 0],
            pc=1,
        )

        issue = detector.check(state, instruction, _is_sat)

        assert issue is not None
        assert issue.kind.name == "VALUE_ERROR"

    def test_check_ignores_min_nonempty_iterable(self) -> None:
        """Do not report VALUE_ERROR for min() on a known nonempty iterable."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        state = VMState(stack=[min, [1]], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_known_empty_iterable_treats_solver_unknown_as_not_known(self) -> None:
        """Solver UNKNOWN must not prove symbolic iterable emptiness."""
        symbolic_list, len_constraint = SymbolicList.symbolic("unknown_min_items")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = SolverContext.active.set(solver)
        try:
            is_known_empty = is_known_empty_iterable(
                symbolic_list,
                [len_constraint, symbolic_list.z3_len == 0],
            )
        finally:
            SolverContext.active.reset(token)

        assert not is_known_empty

    def test_check_reports_range_zero_step(self) -> None:
        """Report VALUE_ERROR for range(start, stop, 0), matching CPython behavior."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=3, argval=3)
        state = VMState(stack=[range, 0, 10, 0], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _is_sat)

        assert issue is not None
        assert issue.kind.name == "VALUE_ERROR"

    def test_check_ignores_range_nonzero_step(self) -> None:
        """Do not report VALUE_ERROR for range() with a concrete nonzero step."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=3, argval=3)
        state = VMState(stack=[range, 0, 10, 2], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _is_sat)

        assert issue is None

    def test_check_reports_symbolic_range_zero_step(self) -> None:
        """Report VALUE_ERROR when a symbolic range step can be zero."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=3, argval=3)
        step, step_constraint = SymbolicValue.symbolic_int("step")
        state = VMState(stack=[range, 0, 10, step], path_constraints=[step_constraint], pc=1)

        issue = detector.check(state, instruction, _is_sat)

        assert issue is not None
        assert issue.kind.name == "VALUE_ERROR"
        counterexample = issue.get_counterexample()
        assert counterexample["step"] == 0

    def test_check_ignores_guarded_nonzero_symbolic_range_step(self) -> None:
        """Do not report range() when constraints prove the symbolic step is nonzero."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=3, argval=3)
        step, step_constraint = SymbolicValue.symbolic_int("step")
        state = VMState(
            stack=[range, 0, 10, step],
            path_constraints=[step_constraint, step.z3_int != 0],
            pc=1,
        )

        issue = detector.check(state, instruction, _is_sat)

        assert issue is None

    def test_check_reports_symbolic_negative_shift_count(self) -> None:
        """Report VALUE_ERROR when a symbolic shift count can be negative."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("BINARY_OP", arg=3, argrepr="<<")
        shift, shift_constraint = SymbolicValue.symbolic_int("shift")
        state = VMState(stack=[1, shift], path_constraints=[shift_constraint], pc=1)

        issue = detector.check(state, instruction, _is_sat)

        assert issue is not None
        assert issue.kind.name == "VALUE_ERROR"
        counterexample = issue.get_counterexample()
        assert isinstance(counterexample["shift"], int)
        assert counterexample["shift"] < 0

    def test_check_ignores_guarded_non_negative_shift_count(self) -> None:
        """Return None when path constraints prove the shift count is non-negative."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("BINARY_OP", arg=3, argrepr="<<")
        shift, shift_constraint = SymbolicValue.symbolic_int("shift")
        state = VMState(
            stack=[1, shift],
            path_constraints=[shift_constraint, shift.z3_int >= 0],
            pc=1,
        )

        issue = detector.check(state, instruction, _is_sat)

        assert issue is None

    def test_check_does_not_report_negative_shift_on_solver_unknown(self) -> None:
        """Solver UNKNOWN must not become a definite ValueError report."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("BINARY_OP", arg=3, argrepr="<<")
        shift, shift_constraint = SymbolicValue.symbolic_int("unknown_shift")
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = SolverContext.active.set(solver)
        try:
            issue = detector.check(
                VMState(stack=[1, shift], path_constraints=[shift_constraint], pc=1),
                instruction,
                lambda _constraints: True,
            )
        finally:
            SolverContext.active.reset(token)

        assert issue is None


def _is_sat(constraints: list[z3.BoolRef]) -> bool:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.sat
