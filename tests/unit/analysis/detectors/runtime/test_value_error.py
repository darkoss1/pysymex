"""Tests for pysymex/analysis/detectors/runtime/value_error.py."""

from __future__ import annotations

import dis
from typing import cast

import z3

from pysymex._typing import StackValue
from pysymex.analysis.detectors.runtime.value_error import ValueErrorDetector
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue


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
    """Test suite for pysymex.analysis.detectors.base.ValueErrorDetector."""

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

    def test_check_reports_invalid_int_literal_with_base(self) -> None:
        """Report VALUE_ERROR for int() conversion when literal is invalid for explicit base."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=2, argval=2)
        state = VMState(stack=[int, "2", 2], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_invalid_fromhex_literal(self) -> None:
        """Report VALUE_ERROR for bytes.fromhex() conversion with invalid hex token."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)

        class _FromHexCallable:
            __name__ = "fromhex"

        state = VMState(
            stack=[cast("StackValue", _FromHexCallable()), "zz"],
            path_constraints=[],
            pc=1,
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_min_empty_iterable(self) -> None:
        """Report VALUE_ERROR for min([]), matching CPython empty-sequence behavior."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        state = VMState(stack=[min, []], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is not None
        assert issue.kind.name == "VALUE_ERROR"

    def test_check_ignores_min_nonempty_iterable(self) -> None:
        """Do not report VALUE_ERROR for min() on a known nonempty iterable."""
        detector = ValueErrorDetector()
        instruction = _make_instruction("CALL", arg=1, argval=1)
        state = VMState(stack=[min, [1]], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

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


def _is_sat(constraints: list[z3.BoolRef]) -> bool:
    solver = z3.Solver()
    solver.add(*constraints)
    return solver.check() == z3.sat
