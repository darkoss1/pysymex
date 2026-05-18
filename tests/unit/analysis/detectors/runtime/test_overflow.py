"""Tests for pysymex/analysis/detectors/runtime/overflow.py."""

from __future__ import annotations

import dis

from pysymex.analysis.detectors.runtime.overflow import OverflowDetector
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


class TestOverflowDetector:
    """Test suite for pysymex.analysis.detectors.base.OverflowDetector."""

    def test_check_reports_addition_overflow_for_32bit_bounds(self) -> None:
        """Report OVERFLOW when 32-bit addition can exceed max bound."""
        detector = OverflowDetector(bound_type="32bit")
        instruction = _make_instruction("BINARY_OP", argrepr="+")
        left = SymbolicValue.from_const(2**31 - 1)
        right = SymbolicValue.from_const(1)
        state = VMState(stack=[left, right], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_arg_decoded_shift_assignment(self) -> None:
        """Decode BINARY_OP arg metadata even when argrepr is empty."""
        detector = OverflowDetector()
        instruction = _make_instruction("BINARY_OP", arg=16, argrepr="")
        state = VMState(stack=[1, 70], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_unsupported_operator(self) -> None:
        """Return None when operation is not tracked for overflow."""
        detector = OverflowDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="/")
        state = VMState(stack=[1, 2], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None
