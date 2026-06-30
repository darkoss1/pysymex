"""Tests for bounded integer overflow detection."""

from __future__ import annotations

import dis

import z3

from pysymex._internal.analysis.detectors.runtime.overflow import OverflowDetector
from pysymex._internal.core.state.record import VMState


def _always_sat(constraints: list[z3.BoolRef]) -> bool:
    """Always return True for satisfiability checks."""
    _ = constraints
    return True


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    """Create deterministic bytecode instructions for detector tests."""

    def _dummy() -> None:
        """Provide a stable instruction template."""
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


class TestOverflowDetectorBounded:
    """Test suite for bounded overflow detector behavior."""

    def test_initialization_sets_32bit_bounds(self) -> None:
        """Initialize min/max tracking correctly for 32 bits."""
        detector = OverflowDetector(bound_type="32bit")
        assert detector.min_val == -(2**31)
        assert detector.max_val == 2**31 - 1

    def test_initialization_sets_64bit_bounds(self) -> None:
        """Initialize min/max tracking correctly for 64 bits."""
        detector = OverflowDetector(bound_type="64bit")
        assert detector.min_val == -(2**63)
        assert detector.max_val == 2**63 - 1

    def test_check_reports_bounded_overflow(self) -> None:
        """Report overflow on feasible bounded BINARY_OP paths."""
        detector = OverflowDetector(bound_type="32bit")
        instruction = _make_instruction("BINARY_OP", argrepr="+")
        state = VMState(stack=[2**31 - 1, 1], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, _always_sat)
        assert issue is not None
        assert issue.kind.name == "OVERFLOW"
