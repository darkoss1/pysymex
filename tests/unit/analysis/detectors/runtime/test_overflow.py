"""Tests for pysymex/_internal/analysis/detectors/runtime/overflow.py."""

from __future__ import annotations

import dis
import time

from pysymex._internal.analysis.detectors.runtime.overflow import OverflowDetector
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.state.record import VMState
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


class TestOverflowDetector:
    """Test suite for pysymex._internal.analysis.detectors.detector.OverflowDetector."""

    def test_description_identifies_bounded_width_policy(self) -> None:
        """Keep the user-visible detector metadata honest about its numeric model."""
        assert OverflowDetector.description == "Detects bounded-width integer overflow"

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

    def test_check_does_not_report_definite_issue_on_solver_unknown(self) -> None:
        """Solver UNKNOWN must not become a definite overflow issue."""
        detector = OverflowDetector(bound_type="32bit")
        instruction = _make_instruction("BINARY_OP", argrepr="+")
        left, left_constraint = SymbolicValue.symbolic_int("unknown_overflow_left")
        right = SymbolicValue.from_const(1)
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = SolverContext.active.set(solver)
        try:
            issue = detector.check(
                VMState(stack=[left, right], path_constraints=[left_constraint], pc=1),
                instruction,
                lambda _constraints: True,
            )
        finally:
            SolverContext.active.reset(token)

        assert issue is None
