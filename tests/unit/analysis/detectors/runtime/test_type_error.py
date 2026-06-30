"""Tests for pysymex/_internal/analysis/detectors/runtime/type_error.py."""

from __future__ import annotations

import dis
import time

from pysymex._internal.analysis.detectors.runtime.errors.type import TypeErrorDetector
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


def _make_instruction(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    def _dummy() -> None:
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


class TestTypeErrorDetector:
    """Test suite for pysymex._internal.analysis.detectors.detector.TypeErrorDetector."""

    def test_check_reports_plus_mismatch_with_symbolic_string(self) -> None:
        """Report TYPE_ERROR for `str + non-str` concatenation mismatch."""
        detector = TypeErrorDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="+")
        right, right_constraint = SymbolicValue.symbolic_int("not_string_value")
        state = VMState(
            stack=[SymbolicString.from_const("prefix"), right],
            path_constraints=[right_constraint],
            pc=1,
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_non_string_op_with_string_operand(self) -> None:
        """Report TYPE_ERROR for non-string operators involving strings."""
        detector = TypeErrorDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="/")
        state = VMState(
            stack=[SymbolicString.from_const("left"), SymbolicValue.from_const(1)],
            path_constraints=[],
            pc=2,
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_arg_based_operator_without_argrepr(self) -> None:
        """Decode operator from BINARY_OP arg when argrepr is empty."""
        detector = TypeErrorDetector()
        instruction = _make_instruction("BINARY_OP", arg=11, argrepr="")
        state = VMState(
            stack=[SymbolicString.from_const("left"), SymbolicValue.from_const(1)],
            path_constraints=[],
            pc=3,
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_ignores_internal_symbolic_attribute_placeholder(self) -> None:
        """Synthetic self/cls attribute placeholders are unknown, not definite TypeError."""
        detector = TypeErrorDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="+")
        internal_attr, type_constraint = SymbolicValue.symbolic("self.ready")
        state = VMState(
            stack=[internal_attr, SymbolicValue.from_const(1)],
            path_constraints=[type_constraint],
            pc=4,
        )

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_still_reports_external_symbolic_string_mismatch(self) -> None:
        """The synthetic-attribute suppression must not hide ordinary symbolic mismatches."""
        detector = TypeErrorDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="+")
        external_value, type_constraint = SymbolicValue.symbolic("external_value")
        state = VMState(
            stack=[external_value, SymbolicValue.from_const(1)],
            path_constraints=[type_constraint],
            pc=5,
        )

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is not None

    def test_check_does_not_report_definite_issue_on_solver_unknown(self) -> None:
        """Solver UNKNOWN must not become a definite TypeError issue."""
        detector = TypeErrorDetector()
        instruction = _make_instruction("BINARY_OP", argrepr="+")
        external_value, type_constraint = SymbolicValue.symbolic("unknown_type_operand")
        state = VMState(
            stack=[external_value, SymbolicValue.from_const(1)],
            path_constraints=[type_constraint],
            pc=6,
        )
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = SolverContext.active.set(solver)
        try:
            issue = detector.check(state, instruction, lambda _constraints: True)
        finally:
            SolverContext.active.reset(token)

        assert issue is None
