"""Tests for pysymex/_internal/analysis/detectors/runtime/unbound/variable.py."""

from __future__ import annotations

import dis
import time

import z3

from pysymex._internal.analysis.detectors.runtime.unbound.variable import UnboundVariableDetector
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.solver.engine.context import SolverContext
from pysymex._internal.core.solver.engine.incremental import IncrementalSolver
from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.state.types import UNBOUND


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


class TestUnboundVariableDetector:
    """Test suite for pysymex._internal.analysis.detectors.detector.UnboundVariableDetector."""

    def test_check_reports_unbound_load_fast(self) -> None:
        """Report UNBOUND_VARIABLE for LOAD_FAST when local is UNBOUND."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_FAST", "x")
        state = VMState(stack=[], path_constraints=[], pc=1)
        state.set_local("x", UNBOUND)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_unbound_load_name(self) -> None:
        """Report UNBOUND_VARIABLE for LOAD_NAME missing in locals/globals."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_NAME", "missing_name")
        state = VMState(stack=[], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_missing_load_global_as_name_error(self) -> None:
        """Report NAME_ERROR for a missing global before LOAD_GLOBAL fallback modeling."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_GLOBAL", "missing_global")
        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is not None
        assert issue.kind is IssueKind.NAME_ERROR

    def test_check_reports_unbound_builtin_shadow_load_fast(self) -> None:
        """Builtin-looking local names still raise UnboundLocalError when local-bound."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_FAST_CHECK", "len")
        state = VMState(stack=[], path_constraints=[], pc=1)
        state.set_local("len", UNBOUND)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is not None
        assert issue.kind is IssueKind.UNBOUND_VARIABLE

    def test_check_reports_missing_load_fast_check(self) -> None:
        """LOAD_FAST_CHECK raises UnboundLocalError when a fast local was never assigned."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_FAST_CHECK", "late")
        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is not None
        assert issue.kind is IssueKind.UNBOUND_VARIABLE

    def test_check_ignores_builtin_load_global(self) -> None:
        """Builtins resolved after global lookup should not be reported as missing globals."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_GLOBAL", "any")
        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_ignores_bound_load_name_in_globals(self) -> None:
        """Return None for LOAD_NAME when symbol exists in globals."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_NAME", "configured")
        state = VMState(stack=[], path_constraints=[], pc=1)
        state.set_global("configured", 1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_builtin_name(self) -> None:
        """Return None for builtins resolved by LOAD_NAME."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_NAME", "len")
        state = VMState(stack=[], path_constraints=[], pc=1)
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_builtin_exception_name(self) -> None:
        """Return None for builtin exception classes resolved by LOAD_NAME."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_NAME", "ZeroDivisionError")
        state = VMState(stack=[], path_constraints=[], pc=1)

        issue = detector.check(state, instruction, lambda _constraints: True)

        assert issue is None

    def test_check_does_not_report_definite_issue_on_solver_unknown(self) -> None:
        """Solver UNKNOWN must not become a definite unbound-variable issue."""
        detector = UnboundVariableDetector()
        instruction = _make_instruction("LOAD_FAST", "x")
        state = VMState(stack=[], path_constraints=[z3.Bool("unbound_path")], pc=2)
        state.set_local("x", UNBOUND)
        solver = IncrementalSolver(timeout_ms=1000)
        solver.set_deadline(time.perf_counter() - 1.0)
        token = SolverContext.active.set(solver)
        try:
            issue = detector.check(state, instruction, lambda _constraints: True)
        finally:
            SolverContext.active.reset(token)

        assert issue is None
