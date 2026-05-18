"""Tests for pysymex/analysis/detectors/runtime/assertion_error.py."""

from __future__ import annotations

import dis

from pysymex.analysis.detectors.runtime.assertion_error import AssertionErrorDetector
from pysymex.core.state import VMState


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


class TestAssertionErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.AssertionErrorDetector."""

    def test_check_reports_assertion_by_stack_marker(self) -> None:
        """Report ASSERTION_ERROR when stack top clearly contains AssertionError."""
        detector = AssertionErrorDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[AssertionError],
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_assertion_by_recent_load_assertion_opcode(self) -> None:
        """Report ASSERTION_ERROR when recent bytecode contains LOAD_ASSERTION_ERROR."""
        detector = AssertionErrorDetector()
        load_assertion = _make_instruction("LOAD_ASSERTION_ERROR", offset=0)
        raise_assertion = _make_instruction("RAISE_VARARGS", arg=1, argval=1, offset=2)
        state = VMState(
            stack=[int],
            path_constraints=[],
            pc=1,
            current_instructions=[load_assertion, raise_assertion],
        )
        issue = detector.check(state, raise_assertion, lambda _constraints: True)
        assert issue is not None

    def test_check_reports_explicit_assertion_error_constructor_raise(self) -> None:
        """Report ASSERTION_ERROR for explicit ``raise AssertionError(...)`` bytecode."""
        detector = AssertionErrorDetector()
        load_assertion = _make_instruction(
            "LOAD_GLOBAL", argval="AssertionError", argrepr="AssertionError + NULL", offset=0
        )
        call_assertion = _make_instruction("CALL", arg=1, argval=1, offset=2)
        raise_assertion = _make_instruction("RAISE_VARARGS", arg=1, argval=1, offset=3)
        state = VMState(
            stack=[int],
            path_constraints=[],
            pc=2,
            current_instructions=[load_assertion, call_assertion, raise_assertion],
        )

        issue = detector.check(state, raise_assertion, lambda _constraints: True)

        assert issue is not None

    def test_check_ignores_non_assertion_raise(self) -> None:
        """Return None when raised value is not related to AssertionError."""
        detector = AssertionErrorDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[ValueError],
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _constraints: True)
        assert issue is None

    def test_check_ignores_unsat_assertion_path(self) -> None:
        """Return None when assertion path constraints are unsatisfiable."""
        detector = AssertionErrorDetector()
        instruction = _make_instruction("RAISE_VARARGS", arg=1, argval=1)
        state = VMState(
            stack=[AssertionError],
            path_constraints=[],
            pc=1,
            current_instructions=[instruction],
        )
        issue = detector.check(state, instruction, lambda _constraints: False)
        assert issue is None
