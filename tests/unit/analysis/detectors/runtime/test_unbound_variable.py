"""Tests for pysymex/analysis/detectors/runtime/unbound_variable.py."""

from __future__ import annotations

import dis

from pysymex.analysis.detectors.runtime.unbound_variable import UnboundVariableDetector
from pysymex.core.state import VMState, UNBOUND


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
    """Test suite for pysymex.analysis.detectors.base.UnboundVariableDetector."""

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
