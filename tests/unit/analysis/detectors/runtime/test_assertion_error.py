from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/runtime/assertion_error.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.runtime.assertion_error import AssertionErrorDetector


def MockInstr(
    opname: str, argval: object = None, argrepr: str = "", arg: int = 0, offset: int = 10
) -> dis.Instruction:
    import dis

    def _dummy() -> None:
        pass

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

    def test_check(self) -> None:
        """Test check behavior."""
        d = AssertionErrorDetector()
        instr = MockInstr("RAISE_VARARGS", 1)
        err = Mock()
        err.name = "AssertionError"
        state = Mock(stack=[err], path_constraints=[], pc=1)
        state.peek = Mock(return_value=err)
        issue = d.check(state, instr, lambda c: True)
        assert issue is not None
        assert issue.kind.name == "ASSERTION_ERROR"
