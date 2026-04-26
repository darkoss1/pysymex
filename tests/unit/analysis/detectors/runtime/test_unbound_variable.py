from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/runtime/unbound_variable.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.runtime.unbound_variable import UnboundVariableDetector


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


class TestUnboundVariableDetector:
    """Test suite for pysymex.analysis.detectors.base.UnboundVariableDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = UnboundVariableDetector()
        instr = MockInstr("LOAD_FAST", "x")
        from pysymex.core.state import UNBOUND

        state = Mock(path_constraints=[], pc=1)
        state.get_local.return_value = UNBOUND
        issue = d.check(state, instr, lambda c: True)
        assert issue is not None
        assert issue.kind.name == "UNBOUND_VARIABLE"
