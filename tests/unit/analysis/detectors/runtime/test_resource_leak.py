from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/runtime/resource_leak.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.runtime.resource_leak import ResourceLeakDetector


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


class TestResourceLeakDetector:
    """Test suite for pysymex.analysis.detectors.specialized.ResourceLeakDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = ResourceLeakDetector()
        instr1 = MockInstr("CALL", arg=0)
        state1 = Mock(stack=[Mock(name="open", qualname="open")])
        d.check(state1, instr1, lambda c: True)
        assert d.check(None, instr1, lambda c: True) is None

        instr2 = MockInstr("RETURN_VALUE")
        issue = d.check(state1, instr2, lambda c: True)
        assert issue is None
