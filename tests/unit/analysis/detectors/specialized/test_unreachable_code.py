from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/specialized/unreachable_code.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.specialized.unreachable_code import UnreachableCodeDetector


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


class TestUnreachableCodeDetector:
    """Test suite for pysymex.analysis.detectors.specialized.UnreachableCodeDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = UnreachableCodeDetector()
        instr = MockInstr("NOP")
        state = Mock(path_constraints=["c1"], pc=1)
        issue = d.check(state, instr, lambda c: False)
        assert issue is None
