from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/specialized/infinite_loop.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.specialized.infinite_loop import InfiniteLoopDetector


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


class TestInfiniteLoopDetector:
    """Test suite for pysymex.analysis.detectors.specialized.InfiniteLoopDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = InfiniteLoopDetector()
        instr = MockInstr("JUMP_BACKWARD")
        state = Mock(pc=1)

        d._max_iterations = 2
        assert d.check(state, instr, lambda c: True) is None
        assert d.check(state, instr, lambda c: True) is None
        issue = d.check(state, instr, lambda c: True)
        assert issue is not None
        assert issue.kind.name == "INFINITE_LOOP"
