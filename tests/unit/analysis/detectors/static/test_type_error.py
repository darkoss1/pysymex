from pysymex.analysis.detectors.types import TypeEnvironment, DetectionContext
from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/static/type_error.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.static.type_error import StaticTypeErrorDetector


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


class TestStaticTypeErrorDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticTypeErrorDetector."""

    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticTypeErrorDetector().issue_kind().name == "TYPE_ERROR"

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticTypeErrorDetector()
        assert d.should_check(create_mock_ctx(MockInstr("BINARY_OP"))) is True
        assert d.should_check(create_mock_ctx(MockInstr("CALL"))) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticTypeErrorDetector()
        instr0 = MockInstr("NOP", offset=0)
        instr1 = MockInstr("LOAD_CONST", argval=1, offset=2)
        instr2 = MockInstr("LOAD_CONST", argval="a", offset=4)
        instr3 = MockInstr("BINARY_OP", argrepr="+", offset=6)
        env = TypeEnvironment()
        ctx = DetectionContext(Mock(), [instr0, instr1, instr2, instr3], 6, instr3, 10, env)
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind.name == "TYPE_ERROR"


def create_mock_ctx(instr):
    from unittest.mock import Mock

    ctx = Mock()
    ctx.instruction = instr
    return ctx
