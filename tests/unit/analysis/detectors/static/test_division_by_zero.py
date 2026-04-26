from pysymex.analysis.detectors.types import TypeEnvironment, DetectionContext
from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/static/division_by_zero.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.static.division_by_zero import StaticDivisionByZeroDetector


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


class TestStaticDivisionByZeroDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticDivisionByZeroDetector."""

    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticDivisionByZeroDetector().issue_kind().name == "DIVISION_BY_ZERO"

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticDivisionByZeroDetector()
        ctx = create_mock_ctx(MockInstr("BINARY_OP", argrepr="/"))
        assert d.should_check(ctx) is True
        ctx2 = create_mock_ctx(MockInstr("BINARY_OP", argrepr="+"))
        assert d.should_check(ctx2) is False

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticDivisionByZeroDetector()
        instr1 = MockInstr("LOAD_CONST", argval=0, offset=0)
        instr2 = MockInstr("BINARY_OP", argrepr="/", offset=2)
        env = TypeEnvironment()
        ctx = DetectionContext(Mock(), [instr1, instr2], 2, instr2, 10, env)
        issue = d.check(ctx)
        assert issue is not None
        assert "constant 0" in issue.message


def create_mock_ctx(instr):
    from unittest.mock import Mock

    ctx = Mock()
    ctx.instruction = instr
    return ctx
