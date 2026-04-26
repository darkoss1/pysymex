from pysymex.analysis.detectors.types import TypeEnvironment, DetectionContext
from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/static/assertion_error.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.static.assertion_error import StaticAssertionErrorDetector


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


class TestStaticAssertionErrorDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticAssertionErrorDetector."""

    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticAssertionErrorDetector().issue_kind().name == "ASSERTION_ERROR"

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticAssertionErrorDetector()
        assert d.should_check(create_mock_ctx(MockInstr("LOAD_ASSERTION_ERROR"))) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticAssertionErrorDetector()
        instr0 = MockInstr("NOP", offset=0)
        instr1 = MockInstr("LOAD_CONST", argval=False, offset=2)
        instr2 = MockInstr("LOAD_ASSERTION_ERROR", offset=4)
        ctx = DetectionContext(Mock(), [instr0, instr1, instr2], 4, instr2, 10, TypeEnvironment())
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind.name == "ASSERTION_ERROR"


def create_mock_ctx(instr):
    from unittest.mock import Mock

    ctx = Mock()
    ctx.instruction = instr
    return ctx
