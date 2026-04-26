from pysymex.analysis.detectors.types import TypeEnvironment, DetectionContext, PyType
from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/static/attribute_error.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.static.attribute_error import StaticAttributeErrorDetector


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


class TestStaticAttributeErrorDetector:
    """Test suite for pysymex.analysis.detectors.static.StaticAttributeErrorDetector."""

    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert StaticAttributeErrorDetector().issue_kind().name == "ATTRIBUTE_ERROR"

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = StaticAttributeErrorDetector()
        assert d.should_check(create_mock_ctx(MockInstr("LOAD_ATTR"))) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = StaticAttributeErrorDetector()
        instr0 = MockInstr("NOP", offset=0)
        instr1 = MockInstr("LOAD_FAST", argval="obj", offset=2)
        instr2 = MockInstr("LOAD_ATTR", argval="missing", offset=4)
        env = TypeEnvironment()
        env.set_type("obj", PyType.none_type())
        ctx = DetectionContext(Mock(), [instr0, instr1, instr2], 4, instr2, 10, env)
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind.name == "ATTRIBUTE_ERROR"


def create_mock_ctx(instr):
    from unittest.mock import Mock

    ctx = Mock()
    ctx.instruction = instr
    return ctx
