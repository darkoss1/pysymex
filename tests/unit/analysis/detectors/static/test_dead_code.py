from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/static/dead_code.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.static.dead_code import DeadCodeDetector


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


class TestDeadCodeDetector:
    """Test suite for pysymex.analysis.detectors.static.DeadCodeDetector."""

    def test_issue_kind(self) -> None:
        """Test issue_kind behavior."""
        assert DeadCodeDetector().issue_kind().name == "DEAD_CODE"

    def test_should_check(self) -> None:
        """Test should_check behavior."""
        d = DeadCodeDetector()
        ctx = create_mock_ctx(MockInstr("NOP"))
        assert d.should_check(ctx) is True
        ctx.flow_context = Mock()
        assert d.should_check(ctx) is True

    def test_check(self) -> None:
        """Test check behavior."""
        d = DeadCodeDetector()
        ctx = create_mock_ctx(MockInstr("NOP"))
        flow = Mock()
        flow.block = Mock(id=1)
        flow.analyzer.cfg.is_reachable.return_value = False
        ctx.flow_context = flow
        issue = d.check(ctx)
        assert issue is not None
        assert issue.kind.name == "DEAD_CODE"


def create_mock_ctx(instr):
    from unittest.mock import Mock

    ctx = Mock()
    ctx.instruction = instr
    return ctx
