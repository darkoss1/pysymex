from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/specialized/resource_leak.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.specialized.resource_leak import (
    ResourceLeakDetector,
    get_named_value_name,
    resolve_target_name,
)


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
        assert d._open_resources == 1

        instr2 = MockInstr("RETURN_VALUE")
        issue = d.check(state1, instr2, lambda c: True)
        assert issue is not None
        assert issue.kind.name == "RESOURCE_LEAK"


def test_get_named_value_name_exists() -> None:
    """Test get_named_value_name behavior."""
    assert callable(get_named_value_name)


def test_resolve_target_name_exists() -> None:
    """Test resolve_target_name behavior."""
    assert callable(resolve_target_name)
