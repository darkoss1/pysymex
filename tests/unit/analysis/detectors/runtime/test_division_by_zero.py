from pysymex.analysis.detectors.base import IssueKind

"""Tests for pysymex/analysis/detectors/runtime/division_by_zero.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.runtime.division_by_zero import (
    DivisionByZeroDetector,
    pure_check_division_by_zero,
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


class TestDivisionByZeroDetector:
    """Test suite for pysymex.analysis.detectors.base.DivisionByZeroDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = DivisionByZeroDetector()
        instr = MockInstr("BINARY_OP", "/", "/")
        state = Mock(stack=[1, 0], path_constraints=[], pc=1)
        issue = d.check(state, instr, lambda c: True)
        assert issue is not None
        assert issue.kind.name == "DIVISION_BY_ZERO"


def test_pure_check_division_by_zero_exists() -> None:
    """Test pure_check_division_by_zero behavior."""
    assert callable(pure_check_division_by_zero)
