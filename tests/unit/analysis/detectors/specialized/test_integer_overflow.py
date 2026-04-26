"""Tests for pysymex/analysis/detectors/specialized/integer_overflow.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.specialized.integer_overflow import (
    IntegerOverflowDetector,
    pure_check_bounded_overflow,
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


class TestIntegerOverflowDetector:
    """Test suite for pysymex.analysis.detectors.specialized.IntegerOverflowDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = IntegerOverflowDetector()
        instr = MockInstr("BINARY_OP", argrepr="+")
        state = Mock(stack=[1, 2], path_constraints=[])
        assert d.check(state, instr, lambda c: True) is None


def test_pure_check_bounded_overflow_exists() -> None:
    """Test pure_check_bounded_overflow behavior."""
    assert callable(pure_check_bounded_overflow)
