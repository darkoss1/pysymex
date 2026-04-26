"""Tests for pysymex/analysis/detectors/runtime/type_error.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.runtime.type_error import TypeErrorDetector


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


class TestTypeErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.TypeErrorDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = TypeErrorDetector()
        instr = MockInstr("BINARY_OP", "+", "+")
        state = Mock(stack=[1, 2], path_constraints=[], pc=1)
        assert d.check(state, instr, lambda c: True) is None
