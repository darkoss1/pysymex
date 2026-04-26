"""Tests for pysymex/analysis/detectors/runtime/attribute_error.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.runtime.attribute_error import AttributeErrorDetector


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


class TestAttributeErrorDetector:
    """Test suite for pysymex.analysis.detectors.base.AttributeErrorDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = AttributeErrorDetector()
        instr = MockInstr("LOAD_ATTR", "attr")
        assert d.check(Mock(), instr, lambda c: True) is None
