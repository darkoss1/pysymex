"""Tests for pysymex/analysis/detectors/specialized/null_dereference.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.specialized.null_dereference import (
    NullDereferenceDetector,
    pure_check_null_deref,
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


class TestNullDereferenceDetector:
    """Test suite for pysymex.analysis.detectors.specialized.NullDereferenceDetector."""

    def test_check(self) -> None:
        """Test check behavior."""
        d = NullDereferenceDetector()
        instr = MockInstr("LOAD_ATTR", argval="attr")
        state = Mock(stack=[Mock()], pc=1, path_constraints=[])

        assert d.check(state, instr, lambda c: False) is None


def test_pure_check_null_deref_exists() -> None:
    """Test pure_check_null_deref behavior."""
    assert callable(pure_check_null_deref)
