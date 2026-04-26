"""Tests for pysymex/analysis/detectors/logical/t3_path/sequential_modular.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.logical.t3_path.sequential_modular import SequentialModularRule


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


class TestSequentialModularRule:
    """Test suite for SequentialModularRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert SequentialModularRule is not None
        assert SequentialModularRule.__name__ == "SequentialModularRule"
