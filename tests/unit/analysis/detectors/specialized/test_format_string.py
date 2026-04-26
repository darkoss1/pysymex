"""Tests for pysymex/analysis/detectors/specialized/format_string.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.specialized.format_string import FormatStringDetector


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


class TestFormatStringDetector:
    """Test suite for FormatStringDetector."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert FormatStringDetector is not None
        assert FormatStringDetector.__name__ == "FormatStringDetector"
