"""Tests for pysymex/analysis/detectors/logical/t4_interprocedural/range_propagation.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.logical.t4_interprocedural.range_propagation import (
    NumericRangePropagationRule,
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


class TestNumericRangePropagationRule:
    """Test suite for NumericRangePropagationRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert NumericRangePropagationRule is not None
        assert NumericRangePropagationRule.__name__ == "NumericRangePropagationRule"
