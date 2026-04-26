"""Tests for pysymex/analysis/detectors/static/helpers.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.static.helpers import caught_by_handler_reason


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


def test_caught_by_handler_reason_exists() -> None:
    """Test caught_by_handler_reason behavior."""
    assert callable(caught_by_handler_reason)
