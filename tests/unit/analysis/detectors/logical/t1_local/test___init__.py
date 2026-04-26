"""Tests for pysymex/analysis/detectors/logical/t1_local/__init__.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.logical.t1_local import __all__


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


def test_exports() -> None:
    """Test module exports."""
    assert len(__all__) >= 0
    assert isinstance(__all__, list)
