"""Tests for pysymex/analysis/detectors/logical/t3_path/post_assignment.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.logical.t3_path.post_assignment import (
    PostAssignmentContradictionRule,
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


class TestPostAssignmentContradictionRule:
    """Test suite for PostAssignmentContradictionRule."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert PostAssignmentContradictionRule is not None
        assert PostAssignmentContradictionRule.__name__ == "PostAssignmentContradictionRule"
