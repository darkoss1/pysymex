"""Tests for pysymex/analysis/detectors/specialized/helpers.py."""

from unittest.mock import Mock, patch
import z3
import dis
import pytest
from pysymex.analysis.detectors.specialized.helpers import (
    HasName,
    get_named_value_name,
    resolve_target_name,
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


class TestHasName:
    """Test suite for HasName."""

    def test_initialization(self) -> None:
        """Test basic initialization and properties."""
        assert HasName is not None
        assert HasName.__name__ == "HasName"


def test_get_named_value_name_exists() -> None:
    """Test get_named_value_name behavior."""
    assert callable(get_named_value_name)


def test_resolve_target_name_exists() -> None:
    """Test resolve_target_name behavior."""
    assert callable(resolve_target_name)
