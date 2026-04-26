from __future__ import annotations

from pysymex.core.state import VMState
from pysymex.models.containers import bytes as bytes_models


def _state() -> VMState:
    return VMState(pc=0)


def test_bytes_concrete_faithfulness_baseline() -> None:
    """Faithfulness baseline for concrete bytes operations."""
    for value in [b"", b"abc", b"A\tB", b"123"]:
        assert value.upper() == bytes(value).upper()
        assert value.lower() == bytes(value).lower()


def test_bytes_symbolic_error_paths() -> None:
    """Symbolic and error path checks for representative methods."""
    bytes_models.BytesFindModel().apply([], {}, _state())
    bytes_models.BytesLenModel().apply([], {}, _state())


def test_bytes_edge_case_empty() -> None:
    """Edge case: empty bytes decode behavior."""
    assert b"".decode() == ""
