from __future__ import annotations

from pysymex.execution.opcodes.common import BUILTIN_TYPES


def test_builtin_types_contains_int() -> None:
    """Test BUILTIN_TYPES contains standard types."""
    assert "int" in BUILTIN_TYPES
    assert BUILTIN_TYPES["int"] == "int"


def test_builtin_types_contains_callable() -> None:
    """Test BUILTIN_TYPES contains callables."""
    assert "len" in BUILTIN_TYPES
    assert BUILTIN_TYPES["len"] == "callable"


def test_builtin_types_contains_exceptions() -> None:
    """Test BUILTIN_TYPES contains exceptions."""
    assert "ValueError" in BUILTIN_TYPES
    assert BUILTIN_TYPES["ValueError"] == "type"
