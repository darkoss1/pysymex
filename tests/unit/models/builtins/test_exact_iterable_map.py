"""Focused model tests for exact map() iterator behavior."""

from __future__ import annotations

import pysymex.models.builtins as builtins
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.scalars.values import SymbolicValue


def _state() -> VMState:
    return VMState(pc=0)


def test_map_bool_materializes_zero_byte_as_false_iterator_item() -> None:
    result = builtins.MapModel().apply([bool, SymbolicValue.from_const(b"\x00")], {}, _state())
    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)

    item = builtins.NextModel().apply([iterator], {}, _state())

    assert item.value is False


def test_map_bool_materializes_nonzero_byte_as_true_iterator_item() -> None:
    result = builtins.MapModel().apply([bool, SymbolicValue.from_const(b"\x01")], {}, _state())
    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)

    item = builtins.NextModel().apply([iterator], {}, _state())

    assert item.value is True


def test_map_int_materializes_string_digit_as_integer_item() -> None:
    result = builtins.MapModel().apply([int, "1"], {}, _state())
    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)

    item = builtins.NextModel().apply([iterator], {}, _state())

    assert item.value == 1
