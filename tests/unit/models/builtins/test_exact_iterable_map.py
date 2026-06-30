"""Focused model tests for exact map() iterator behavior."""

from __future__ import annotations

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.lazy import MapModel
from pysymex._internal.models.builtins.iteration.next_model import NextModel


def _state() -> VMState:
    return VMState(pc=0)


def test_map_bool_materializes_zero_byte_as_false_iterator_item() -> None:
    result = MapModel().apply([bool, SymbolicValue.from_const(b"\x00")], {}, _state())
    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)

    item = NextModel().apply([iterator], {}, _state())

    assert item.value is False


def test_map_bool_materializes_nonzero_byte_as_true_iterator_item() -> None:
    result = MapModel().apply([bool, SymbolicValue.from_const(b"\x01")], {}, _state())
    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)

    item = NextModel().apply([iterator], {}, _state())

    assert item.value is True


def test_map_int_materializes_string_digit_as_integer_item() -> None:
    result = MapModel().apply([int, "1"], {}, _state())
    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)

    item = NextModel().apply([iterator], {}, _state())

    assert item.value == 1
