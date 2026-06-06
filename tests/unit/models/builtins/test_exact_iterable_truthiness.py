"""Focused model tests for exact iterable truthiness builtins."""

from __future__ import annotations

import pysymex.models.builtins as builtins
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue


def _state() -> VMState:
    return VMState(pc=0)


def test_any_model_materializes_zero_byte_as_false() -> None:
    result = builtins.AnyModel().apply([SymbolicValue.from_const(b"\x00")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is False


def test_any_model_materializes_nonzero_byte_as_true() -> None:
    result = builtins.AnyModel().apply([SymbolicValue.from_const(b"\x01")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_all_model_materializes_empty_bytes_as_true() -> None:
    result = builtins.AllModel().apply([SymbolicValue.from_const(b"")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_filter_none_materializes_zero_byte_as_empty_list() -> None:
    filter_result = builtins.FilterModel().apply(
        [None, SymbolicValue.from_const(b"\x00")],
        {},
        _state(),
    )

    assert isinstance(filter_result.value, SymbolicIterator)

    list_result = builtins.ListModel().apply([filter_result.value], {}, _state())
    assert isinstance(list_result.value, SymbolicList)
    assert list_result.value.concrete_items == []


def test_filter_none_materializes_nonzero_byte_item() -> None:
    filter_result = builtins.FilterModel().apply(
        [None, SymbolicValue.from_const(b"\x01")],
        {},
        _state(),
    )

    assert isinstance(filter_result.value, SymbolicIterator)

    list_result = builtins.ListModel().apply([filter_result.value], {}, _state())
    assert isinstance(list_result.value, SymbolicList)
    assert list_result.value.concrete_items == [1]
