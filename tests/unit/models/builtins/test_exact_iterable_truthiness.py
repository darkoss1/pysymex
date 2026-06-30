"""Focused model tests for exact iterable truthiness builtins."""

from __future__ import annotations

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.constructors.collections import ListModel
from pysymex._internal.models.builtins.iteration.lazy import FilterModel
from pysymex._internal.models.builtins.iteration.truth import AllModel, AnyModel


def _state() -> VMState:
    return VMState(pc=0)


def test_any_model_materializes_zero_byte_as_false() -> None:
    result = AnyModel().apply([SymbolicValue.from_const(b"\x00")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is False


def test_any_model_materializes_nonzero_byte_as_true() -> None:
    result = AnyModel().apply([SymbolicValue.from_const(b"\x01")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_all_model_materializes_empty_bytes_as_true() -> None:
    result = AllModel().apply([SymbolicValue.from_const(b"")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_filter_none_materializes_zero_byte_as_empty_list() -> None:
    filter_result = FilterModel().apply(
        [None, SymbolicValue.from_const(b"\x00")],
        {},
        _state(),
    )

    assert isinstance(filter_result.value, SymbolicIterator)

    list_result = ListModel().apply([filter_result.value], {}, _state())
    assert isinstance(list_result.value, SymbolicList)
    assert list_result.value.concrete_items == []


def test_filter_none_materializes_nonzero_byte_item() -> None:
    filter_result = FilterModel().apply(
        [None, SymbolicValue.from_const(b"\x01")],
        {},
        _state(),
    )

    assert isinstance(filter_result.value, SymbolicIterator)

    list_result = ListModel().apply([filter_result.value], {}, _state())
    assert isinstance(list_result.value, SymbolicList)
    assert list_result.value.concrete_items == [1]
