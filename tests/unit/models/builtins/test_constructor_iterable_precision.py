"""Focused constructor precision tests for exact literal iterables."""

from __future__ import annotations

import dataclasses

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.constructors.collections import ListModel
from pysymex._internal.models.builtins.types.containers.tuples.construction import (
    TupleConstructorModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def test_list_constructor_materializes_concrete_symbolic_string_chars() -> None:
    result = ListModel().apply([SymbolicString.from_const("ab")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a", "b"]


def test_list_constructor_materializes_modeled_bytes_as_integer_items() -> None:
    result = ListModel().apply([SymbolicValue.from_const(b"\x01")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [1]


def test_list_constructor_drops_source_runtime_type_tag() -> None:
    """list(tuple-like storage) returns a list rather than leaking source identity."""
    source = dataclasses.replace(SymbolicList.from_const([1]), _type="tuple")

    result = ListModel().apply([source], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [1]
    assert getattr(result.value, "_type", None) is None


def test_tuple_constructor_materializes_concrete_symbolic_string_chars() -> None:
    result = TupleConstructorModel().apply([SymbolicString.from_const("a")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a"]
    assert getattr(result.value, "_type", None) == "tuple"


def test_empty_tuple_constructor_retains_tuple_runtime_type() -> None:
    result = TupleConstructorModel().apply([], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type", None) == "tuple"
