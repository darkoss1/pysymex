"""Focused constructor precision tests for exact literal iterables."""

from __future__ import annotations

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.collections import ListModel
from pysymex.models.containers.tuples.construction import TupleModel


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


def test_tuple_constructor_materializes_concrete_symbolic_string_chars() -> None:
    result = TupleModel().apply([SymbolicString.from_const("a")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a"]
