"""Focused model tests for exact reversed() iterator behavior."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.next_model import NextModel
from pysymex._internal.models.builtins.iteration.reversed_model import ReversedModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_reversed_bytes_materializes_integer_items_in_reverse_order() -> None:
    result = ReversedModel().apply([SymbolicValue.from_const(b"\x01\x02")], {}, _state())

    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)
    assert iterator.iterable == [2, 1]


def test_reversed_string_materializes_characters_in_reverse_order() -> None:
    result = ReversedModel().apply(["ab"], {}, _state())

    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)
    assert iterator.iterable == ["b", "a"]


def test_reversed_dict_materializes_keys_in_reverse_insertion_order() -> None:
    source = cast("StackValue", {1: "a", 2: "b"})

    result = ReversedModel().apply([source], {}, _state())

    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)
    assert iterator.iterable == [2, 1]


def test_reversed_set_emits_type_error_side_effect() -> None:
    result = ReversedModel().apply([SymbolicValue.from_const({1})], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_second_next_on_reversed_singleton_emits_stop_iteration() -> None:
    result = ReversedModel().apply([[1]], {}, _state())
    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)

    first = NextModel().apply([iterator], {}, _state())
    mutation = cast("dict[str, object]", first.side_effects.get("iterator_mutation"))
    updated = mutation["updated_iterator"]
    assert isinstance(updated, SymbolicIterator)

    second = NextModel().apply([updated], {}, _state())

    effect = second.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "StopIteration"
