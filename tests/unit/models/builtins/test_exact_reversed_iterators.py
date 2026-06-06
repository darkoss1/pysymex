"""Focused model tests for exact reversed() iterator behavior."""

from __future__ import annotations

from typing import cast

import pysymex.models.builtins as builtins
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.typing import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_reversed_bytes_materializes_integer_items_in_reverse_order() -> None:
    result = builtins.ReversedModel().apply([SymbolicValue.from_const(b"\x01\x02")], {}, _state())

    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)
    assert iterator.iterable == [2, 1]


def test_reversed_string_materializes_characters_in_reverse_order() -> None:
    result = builtins.ReversedModel().apply(["ab"], {}, _state())

    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)
    assert iterator.iterable == ["b", "a"]


def test_reversed_dict_materializes_keys_in_reverse_insertion_order() -> None:
    source = cast("StackValue", {1: "a", 2: "b"})

    result = builtins.ReversedModel().apply([source], {}, _state())

    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)
    assert iterator.iterable == [2, 1]


def test_reversed_set_emits_type_error_side_effect() -> None:
    result = builtins.ReversedModel().apply([SymbolicValue.from_const({1})], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_second_next_on_reversed_singleton_emits_stop_iteration() -> None:
    result = builtins.ReversedModel().apply([[1]], {}, _state())
    iterator = result.value
    assert isinstance(iterator, SymbolicIterator)

    first = builtins.NextModel().apply([iterator], {}, _state())
    mutation = cast("dict[str, object]", first.side_effects.get("iterator_mutation"))
    updated = mutation["updated_iterator"]
    assert isinstance(updated, SymbolicIterator)

    second = builtins.NextModel().apply([updated], {}, _state())

    effect = second.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "StopIteration"
