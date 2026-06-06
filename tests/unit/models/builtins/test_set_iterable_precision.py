"""Focused set and frozenset iterable precision tests."""

from __future__ import annotations

from typing import cast

import pysymex.models.builtins as builtins
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.sequences import SymbolicSet
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.typing import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_next_symbolic_set_iterator_returns_retained_member_and_advances() -> None:
    source = cast(StackValue, SymbolicSet.from_const({3}))
    iterator_result = builtins.IterModel().apply([source], {}, _state())
    iterator = iterator_result.value
    assert isinstance(iterator, SymbolicIterator)

    result = builtins.NextModel().apply([iterator], {}, _state())

    assert result.value == 3
    mutation = cast("dict[str, object]", result.side_effects.get("iterator_mutation"))
    assert isinstance(mutation, dict)
    updated = mutation["updated_iterator"]
    assert isinstance(updated, SymbolicIterator)
    assert updated.index == 1


def test_list_constructor_materializes_modeled_set_members() -> None:
    result = builtins.ListModel().apply([cast(StackValue, {4})], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [4]


def test_frozenset_constructor_materializes_exact_members() -> None:
    result = builtins.FrozensetModel().apply([cast(StackValue, {5})], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type") == "frozenset"
    assert result.value.concrete_items == [5]


def test_list_constructor_materializes_frozenset_members() -> None:
    frozen_result = builtins.FrozensetModel().apply([cast(StackValue, {6})], {}, _state())

    result = builtins.ListModel().apply([frozen_result.value], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [6]


def test_set_constructor_rejects_exact_unhashable_members() -> None:
    source = cast(StackValue, [[1]])

    result = builtins.SetModel().apply([source], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_frozenset_constructor_rejects_exact_unhashable_members() -> None:
    source = cast(StackValue, [[1]])

    result = builtins.FrozensetModel().apply([source], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
