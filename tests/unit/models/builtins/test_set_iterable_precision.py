"""Focused set and frozenset iterable precision tests."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.models.builtins.constructors.collections import ListModel
from pysymex._internal.models.builtins.constructors.set import FrozensetModel
from pysymex._internal.models.builtins.iteration.iter_model import IterModel
from pysymex._internal.models.builtins.iteration.next_model import NextModel
from pysymex._internal.models.builtins.types.containers.sets.constructor import SetConstructorModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_next_symbolic_set_iterator_returns_retained_member_and_advances() -> None:
    source = cast(StackValue, SymbolicSet.from_const({3}))
    iterator_result = IterModel().apply([source], {}, _state())
    iterator = iterator_result.value
    assert isinstance(iterator, SymbolicIterator)

    result = NextModel().apply([iterator], {}, _state())

    assert result.value == 3
    mutation = cast("dict[str, object]", result.side_effects.get("iterator_mutation"))
    assert isinstance(mutation, dict)
    updated = mutation["updated_iterator"]
    assert isinstance(updated, SymbolicIterator)
    assert updated.index == 1


def test_list_constructor_materializes_modeled_set_members() -> None:
    result = ListModel().apply([cast(StackValue, {4})], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [4]


def test_frozenset_constructor_materializes_exact_members() -> None:
    result = FrozensetModel().apply([cast(StackValue, {5})], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type") == "frozenset"
    assert result.value.concrete_items == [5]


def test_list_constructor_materializes_frozenset_members() -> None:
    frozen_result = FrozensetModel().apply([cast(StackValue, {6})], {}, _state())

    result = ListModel().apply([frozen_result.value], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [6]


def test_set_constructor_rejects_exact_unhashable_members() -> None:
    source = cast(StackValue, [[1]])

    result = SetConstructorModel().apply([source], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_frozenset_constructor_rejects_exact_unhashable_members() -> None:
    source = cast(StackValue, [[1]])

    result = FrozensetModel().apply([source], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
