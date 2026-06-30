"""Focused model tests for exact non-list iterable builtins."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.aggregates import SortedModel, SumModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_sum_model_materializes_modeled_bytes_items() -> None:
    result = SumModel().apply([SymbolicValue.from_const(b"\x01")], {}, _state())

    assert result.value == 1


def test_sum_model_reports_string_items_type_error() -> None:
    result = SumModel().apply(["a"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_sorted_model_materializes_modeled_bytes_items() -> None:
    result = SortedModel().apply([SymbolicValue.from_const(b"\x02\x01")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [1, 2]


def test_sorted_model_materializes_dict_keys() -> None:
    source = cast(StackValue, {2: "b", 1: "a"})
    result = SortedModel().apply([source], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [1, 2]
