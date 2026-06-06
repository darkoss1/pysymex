"""Focused model tests for exact non-list iterable builtins."""

from __future__ import annotations

from typing import cast

import pysymex.models.builtins as builtins
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.typing import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_sum_model_materializes_modeled_bytes_items() -> None:
    result = builtins.SumModel().apply([SymbolicValue.from_const(b"\x01")], {}, _state())

    assert result.value == 1


def test_sum_model_reports_string_items_type_error() -> None:
    result = builtins.SumModel().apply(["a"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_sorted_model_materializes_modeled_bytes_items() -> None:
    result = builtins.SortedModel().apply([SymbolicValue.from_const(b"\x02\x01")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [1, 2]


def test_sorted_model_materializes_dict_keys() -> None:
    source = cast(StackValue, {2: "b", 1: "a"})
    result = builtins.SortedModel().apply([source], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [1, 2]
