from __future__ import annotations

import inspect

import pytest

from pysymex._typing import StackValue
from pysymex.core.state import VMState
from pysymex.core.types.scalars import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.builtins import core, extended


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize("values", [[], [1], [1, 2, 3], [0, 0, 0]])
def test_len_model_parametrized_faithfulness(values: list[int]) -> None:
    args: list[StackValue] = [list(values)]
    result = core.LenModel().apply(args, {}, _state())
    assert result.value == len(values)


@pytest.mark.parametrize("items", [[], [1], [0, 1, 2], [False, True]])
def test_all_any_parametrized_faithfulness(items: list[int | bool]) -> None:
    def _bool_value(value: StackValue) -> bool:
        if isinstance(value, SymbolicValue) and isinstance(value.value, bool):
            return value.value
        return bool(value)

    stack_items: list[StackValue] = [*items]
    args: list[StackValue] = [stack_items]
    all_res = extended.AllModel().apply(args, {}, _state())
    any_res = extended.AnyModel().apply(args, {}, _state())
    assert _bool_value(all_res.value) == all(items)
    assert _bool_value(any_res.value) == any(items)


def test_extended_auto_discovery_apply() -> None:
    classes: list[type[FunctionModel]] = []
    for _, obj in inspect.getmembers(extended, inspect.isclass):
        if obj.__module__ == extended.__name__ and issubclass(obj, FunctionModel) and obj is not FunctionModel:
            classes.append(obj)
    for cls in classes:
        model = cls()
        result = model.apply([], {}, _state())
        assert isinstance(result, ModelResult)
