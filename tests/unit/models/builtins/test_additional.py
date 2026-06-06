from __future__ import annotations

import pytest

from pysymex.typing import StackValue
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import ModelResult
from pysymex.models.builtins.core.len import LenModel
from pysymex.models.builtins.extended.registry import EXTENDED_MODELS
from pysymex.models.builtins.extended.truth import AllModel, AnyModel


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize("values", [[], [1], [1, 2, 3], [0, 0, 0]])
def test_len_model_parametrized_faithfulness(values: list[int]) -> None:
    args: list[StackValue] = [list(values)]
    result = LenModel().apply(args, {}, _state())
    assert result.value == len(values)


@pytest.mark.parametrize("items", [[], [1], [0, 1, 2], [False, True]])
def test_all_any_parametrized_faithfulness(items: list[int | bool]) -> None:
    def _bool_value(value: StackValue) -> bool:
        if isinstance(value, SymbolicValue) and isinstance(value.value, bool):
            return value.value
        return bool(value)

    stack_items: list[StackValue] = [*items]
    args: list[StackValue] = [stack_items]
    all_res = AllModel().apply(args, {}, _state())
    any_res = AnyModel().apply(args, {}, _state())
    assert _bool_value(all_res.value) == all(items)
    assert _bool_value(any_res.value) == any(items)


def test_extended_auto_discovery_apply() -> None:
    for model in EXTENDED_MODELS:
        result = model.apply([], {}, _state())
        assert isinstance(result, ModelResult)
