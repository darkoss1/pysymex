from __future__ import annotations

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.truth import AllModel, AnyModel
from pysymex._internal.models.builtins.registry.builtin_models import builtin_models
from pysymex._internal.models.builtins.sequences.len import LenModel
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult
from pysymex._internal.typing.protocols import StackValue


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


def test_builtin_family_discovery_apply() -> None:
    for model in builtin_models():
        if not isinstance(model, FunctionModel):
            continue
        result = model.apply([], {}, _state())
        assert isinstance(result, ModelResult)
