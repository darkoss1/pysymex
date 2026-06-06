from __future__ import annotations

import pytest

import pysymex.models.builtins as builtins_models
from pysymex.core.state.record import VMState
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect
from pysymex.typing import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    "model",
    [
        builtins_models.AiterModel(),
        builtins_models.AnextModel(),
    ],
)
@pytest.mark.parametrize("argument", [1, None, "value"])
def test_async_builtins_reject_definite_non_async_inputs(
    model: FunctionModel, argument: StackValue
) -> None:
    result = model.apply([argument], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
