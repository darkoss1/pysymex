from __future__ import annotations

import pytest

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.iterables import SortedModel, SumModel
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect
from pysymex.typing import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    ("model", "argument"),
    [
        (SortedModel(), SymbolicValue.from_const(1)),
        (SumModel(), 1),
        (SumModel(), SymbolicValue.from_const(1)),
    ],
)
def test_aggregate_builtins_reject_definite_non_iterables(
    model: FunctionModel, argument: StackValue
) -> None:
    result = model.apply([argument], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
