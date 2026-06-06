from __future__ import annotations

import pytest

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.iterables import FilterModel, MapModel
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect
from pysymex.typing import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (MapModel(), [str, 1]),
        (MapModel(), [str, [1], SymbolicValue.from_const(1)]),
        (FilterModel(), [None, 1]),
        (FilterModel(), [None, SymbolicValue.from_const(1)]),
    ],
)
def test_lazy_iterator_constructors_reject_definite_non_iterables(
    model: FunctionModel, args: list[StackValue]
) -> None:
    result = model.apply(args, {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
