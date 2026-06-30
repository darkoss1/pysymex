from __future__ import annotations

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.aggregates import SortedModel, SumModel
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


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

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
