from __future__ import annotations

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.aggregates import EnumerateModel, ZipModel
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (EnumerateModel(), [1]),
        (EnumerateModel(), [SymbolicValue.from_const(1)]),
        (ZipModel(), [[1], 1]),
        (ZipModel(), [SymbolicValue.from_const(1)]),
    ],
)
def test_sequence_iterator_constructors_reject_definite_non_iterables(
    model: FunctionModel, args: list[StackValue]
) -> None:
    result = model.apply(args, {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize("start", [1.0, SymbolicValue.from_const(1.0)])
def test_enumerate_rejects_definite_non_integer_start(start: StackValue) -> None:
    result = EnumerateModel().apply([[1]], {"start": start}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
