from __future__ import annotations

import pytest

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.core.iterables import EnumerateModel, ZipModel
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect
from pysymex.typing import StackValue


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

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize("start", [1.0, SymbolicValue.from_const(1.0)])
def test_enumerate_rejects_definite_non_integer_start(start: StackValue) -> None:
    result = EnumerateModel().apply([[1]], {"start": start}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
