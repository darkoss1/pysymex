from __future__ import annotations

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.reflection.identity import AiterModel, AnextModel
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize(
    "model",
    [
        AiterModel(),
        AnextModel(),
    ],
)
@pytest.mark.parametrize("argument", [1, None, "value"])
def test_async_builtins_reject_definite_non_async_inputs(
    model: FunctionModel, argument: StackValue
) -> None:
    result = model.apply([argument], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_async_builtins_declare_unknown_protocol_semantics() -> None:
    """Potential async protocol objects cannot produce silent symbolic success."""
    value, _constraint = SymbolicValue.symbolic("async_protocol_value")

    aiter_result = AiterModel().apply([value], {}, _state())
    anext_result = AnextModel().apply([value, 0], {}, _state())

    assert aiter_result.degradations[0].label == "builtin_aiter_protocol_unsupported"
    assert anext_result.degradations[0].label == "builtin_anext_protocol_unsupported"
