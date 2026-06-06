from __future__ import annotations

import pytest

import pysymex.models.builtins as builtins_models
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.havoc import HavocValue
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.typing import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize("producer", [1, "value", [1]])
def test_two_argument_iter_rejects_definite_non_callable_producer(producer: StackValue) -> None:
    result = builtins_models.IterModel().apply([producer, None], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_next_on_opaque_generator_returns_havoc_without_type_error() -> None:
    source, _constraint = SymbolicList.symbolic("generator_source")
    generator = SymbolicIterator("generator", source, is_generator=True)

    result = builtins_models.NextModel().apply([generator], {}, _state())

    assert isinstance(result.value, HavocValue)
    assert "raised_exception" not in result.side_effects
