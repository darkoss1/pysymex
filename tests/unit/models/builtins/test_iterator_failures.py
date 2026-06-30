from __future__ import annotations

import pytest

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.havoc import HavocValue
from pysymex._internal.models.builtins.iteration.iter_model import IterModel
from pysymex._internal.models.builtins.iteration.next_model import NextModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize("producer", [1, "value", [1]])
def test_two_argument_iter_rejects_definite_non_callable_producer(producer: StackValue) -> None:
    result = IterModel().apply([producer, None], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_next_on_opaque_generator_returns_havoc_without_type_error() -> None:
    source, _constraint = SymbolicList.symbolic("generator_source")
    generator = SymbolicIterator("generator", source, is_generator=True)

    result = NextModel().apply([generator], {}, _state())

    assert isinstance(result.value, HavocValue)
    assert "raised_exception" not in result.side_effects
