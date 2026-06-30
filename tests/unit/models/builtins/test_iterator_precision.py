"""Focused builtin iterator precision tests."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.callable_iterators import CallableSentinelIterator
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.builtins.iteration.iter_model import IterModel
from pysymex._internal.models.builtins.iteration.next_model import NextModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_next_symbolic_dict_iterator_returns_retained_key_and_advances() -> None:
    iterator_result = IterModel().apply([SymbolicDict.from_const({3: 1})], {}, _state())
    iterator = iterator_result.value
    assert isinstance(iterator, SymbolicIterator)

    result = NextModel().apply([iterator], {}, _state())

    assert result.value == 3
    mutation = cast("dict[str, object]", result.side_effects.get("iterator_mutation"))
    assert isinstance(mutation, dict)
    updated = mutation["updated_iterator"]
    assert isinstance(updated, SymbolicIterator)
    assert updated.index == 1


def test_next_empty_symbolic_dict_iterator_raises_stop_iteration() -> None:
    iterator = SymbolicIterator("dict_iter", SymbolicDict.from_const({}))

    result = NextModel().apply([iterator], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "StopIteration"


def test_next_symbolic_bytes_iterator_returns_integer_byte_and_advances() -> None:
    source = cast(StackValue, SymbolicBytes.concrete(b"\x01"))
    iterator_result = IterModel().apply([source], {}, _state())
    iterator = iterator_result.value
    assert isinstance(iterator, SymbolicIterator)

    result = NextModel().apply([iterator], {}, _state())

    assert result.value == 1
    mutation = cast("dict[str, object]", result.side_effects.get("iterator_mutation"))
    assert isinstance(mutation, dict)
    updated = mutation["updated_iterator"]
    assert isinstance(updated, SymbolicIterator)
    assert updated.index == 1


def test_next_empty_symbolic_bytes_iterator_raises_stop_iteration() -> None:
    iterator = SymbolicIterator("bytes_iter", SymbolicBytes.concrete(b""))

    result = NextModel().apply([iterator], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "StopIteration"


def test_next_symbolic_string_iterator_returns_character_and_advances() -> None:
    iterator_result = IterModel().apply([SymbolicString.from_const("a")], {}, _state())
    iterator = iterator_result.value
    assert isinstance(iterator, SymbolicIterator)

    result = NextModel().apply([iterator], {}, _state())

    assert result.value == "a"
    mutation = cast("dict[str, object]", result.side_effects.get("iterator_mutation"))
    assert isinstance(mutation, dict)
    updated = mutation["updated_iterator"]
    assert isinstance(updated, SymbolicIterator)
    assert updated.index == 1


def test_next_empty_symbolic_string_iterator_raises_stop_iteration() -> None:
    iterator = SymbolicIterator("string_iter", SymbolicString.from_const(""))

    result = NextModel().apply([iterator], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "StopIteration"


def test_two_argument_iter_returns_callable_sentinel_iterator() -> None:
    def producer() -> int:
        return 1

    result = IterModel().apply([producer, 0], {}, _state())

    assert isinstance(result.value, CallableSentinelIterator)
    assert result.value.producer is producer
    assert result.value.sentinel == 0
    assert "raised_exception" not in result.side_effects
