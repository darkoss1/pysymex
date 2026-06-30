"""Focused model tests for min()/max() over exact non-list iterables."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.numeric.max import MaxModel
from pysymex._internal.models.builtins.numeric.min import MinModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_min_model_materializes_modeled_bytes_item() -> None:
    result = MinModel().apply([SymbolicValue.from_const(b"\x01")], {}, _state())

    assert result.value == 1


def test_min_model_reports_empty_bytes_value_error() -> None:
    result = MinModel().apply([SymbolicValue.from_const(b"")], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "ValueError"


def test_max_model_materializes_modeled_bytes_item() -> None:
    result = MaxModel().apply([SymbolicValue.from_const(b"\x01")], {}, _state())

    assert result.value == 1


def test_min_model_materializes_string_character() -> None:
    result = MinModel().apply(["ba"], {}, _state())

    assert result.value == "a"


def test_max_model_materializes_dict_key() -> None:
    source = cast(StackValue, {2: "b", 1: "a"})
    result = MaxModel().apply([source], {}, _state())

    assert result.value == 2
