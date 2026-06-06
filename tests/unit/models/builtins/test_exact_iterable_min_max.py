"""Focused model tests for min()/max() over exact non-list iterables."""

from __future__ import annotations

from typing import cast

import pysymex.models.builtins as builtins
from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import is_raised_exception_effect
from pysymex.typing import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def test_min_model_materializes_modeled_bytes_item() -> None:
    result = builtins.MinModel().apply([SymbolicValue.from_const(b"\x01")], {}, _state())

    assert result.value == 1


def test_min_model_reports_empty_bytes_value_error() -> None:
    result = builtins.MinModel().apply([SymbolicValue.from_const(b"")], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "ValueError"


def test_max_model_materializes_modeled_bytes_item() -> None:
    result = builtins.MaxModel().apply([SymbolicValue.from_const(b"\x01")], {}, _state())

    assert result.value == 1


def test_min_model_materializes_string_character() -> None:
    result = builtins.MinModel().apply(["ba"], {}, _state())

    assert result.value == "a"


def test_max_model_materializes_dict_key() -> None:
    source = cast(StackValue, {2: "b", 1: "a"})
    result = builtins.MaxModel().apply([source], {}, _state())

    assert result.value == 2
