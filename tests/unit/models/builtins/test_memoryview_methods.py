from __future__ import annotations

from pysymex.core.state.record import VMState
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import ModelResult, is_raised_exception_effect
from pysymex.models.builtins.extended.memoryview_complex import (
    MemoryviewCastModel,
    MemoryviewHexModel,
    MemoryviewReleaseModel,
    MemoryviewTobytesModel,
    MemoryviewTolistModel,
)
from pysymex.typing import StackValue


def _receiver() -> StackValue:
    return SymbolicValue.symbolic("memoryview_receiver")[0]


def _assert_type_error(result: ModelResult) -> None:
    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def _assert_value_error(result: ModelResult) -> None:
    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "ValueError"


def test_memoryview_receiver_only_methods_reject_invalid_calls() -> None:
    receiver = _receiver()
    for model in (MemoryviewTolistModel(), MemoryviewReleaseModel()):
        assert "raised_exception" not in model.apply([receiver], {}, VMState()).side_effects
        _assert_type_error(model.apply([], {}, VMState()))
        _assert_type_error(model.apply([receiver, 1], {}, VMState()))
        _assert_type_error(model.apply([receiver], {"extra": 1}, VMState()))


def test_memoryview_tobytes_enforces_order_binding() -> None:
    model = MemoryviewTobytesModel()
    receiver = _receiver()

    assert "raised_exception" not in model.apply([receiver], {"order": "C"}, VMState()).side_effects
    _assert_type_error(model.apply([], {}, VMState()))
    _assert_type_error(model.apply([receiver, "C"], {"order": "C"}, VMState()))
    _assert_type_error(model.apply([receiver], {"unexpected": "C"}, VMState()))
    _assert_type_error(model.apply([receiver, 1], {}, VMState()))
    _assert_value_error(model.apply([receiver, "bad"], {}, VMState()))


def test_memoryview_hex_enforces_optional_parameter_binding() -> None:
    model = MemoryviewHexModel()
    receiver = _receiver()
    valid_kwargs: dict[str, StackValue] = {"sep": ":", "bytes_per_sep": 1}

    assert "raised_exception" not in model.apply([receiver], valid_kwargs, VMState()).side_effects
    _assert_type_error(model.apply([], {}, VMState()))
    _assert_type_error(model.apply([receiver, ":"], {"sep": ":"}, VMState()))
    _assert_type_error(model.apply([receiver], {"unknown": ":"}, VMState()))
    _assert_type_error(model.apply([receiver, 1], {}, VMState()))
    _assert_type_error(model.apply([receiver, ":", "1"], {}, VMState()))
    _assert_value_error(model.apply([receiver, "::"], {}, VMState()))


def test_memoryview_cast_enforces_format_and_shape_binding() -> None:
    model = MemoryviewCastModel()
    receiver = _receiver()

    assert (
        "raised_exception" not in model.apply([receiver], {"format": "B"}, VMState()).side_effects
    )
    assert (
        "raised_exception"
        not in model.apply([receiver, "B"], {"shape": [1]}, VMState()).side_effects
    )
    _assert_type_error(model.apply([receiver], {"shape": [1]}, VMState()))
    _assert_type_error(model.apply([receiver, "B"], {"format": "B"}, VMState()))
    _assert_type_error(model.apply([receiver, "B", [1], 2], {}, VMState()))
    _assert_type_error(model.apply([receiver, 1], {}, VMState()))
    _assert_type_error(model.apply([receiver], {"format": None}, VMState()))
