from __future__ import annotations

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.constructors.object import MemoryviewModel
from pysymex._internal.models.builtins.memoryview.methods import (
    MemoryviewCastModel,
    MemoryviewHexModel,
    MemoryviewReleaseModel,
    MemoryviewTobytesModel,
    MemoryviewTolistModel,
)
from pysymex._internal.models.contracts.results import ModelResult, SideEffects
from pysymex._internal.typing.protocols import StackValue


def _receiver() -> StackValue:
    return SymbolicValue.symbolic("memoryview_receiver")[0]


def _assert_type_error(result: ModelResult) -> None:
    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def _assert_value_error(result: ModelResult) -> None:
    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "ValueError"


def test_memoryview_receiver_only_methods_reject_invalid_calls() -> None:
    receiver = _receiver()
    for model in (MemoryviewTolistModel(), MemoryviewReleaseModel()):
        assert "raised_exception" not in model.apply([receiver], {}, VMState()).side_effects
        _assert_type_error(model.apply([], {}, VMState()))
        _assert_type_error(model.apply([receiver, 1], {}, VMState()))
        _assert_type_error(model.apply([receiver], {"extra": 1}, VMState()))


def test_memoryview_release_uses_canonical_symbolic_none_result() -> None:
    """Side-effect-only builtin methods return the shared symbolic None carrier."""
    result = MemoryviewReleaseModel().apply([_receiver()], {}, VMState())

    assert isinstance(result.value, SymbolicNoneType)


def test_memoryview_tolist_does_not_force_nonempty_buffers_empty() -> None:
    """Unknown source shape must not be under-approximated as an empty list."""
    result = MemoryviewTolistModel().apply([_receiver()], {}, VMState())

    assert isinstance(result.value, SymbolicList)
    solver = z3.Solver()
    solver.add(*result.constraints, result.value.z3_len > 0)
    assert solver.check() == z3.sat


def test_memoryview_methods_preserve_exact_bytes_source() -> None:
    """Exact constructor sources flow through core memoryview conversion methods."""
    receiver_result = MemoryviewModel().apply([b"\x01\xff"], {}, VMState())
    receiver = receiver_result.value

    tobytes = MemoryviewTobytesModel().apply([receiver], {}, VMState())
    tolist = MemoryviewTolistModel().apply([receiver], {}, VMState())
    hexadecimal = MemoryviewHexModel().apply([receiver, ":", 1], {}, VMState())

    assert isinstance(tobytes.value, SymbolicList)
    assert tobytes.value.concrete_items == [1, 255]
    assert getattr(tobytes.value, "_type", None) == "bytes"
    assert isinstance(tolist.value, SymbolicList)
    assert tolist.value.concrete_items == [1, 255]
    assert isinstance(hexadecimal.value, SymbolicString)
    assert hexadecimal.value.z3_str.as_string() == "01:ff"


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
