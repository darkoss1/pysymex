from __future__ import annotations

import pytest

import pysymex.models.builtins as builtins_models
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.models.builtins.base import FunctionModel, is_raised_exception_effect


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize("model", [builtins_models.BytesModel(), builtins_models.BytearrayModel()])
def test_binary_constructors_report_definite_source_failures(model: FunctionModel) -> None:
    invalid_type = model.apply([None], {}, _state())
    negative_count = model.apply([-1], {}, _state())

    invalid_effect = invalid_type.side_effects.get("raised_exception")
    negative_effect = negative_count.side_effects.get("raised_exception")
    assert is_raised_exception_effect(invalid_effect)
    assert invalid_effect["exception_type"] == "TypeError"
    assert is_raised_exception_effect(negative_effect)
    assert negative_effect["exception_type"] == "ValueError"


@pytest.mark.parametrize("model", [builtins_models.BytesModel(), builtins_models.BytearrayModel()])
def test_binary_constructors_report_invalid_codec_forms(model: FunctionModel) -> None:
    invalid_results = [
        model.apply(["a"], {}, _state()),
        model.apply([1, "utf-8"], {}, _state()),
        model.apply(["a"], {"errors": "ignore"}, _state()),
    ]

    for result in invalid_results:
        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize("model", [builtins_models.BytesModel(), builtins_models.BytearrayModel()])
def test_binary_constructors_report_invalid_encoding_and_errors_types(
    model: FunctionModel,
) -> None:
    invalid_results = [
        model.apply(["a", 1], {}, _state()),
        model.apply(["a", "ascii", 1], {}, _state()),
        model.apply(["a"], {"encoding": 1}, _state()),
        model.apply(["a", "ascii"], {"errors": 1}, _state()),
    ]

    for result in invalid_results:
        effect = result.side_effects.get("raised_exception")
        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


def test_bytes_constructor_retains_exact_bytes_payload_and_type() -> None:
    result = builtins_models.BytesModel().apply([b"\x01"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [1]
    assert getattr(result.value, "_type", None) == "bytes"


def test_bytes_constructor_retains_zero_filled_integer_size() -> None:
    result = builtins_models.BytesModel().apply([1], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [0]
    assert getattr(result.value, "_type", None) == "bytes"


def test_bytes_constructor_no_args_is_bytes_typed_empty_payload() -> None:
    result = builtins_models.BytesModel().apply([], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == []
    assert getattr(result.value, "_type", None) == "bytes"


def test_bytes_constructor_retains_exact_encoded_string_payload() -> None:
    result = builtins_models.BytesModel().apply(["A", "ascii"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [65]
    assert getattr(result.value, "_type", None) == "bytes"


def test_bytearray_constructor_retains_exact_encoded_string_payload() -> None:
    result = builtins_models.BytearrayModel().apply(["A", "ascii"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [65]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_binary_constructors_retain_encoded_nul_payload() -> None:
    bytes_result = builtins_models.BytesModel().apply(["\x00", "latin1"], {}, _state())
    bytearray_result = builtins_models.BytearrayModel().apply(["\x00", "latin1"], {}, _state())

    assert isinstance(bytes_result.value, SymbolicList)
    assert bytes_result.value.concrete_items == [0]
    assert getattr(bytes_result.value, "_type", None) == "bytes"
    assert isinstance(bytearray_result.value, SymbolicList)
    assert bytearray_result.value.concrete_items == [0]
    assert getattr(bytearray_result.value, "_type", None) == "bytearray"


def test_bytes_constructor_applies_exact_encoding_errors() -> None:
    result = builtins_models.BytesModel().apply(["é", "ascii", "ignore"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == []
    assert getattr(result.value, "_type", None) == "bytes"


def test_frozenset_constructor_rejects_definite_non_iterable() -> None:
    result = builtins_models.FrozensetModel().apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_memoryview_constructor_rejects_definite_non_buffer() -> None:
    result = builtins_models.MemoryviewModel().apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
