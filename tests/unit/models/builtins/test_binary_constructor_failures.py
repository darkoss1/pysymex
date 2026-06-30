from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.bytes.constructors import BytearrayModel, BytesModel
from pysymex._internal.models.builtins.constructors.object import MemoryviewModel
from pysymex._internal.models.builtins.constructors.set import FrozensetModel
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects


def _state() -> VMState:
    return VMState(pc=0)


@pytest.mark.parametrize("model", [BytesModel(), BytearrayModel()])
def test_binary_constructors_report_definite_source_failures(model: FunctionModel) -> None:
    invalid_type = model.apply([None], {}, _state())
    negative_count = model.apply([-1], {}, _state())

    invalid_effect = invalid_type.side_effects.get("raised_exception")
    negative_effect = negative_count.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(invalid_effect)
    assert invalid_effect["exception_type"] == "TypeError"
    assert SideEffects.is_raised_exception(negative_effect)
    assert negative_effect["exception_type"] == "ValueError"


@pytest.mark.parametrize("model", [BytesModel(), BytearrayModel()])
def test_binary_constructors_report_invalid_codec_forms(model: FunctionModel) -> None:
    invalid_results = [
        model.apply(["a"], {}, _state()),
        model.apply([1, "utf-8"], {}, _state()),
        model.apply(["a"], {"errors": "ignore"}, _state()),
    ]

    for result in invalid_results:
        effect = result.side_effects.get("raised_exception")
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize("model", [BytesModel(), BytearrayModel()])
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
        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


def test_bytes_constructor_retains_exact_bytes_payload_and_type() -> None:
    result = BytesModel().apply([b"\x01"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [1]
    assert getattr(result.value, "_type", None) == "bytes"


def test_bytes_constructor_retains_zero_filled_integer_size() -> None:
    result = BytesModel().apply([1], {}, _state())

    assert isinstance(result.value, SymbolicList)
    solver = z3.Solver()
    solver.add(*result.constraints, result.value.z3_len != 1)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(*result.constraints, result.value.element_expr_at(z3.IntVal(0)) != 0)
    assert solver.check() == z3.unsat
    assert getattr(result.value, "_type", None) == "bytes"


@pytest.mark.parametrize(
    ("model", "expected_type"),
    [
        (BytesModel(), "bytes"),
        (BytearrayModel(), "bytearray"),
    ],
)
def test_large_zero_filled_binary_constructor_is_compact_and_exact(
    model: FunctionModel, expected_type: str
) -> None:
    """Large literal counts retain exact length and zero contents without allocation."""
    count = 1_000_000_000
    result = model.apply([count], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items is None
    assert getattr(result.value, "_type", None) == expected_type
    solver = z3.Solver()
    solver.add(*result.constraints, result.value.z3_len != count)
    assert solver.check() == z3.unsat
    solver = z3.Solver()
    solver.add(*result.constraints, result.value.element_expr_at(z3.IntVal(999_999_999)) != 0)
    assert solver.check() == z3.unsat


def test_bytes_constructor_no_args_is_bytes_typed_empty_payload() -> None:
    result = BytesModel().apply([], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == []
    assert getattr(result.value, "_type", None) == "bytes"


def test_bytes_constructor_retains_exact_encoded_string_payload() -> None:
    result = BytesModel().apply(["A", "ascii"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [65]
    assert getattr(result.value, "_type", None) == "bytes"


def test_bytearray_constructor_retains_exact_encoded_string_payload() -> None:
    result = BytearrayModel().apply(["A", "ascii"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [65]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_binary_constructors_retain_encoded_nul_payload() -> None:
    bytes_result = BytesModel().apply(["\x00", "latin1"], {}, _state())
    bytearray_result = BytearrayModel().apply(["\x00", "latin1"], {}, _state())

    assert isinstance(bytes_result.value, SymbolicList)
    assert bytes_result.value.concrete_items == [0]
    assert getattr(bytes_result.value, "_type", None) == "bytes"
    assert isinstance(bytearray_result.value, SymbolicList)
    assert bytearray_result.value.concrete_items == [0]
    assert getattr(bytearray_result.value, "_type", None) == "bytearray"


def test_bytes_constructor_applies_exact_encoding_errors() -> None:
    result = BytesModel().apply(["é", "ascii", "ignore"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == []
    assert getattr(result.value, "_type", None) == "bytes"


def test_frozenset_constructor_rejects_definite_non_iterable() -> None:
    result = FrozensetModel().apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_memoryview_constructor_rejects_definite_non_buffer() -> None:
    result = MemoryviewModel().apply([1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_memoryview_constructor_sets_definite_runtime_affinity() -> None:
    result = MemoryviewModel().apply([b"value"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert z3.is_true(result.value.is_obj)
    assert z3.is_false(result.value.is_none)
    assert result.value.affinity_type == "memoryview"
