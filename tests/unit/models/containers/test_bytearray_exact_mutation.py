"""Focused model tests for exact bytearray construction and append mutation."""

from __future__ import annotations

from typing import cast

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.builtins.bytes.constructors import BytearrayModel
from pysymex._internal.models.builtins.types.containers.bytes.bytearray.growth import (
    BytearrayAppendModel,
    BytearrayExtendModel,
    BytearrayInsertModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.bytearray.ordering import (
    BytearrayCopyModel,
    BytearrayReverseModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.bytearray.removal import (
    BytearrayClearModel,
    BytearrayPopModel,
    BytearrayRemoveModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def test_bytearray_constructor_retains_exact_bytes_payload() -> None:
    result = BytearrayModel().apply([b"\x01"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [1]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytearray_constructor_no_args_is_exact_bytearray_payload() -> None:
    result = BytearrayModel().apply([], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == []
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytearray_constructor_retains_zero_filled_integer_size() -> None:
    result = BytearrayModel().apply([1], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [0]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytearray_append_updates_exact_payload_at_old_length() -> None:
    receiver = BytearrayModel().apply([b"\x01"], {}, _state()).value
    assert isinstance(receiver, SymbolicList)

    result = BytearrayAppendModel().apply([receiver, 0], {}, _state())

    assert result.value is not None
    assert receiver.concrete_items == [1, 0]


def test_bytearray_extend_updates_exact_payload_from_old_length() -> None:
    receiver = BytearrayModel().apply([b"\x01"], {}, _state()).value
    assert isinstance(receiver, SymbolicList)

    result = BytearrayExtendModel().apply([receiver, b"\x02\x00"], {}, _state())

    assert result.value is not None
    assert receiver.concrete_items == [1, 2, 0]


def test_bytearray_insert_updates_exact_payload_at_normalized_index() -> None:
    receiver = BytearrayModel().apply([b"\x01"], {}, _state()).value
    assert isinstance(receiver, SymbolicList)

    result = BytearrayInsertModel().apply([receiver, 0, 0], {}, _state())

    assert result.value is not None
    assert receiver.concrete_items == [0, 1]


def test_bytearray_pop_returns_exact_byte_and_updates_payload() -> None:
    receiver = BytearrayModel().apply([b"\x01\x00"], {}, _state()).value
    assert isinstance(receiver, SymbolicList)

    result = BytearrayPopModel().apply([receiver], {}, _state())

    assert getattr(result.value, "value", None) == 0
    assert receiver.concrete_items == [1]


def test_bytearray_remove_updates_exact_payload() -> None:
    receiver = BytearrayModel().apply([b"\x00\x01"], {}, _state()).value
    assert isinstance(receiver, SymbolicList)

    result = BytearrayRemoveModel().apply([receiver, 0], {}, _state())

    assert result.value is not None
    assert receiver.concrete_items == [1]


def test_bytearray_remove_missing_exact_byte_reports_value_error() -> None:
    receiver = BytearrayModel().apply([b"\x01"], {}, _state()).value
    assert isinstance(receiver, SymbolicList)

    result = BytearrayRemoveModel().apply([receiver, 2], {}, _state())

    raised = cast("dict[str, object] | None", result.side_effects.get("raised_exception"))
    assert raised is not None
    assert raised["issue_kind"] == "VALUE_ERROR"


def test_bytearray_clear_removes_exact_payload() -> None:
    receiver = BytearrayModel().apply([b"\x00"], {}, _state()).value
    assert isinstance(receiver, SymbolicList)

    result = BytearrayClearModel().apply([receiver], {}, _state())

    assert result.value is not None
    assert receiver.concrete_items == []


def test_bytearray_copy_returns_independent_exact_payload() -> None:
    receiver = BytearrayModel().apply([b"\x00"], {}, _state()).value
    assert isinstance(receiver, SymbolicList)

    result = BytearrayCopyModel().apply([receiver], {}, _state())
    BytearrayClearModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [0]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytearray_reverse_updates_exact_payload_order() -> None:
    receiver = BytearrayModel().apply([b"\x01\x00"], {}, _state()).value
    assert isinstance(receiver, SymbolicList)

    result = BytearrayReverseModel().apply([receiver], {}, _state())

    assert result.value is not None
    assert receiver.concrete_items == [0, 1]
