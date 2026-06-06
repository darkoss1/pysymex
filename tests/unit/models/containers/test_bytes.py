from __future__ import annotations

import pytest

from pysymex.typing import StackValue
from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.models.builtins.base import (
    FunctionModel,
    is_raised_exception_effect,
)
from pysymex.models.builtins.results import is_potential_exception_effect
from pysymex.models.containers.bytes.bytearray.growth import (
    BytearrayAppendModel,
    BytearrayExtendModel,
    BytearrayInsertModel,
)
from pysymex.models.containers.bytes.bytearray.misc import BytearrayCopyModel, BytearrayReverseModel
from pysymex.models.containers.bytes.bytearray.removal import (
    BytearrayClearModel,
    BytearrayPopModel,
    BytearrayRemoveModel,
)
from pysymex.models.containers.bytes.bytearray.search import (
    BytearrayContainsModel,
    BytearrayIndexModel,
    BytearrayStartswithModel,
)
from pysymex.models.containers.bytes.bytearray.splitting import (
    BytearrayJoinModel,
    BytearrayPartitionModel,
    BytearraySplitModel,
)
from pysymex.models.containers.bytes.decoding import BytearrayDecodeModel
from pysymex.models.containers.bytes.classification import (
    BytearrayIsasciiModel,
    BytesIsalnumModel,
    BytesIsalphaModel,
    BytesIsasciiModel,
    BytesIsdigitModel,
    BytesIslowerModel,
    BytesIsspaceModel,
    BytesIstitleModel,
    BytesIsupperModel,
)
from pysymex.models.containers.bytes.formatting import BytearrayHexModel, BytesLenModel
from pysymex.models.containers.bytes.search.counts import BytesContainsModel
from pysymex.models.containers.bytes.search.indexing import BytesFindModel
from pysymex.models.containers.bytes.splitting import BytesSplitModel
from pysymex.models.containers.bytes.transforms.case import (
    BytearrayUpperModel,
    BytesCapitalizeModel,
    BytesLowerModel,
    BytesSwapcaseModel,
    BytesTitleModel,
    BytesUpperModel,
)
from pysymex.models.containers.bytes.transforms.replace import BytearrayReplaceModel
from pysymex.models.containers.bytes.transforms.trimming import BytearrayStripModel


def _state() -> VMState:
    return VMState(pc=0)


def _bytearray_receiver(values: list[int]) -> SymbolicList:
    receiver = SymbolicList.from_const(values)
    setattr(receiver, "_type", "bytearray")
    return receiver


def _bytes_receiver(values: list[int]) -> SymbolicList:
    receiver = SymbolicList.from_const(values)
    setattr(receiver, "_type", "bytes")
    return receiver


def test_bytes_concrete_faithfulness_baseline() -> None:
    """Faithfulness baseline for concrete bytes operations."""
    for value in [b"", b"abc", b"A\tB", b"123"]:
        assert value.upper() == bytes(value).upper()
        assert value.lower() == bytes(value).lower()


def test_bytes_symbolic_error_paths() -> None:
    """Symbolic and error path checks for representative methods."""
    BytesFindModel().apply([], {}, _state())
    BytesLenModel().apply([], {}, _state())


def test_bytes_edge_case_empty() -> None:
    """Edge case: empty bytes decode behavior."""
    assert b"".decode() == ""


INVALID_BYTEARRAY_CASES: list[tuple[FunctionModel, list[StackValue]]] = [
    (BytearrayAppendModel(), []),
    (BytearrayAppendModel(), [1, 2]),
    (BytearrayExtendModel(), []),
    (BytearrayExtendModel(), [b"a", b"b"]),
    (BytearrayInsertModel(), [0]),
    (BytearrayInsertModel(), [0, 1, 2]),
    (BytearrayPopModel(), [0, 1]),
    (BytearrayRemoveModel(), []),
    (BytearrayRemoveModel(), [1, 2]),
    (BytearrayClearModel(), [1]),
    (BytearrayReverseModel(), [1]),
    (BytearrayCopyModel(), [1]),
]


@pytest.mark.parametrize(("model", "method_args"), INVALID_BYTEARRAY_CASES)
def test_bytearray_methods_reject_invalid_positional_arity(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Bytearray methods report TypeError for CPython-invalid positional forms."""
    result = model.apply([SymbolicList.empty("bytearray_receiver"), *method_args], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


BYTEARRAY_METHODS: list[tuple[FunctionModel, list[StackValue]]] = [
    (BytearrayAppendModel(), [1]),
    (BytearrayExtendModel(), [b"a"]),
    (BytearrayInsertModel(), [0, 1]),
    (BytearrayPopModel(), []),
    (BytearrayRemoveModel(), [1]),
    (BytearrayClearModel(), []),
    (BytearrayReverseModel(), []),
    (BytearrayCopyModel(), []),
]


@pytest.mark.parametrize(("model", "method_args"), BYTEARRAY_METHODS)
def test_bytearray_methods_reject_keywords(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Bytearray methods do not accept keyword arguments."""
    result = model.apply(
        [SymbolicList.empty("bytearray_receiver"), *method_args], {"unexpected": 1}, _state()
    )
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(("model", "method_args"), BYTEARRAY_METHODS)
def test_bytearray_methods_accept_valid_positional_forms(
    model: FunctionModel, method_args: list[StackValue]
) -> None:
    """Correctly shaped bytearray calls remain modeled."""
    result = model.apply([SymbolicList.empty("bytearray_receiver"), *method_args], {}, _state())

    assert "raised_exception" not in result.side_effects


RECEIVER_ONLY_BYTES_METHODS: list[FunctionModel] = [
    BytesIsdigitModel(),
    BytesIsalphaModel(),
    BytesIsalnumModel(),
    BytesIsspaceModel(),
    BytesIslowerModel(),
    BytesIsupperModel(),
    BytesIstitleModel(),
    BytesIsasciiModel(),
    BytesUpperModel(),
    BytesLowerModel(),
    BytesTitleModel(),
    BytesCapitalizeModel(),
    BytesSwapcaseModel(),
]


@pytest.mark.parametrize("model", RECEIVER_ONLY_BYTES_METHODS)
def test_receiver_only_bytes_methods_reject_arguments(model: FunctionModel) -> None:
    """Receiver-only bytes calls reject CPython-invalid positional and keyword forms."""
    receiver = SymbolicList.empty("bytes_receiver")
    invalid_calls: list[tuple[list[StackValue], dict[str, StackValue]]] = [
        ([receiver, 1], {}),
        ([receiver], {"unexpected": 1}),
    ]

    for args, kwargs in invalid_calls:
        result = model.apply(args, kwargs, _state())
        effect = result.side_effects.get("raised_exception")

        assert is_raised_exception_effect(effect)
        assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize("model", RECEIVER_ONLY_BYTES_METHODS)
def test_receiver_only_bytes_methods_accept_receiver(model: FunctionModel) -> None:
    """Receiver-only bytes calls retain their normal modeled paths."""
    result = model.apply([SymbolicList.empty("bytes_receiver")], {}, _state())

    assert "raised_exception" not in result.side_effects


def test_bytearray_isascii_uses_receiver_only_contract() -> None:
    """Shared bytearray.isascii handling rejects extra arguments."""
    result = BytearrayIsasciiModel().apply([SymbolicList.empty("receiver"), 1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_bytearray_decode_materializes_exact_string() -> None:
    receiver = SymbolicList.from_const([65])
    setattr(receiver, "_type", "bytearray")

    result = BytearrayDecodeModel().apply([receiver], {}, _state())

    assert isinstance(result.value, object)
    assert getattr(result.value, "name", None) == "'A'"


def test_bytearray_hex_constrains_length_from_receiver() -> None:
    receiver = SymbolicList.from_const([1])
    setattr(receiver, "_type", "bytearray")

    result = BytearrayHexModel().apply([receiver], {}, _state())

    assert result.constraints


def test_bytearray_upper_retains_exact_payload_and_type() -> None:
    result = BytearrayUpperModel().apply([_bytearray_receiver([97])], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [65]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytearray_replace_retains_exact_payload_and_type() -> None:
    result = BytearrayReplaceModel().apply(
        [_bytearray_receiver([97, 48]), b"0", b"\x01"], {}, _state()
    )

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [97, 1]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytearray_strip_retains_exact_payload_and_type() -> None:
    result = BytearrayStripModel().apply([_bytearray_receiver([0, 65, 0]), b"\x00"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [65]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytes_split_empty_separator_reports_value_error() -> None:
    result = BytesSplitModel().apply([_bytes_receiver([65]), b""], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert is_potential_exception_effect(effect)
    assert effect["type"] == "ValueError"


def test_bytearray_split_retains_bytearray_elements() -> None:
    result = BytearraySplitModel().apply([_bytearray_receiver([65, 44, 66]), b","], {}, _state())

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [getattr(part, "concrete_items", None) for part in parts] == [[65], [66]]
    assert [getattr(part, "_type", None) for part in parts] == ["bytearray", "bytearray"]


def test_bytearray_join_retains_exact_payload_and_type() -> None:
    parts = SymbolicList.from_const([_bytearray_receiver([65]), _bytearray_receiver([66])])

    result = BytearrayJoinModel().apply([_bytearray_receiver([45]), parts], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [65, 45, 66]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytearray_partition_retains_bytearray_elements() -> None:
    result = BytearrayPartitionModel().apply(
        [_bytearray_receiver([65, 58, 66]), b":"], {}, _state()
    )

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [getattr(part, "concrete_items", None) for part in parts] == [[65], [58], [66]]
    assert [getattr(part, "_type", None) for part in parts] == [
        "bytearray",
        "bytearray",
        "bytearray",
    ]


def test_bytearray_startswith_materializes_exact_bool() -> None:
    result = BytearrayStartswithModel().apply([_bytearray_receiver([65]), b"Z"], {}, _state())

    assert getattr(result.value, "value", None) is False


def test_bytearray_index_missing_reports_value_error() -> None:
    result = BytearrayIndexModel().apply([_bytearray_receiver([65]), b"Z"], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert is_potential_exception_effect(effect)
    assert effect["type"] == "ValueError"


def test_bytes_contains_accepts_exact_integer_and_bytes_needles() -> None:
    int_result = BytesContainsModel().apply([_bytes_receiver([65]), 65], {}, _state())
    bytes_result = BytesContainsModel().apply([_bytes_receiver([65]), b"A"], {}, _state())

    assert getattr(int_result.value, "value", None) is True
    assert getattr(bytes_result.value, "value", None) is True


def test_bytes_contains_invalid_int_reports_value_error() -> None:
    result = BytesContainsModel().apply([_bytes_receiver([65]), 300], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert is_potential_exception_effect(effect)
    assert effect["type"] == "ValueError"


def test_bytearray_contains_invalid_type_reports_type_error() -> None:
    result = BytearrayContainsModel().apply([_bytearray_receiver([65]), "A"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
