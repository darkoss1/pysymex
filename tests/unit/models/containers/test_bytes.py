from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
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
from pysymex._internal.models.builtins.types.containers.bytes.bytearray.search import (
    BytearrayContainsModel,
    BytearrayIndexModel,
    BytearrayStartsModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.bytearray.splitting import (
    BytearrayJoinModel,
    BytearrayLinesModel,
    BytearrayPartitionModel,
    BytearrayRPartitionModel,
    BytearrayRsplitModel,
    BytearraySplitModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.classification import (
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
from pysymex._internal.models.builtins.types.containers.bytes.decoding import (
    BytearrayDecodeModel,
    BytesDecodeModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.formatting import (
    BytearrayHexModel,
    BytesLenModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.search.counts import (
    BytesContainsModel,
    BytesCountModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.search.indexing import (
    BytesFindModel,
    BytesIndexModel,
    BytesRfindModel,
    BytesRindexModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.splitting import BytesSplitModel
from pysymex._internal.models.builtins.types.containers.bytes.transforms.case import (
    BytearrayUpperModel,
    BytesCapitalizeModel,
    BytesLowerModel,
    BytesSwapcaseModel,
    BytesTitleModel,
    BytesUpperModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.transforms.replace import (
    BytearrayReplaceModel,
    BytesReplaceModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.transforms.trimming import (
    BytearrayStripModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.translation import (
    BytesExpandtabsModel,
    BytesTranslateModel,
)
from pysymex._internal.models.builtins.sequences.len import LenModel
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import SideEffects
from pysymex._internal.typing.protocols import StackValue


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

    assert SideEffects.is_raised_exception(effect)
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

    assert SideEffects.is_raised_exception(effect)
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

BYTES_CLASSIFICATION_FALSE_ON_EMPTY_CASES: list[tuple[FunctionModel, bytes]] = [
    (BytesIsdigitModel(), b"1"),
    (BytesIsalphaModel(), b"a"),
    (BytesIsalnumModel(), b"a1"),
    (BytesIsspaceModel(), b" "),
    (BytesIslowerModel(), b"a"),
    (BytesIsupperModel(), b"A"),
    (BytesIstitleModel(), b"A"),
]

BYTES_CASE_TRANSFORM_MODELS: list[FunctionModel] = [
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

        assert SideEffects.is_raised_exception(effect)
        assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize("model", RECEIVER_ONLY_BYTES_METHODS)
def test_receiver_only_bytes_methods_accept_receiver(model: FunctionModel) -> None:
    """Receiver-only bytes calls retain their normal modeled paths."""
    result = model.apply([SymbolicList.empty("bytes_receiver")], {}, _state())

    assert "raised_exception" not in result.side_effects


@pytest.mark.parametrize(("model", "true_literal"), BYTES_CLASSIFICATION_FALSE_ON_EMPTY_CASES)
def test_bytes_classification_methods_materialize_exact_true(
    model: FunctionModel,
    true_literal: bytes,
) -> None:
    result = model.apply([SymbolicBytes.concrete(true_literal)], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


@pytest.mark.parametrize(("model", "_true_literal"), BYTES_CLASSIFICATION_FALSE_ON_EMPTY_CASES)
def test_bytes_classification_methods_constrain_empty_symbolic_bytes_false(
    model: FunctionModel,
    _true_literal: bytes,
) -> None:
    receiver = SymbolicBytes.symbolic(f"{model.name}_empty_receiver")

    result = model.apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 0)
    solver.add(result.value.z3_bool)
    assert solver.check() == z3.unsat


def test_bytes_len_uses_symbolic_bytes_length() -> None:
    receiver = SymbolicBytes.symbolic("bytes_len_receiver")

    result = BytesLenModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(result.value.z3_int != receiver.z3_len)
    assert solver.check() == z3.unsat


def test_builtin_len_uses_symbolic_bytes_length() -> None:
    receiver = SymbolicBytes.symbolic("builtin_bytes_len_receiver")

    result = LenModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(result.value.z3_int != receiver.z3_len)
    assert solver.check() == z3.unsat


def test_bytes_find_constrains_empty_symbolic_bytes_to_missing() -> None:
    receiver = SymbolicBytes.symbolic("bytes_find_empty_receiver")

    result = BytesFindModel().apply([receiver, b"a"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 0)
    solver.add(result.value.z3_int != -1)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize(
    "model",
    [
        BytesFindModel(),
        BytesRfindModel(),
        BytesIndexModel(),
        BytesRindexModel(),
        BytesCountModel(),
    ],
)
def test_bytes_search_methods_reject_definitely_invalid_slice_bounds(
    model: FunctionModel,
) -> None:
    result = model.apply([b"abc", b"a", "0"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_bytes_count_empty_needle_uses_symbolic_length() -> None:
    receiver = SymbolicBytes.symbolic("bytes_count_empty_needle_receiver")

    result = BytesCountModel().apply([receiver, b""], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(result.value.z3_int != receiver.z3_len + 1)
    assert solver.check() == z3.unsat


def test_bytes_count_nonempty_needle_is_zero_for_empty_symbolic_bytes() -> None:
    receiver = SymbolicBytes.symbolic("bytes_count_empty_receiver")

    result = BytesCountModel().apply([receiver, b"a"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 0)
    solver.add(result.value.z3_int != 0)
    assert solver.check() == z3.unsat


def test_bytes_contains_empty_needle_is_true_for_symbolic_bytes() -> None:
    receiver = SymbolicBytes.symbolic("bytes_contains_empty_needle_receiver")

    result = BytesContainsModel().apply([receiver, b""], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_bytes_contains_nonempty_needle_is_false_for_empty_symbolic_bytes() -> None:
    receiver = SymbolicBytes.symbolic("bytes_contains_empty_receiver")

    result = BytesContainsModel().apply([receiver, b"a"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 0)
    solver.add(result.value.z3_bool)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("model", BYTES_CASE_TRANSFORM_MODELS)
def test_bytes_case_transforms_preserve_symbolic_bytes_length(model: FunctionModel) -> None:
    receiver = SymbolicBytes.symbolic(f"bytes_{model.name}_receiver")

    result = model.apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type", None) == "bytes"
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(result.value.z3_len != receiver.z3_len)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("table", [SymbolicNone(), bytes.maketrans(b"a", b"b")])
def test_bytes_translate_without_delete_preserves_symbolic_bytes_length(table: StackValue) -> None:
    receiver = SymbolicBytes.symbolic("bytes_translate_receiver")

    result = BytesTranslateModel().apply([receiver, table], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type", None) == "bytes"
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(result.value.z3_len != receiver.z3_len)
    assert solver.check() == z3.unsat


def test_bytes_translate_empty_delete_preserves_symbolic_bytes_length() -> None:
    receiver = SymbolicBytes.symbolic("bytes_translate_empty_delete_receiver")

    result = BytesTranslateModel().apply([receiver, SymbolicNone(), b""], {}, _state())

    assert isinstance(result.value, SymbolicList)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(result.value.z3_len != receiver.z3_len)
    assert solver.check() == z3.unsat


def test_bytes_translate_nonempty_delete_can_shrink_symbolic_bytes() -> None:
    receiver = SymbolicBytes.symbolic("bytes_translate_delete_receiver")

    result = BytesTranslateModel().apply([receiver, SymbolicNone(), b"a"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 1)
    solver.add(result.value.z3_len == 0)
    assert solver.check() == z3.sat


def test_bytes_decode_default_preserves_symbolic_nonempty_result() -> None:
    receiver = SymbolicBytes.symbolic("bytes_decode_receiver")

    result = BytesDecodeModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicString)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len > 0)
    solver.add(result.value.z3_len == 0)
    assert solver.check() == z3.unsat


def test_bytes_decode_ignore_can_shrink_symbolic_nonempty_result() -> None:
    receiver = SymbolicBytes.symbolic("bytes_decode_ignore_receiver")

    result = BytesDecodeModel().apply(
        [receiver, SymbolicString.from_const("utf-8"), SymbolicString.from_const("ignore")],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicString)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 1)
    solver.add(result.value.z3_len == 0)
    assert solver.check() == z3.sat


def test_bytes_expandtabs_positive_tabsize_preserves_symbolic_nonempty_result() -> None:
    receiver = SymbolicBytes.symbolic("bytes_expandtabs_positive_receiver")

    result = BytesExpandtabsModel().apply([receiver, 1], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type", None) == "bytes"
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len > 0)
    solver.add(result.value.z3_len == 0)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("tabsize", [0, -1])
def test_bytes_expandtabs_nonpositive_tabsize_can_shrink_symbolic_bytes(
    tabsize: int,
) -> None:
    receiver = SymbolicBytes.symbolic("bytes_expandtabs_nonpositive_receiver")

    result = BytesExpandtabsModel().apply([receiver, tabsize], {}, _state())

    assert isinstance(result.value, SymbolicList)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 1)
    solver.add(result.value.z3_len == 0)
    assert solver.check() == z3.sat


def test_bytes_expandtabs_empty_symbolic_bytes_remains_empty() -> None:
    receiver = SymbolicBytes.symbolic("bytes_expandtabs_empty_receiver")

    result = BytesExpandtabsModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicList)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 0)
    solver.add(result.value.z3_len != 0)
    assert solver.check() == z3.unsat


def test_bytes_expandtabs_invalid_tabsize_rejected_with_symbolic_receiver() -> None:
    receiver = SymbolicBytes.symbolic("bytes_expandtabs_bad_tabsize_receiver")

    result = BytesExpandtabsModel().apply([receiver, "wide"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_bytearray_isascii_uses_receiver_only_contract() -> None:
    """Shared bytearray.isascii handling rejects extra arguments."""
    result = BytearrayIsasciiModel().apply([SymbolicList.empty("receiver"), 1], {}, _state())
    effect = result.side_effects.get("raised_exception")

    assert SideEffects.is_raised_exception(effect)
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


@pytest.mark.parametrize(
    ("index", "expected"),
    [
        (-10, [0, 65, 66]),
        (-1, [65, 0, 66]),
        (10, [65, 66, 0]),
        (True, [65, 0, 66]),
    ],
)
def test_bytearray_insert_uses_core_cpython_index_clamping(
    index: StackValue,
    expected: list[int],
) -> None:
    receiver = _bytearray_receiver([65, 66])

    result = BytearrayInsertModel().apply([receiver, index, 0], {}, _state())

    assert result.value is not None
    assert receiver.concrete_items == expected


@pytest.mark.parametrize(
    ("index", "popped", "remaining"),
    [
        (-2, 65, [66]),
        (-1, 66, [65]),
        (1, 66, [65]),
    ],
)
def test_bytearray_pop_uses_core_existing_index_normalization(
    index: int,
    popped: int,
    remaining: list[int],
) -> None:
    receiver = _bytearray_receiver([65, 66])

    result = BytearrayPopModel().apply([receiver, index], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value == popped
    assert receiver.concrete_items == remaining


def test_bytearray_replace_retains_exact_payload_and_type() -> None:
    result = BytearrayReplaceModel().apply(
        [_bytearray_receiver([97, 48]), b"0", b"\x01"], {}, _state()
    )

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [97, 1]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytes_replace_uses_core_bytes_like_operand_classification() -> None:
    result = BytesReplaceModel().apply([b"\x00\x01", _bytearray_receiver([0]), b"\x02"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [2, 1]
    error_result = BytesReplaceModel().apply([b"\x00", 1, b"\x02"], {}, _state())
    effect = error_result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


@pytest.mark.parametrize(("count", "expected"), [(True, [2, 0]), (1, [2, 0])])
def test_bytes_replace_uses_core_count_index_classification(
    count: StackValue,
    expected: list[int],
) -> None:
    result = BytesReplaceModel().apply([b"\x00\x00", b"\x00", b"\x02", count], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == expected


def test_bytes_replace_rejects_definitely_invalid_count_index() -> None:
    result = BytesReplaceModel().apply([b"\x00", b"\x00", b"\x02", "1"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_bytearray_strip_retains_exact_payload_and_type() -> None:
    result = BytearrayStripModel().apply([_bytearray_receiver([0, 65, 0]), b"\x00"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [65]
    assert getattr(result.value, "_type", None) == "bytearray"


def test_bytes_split_empty_separator_reports_value_error() -> None:
    result = BytesSplitModel().apply([_bytes_receiver([65]), b""], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"


@pytest.mark.parametrize(
    ("model", "args", "message"),
    [
        (
            BytearraySplitModel(),
            ["x"],
            "a bytes-like object is required, not 'str'",
        ),
        (
            BytearrayRsplitModel(),
            [b",", None],
            "'NoneType' object cannot be interpreted as an integer",
        ),
    ],
)
def test_bytearray_split_models_reject_definite_invalid_arguments(
    model: FunctionModel,
    args: list[StackValue],
    message: str,
) -> None:
    result = model.apply([_bytearray_receiver([65, 44, 66]), *args], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


@pytest.mark.parametrize(
    ("model", "separator", "message"),
    [
        (
            BytearrayPartitionModel(),
            "x",
            "a bytes-like object is required, not 'str'",
        ),
        (
            BytearrayRPartitionModel(),
            None,
            "a bytes-like object is required, not 'NoneType'",
        ),
    ],
)
def test_bytearray_partition_models_reject_definite_invalid_separator(
    model: FunctionModel,
    separator: StackValue,
    message: str,
) -> None:
    result = model.apply([_bytearray_receiver([65, 58, 66]), separator], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


def test_bytearray_split_retains_bytearray_elements() -> None:
    result = BytearraySplitModel().apply([_bytearray_receiver([65, 44, 66]), b","], {}, _state())

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [getattr(part, "concrete_items", None) for part in parts] == [[65], [66]]
    assert [getattr(part, "_type", None) for part in parts] == ["bytearray", "bytearray"]


@pytest.mark.parametrize(
    ("keepends", "expected"),
    [
        ([], [[65], [66]]),
        ([1], [[65, 10], [66]]),
        ({}, [[65], [66]]),
        ({"x": 1}, [[65, 10], [66]]),
    ],
)
def test_bytearray_splitlines_uses_concrete_keepends_truthiness(
    keepends: StackValue,
    expected: list[list[int]],
) -> None:
    result = BytearrayLinesModel().apply(
        [_bytearray_receiver([65, 10, 66]), keepends], {}, _state()
    )

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [getattr(part, "concrete_items", None) for part in parts] == expected
    assert [getattr(part, "_type", None) for part in parts] == ["bytearray", "bytearray"]


def test_bytearray_join_retains_exact_payload_and_type() -> None:
    parts = SymbolicList.from_const([_bytearray_receiver([65]), _bytearray_receiver([66])])

    result = BytearrayJoinModel().apply([_bytearray_receiver([45]), parts], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == [65, 45, 66]
    assert getattr(result.value, "_type", None) == "bytearray"


@pytest.mark.parametrize(
    ("iterable", "message"),
    [
        (None, "can only join an iterable"),
        (["a"], "sequence item 0: expected a bytes-like object, str found"),
    ],
)
def test_bytearray_join_rejects_definite_invalid_iterable_or_items(
    iterable: StackValue,
    message: str,
) -> None:
    result = BytearrayJoinModel().apply([_bytearray_receiver([44]), iterable], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


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
    result = BytearrayStartsModel().apply([_bytearray_receiver([65]), b"Z"], {}, _state())

    assert getattr(result.value, "value", None) is False


def test_bytearray_index_missing_reports_value_error() -> None:
    result = BytearrayIndexModel().apply([_bytearray_receiver([65]), b"Z"], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"


def test_bytes_contains_accepts_exact_integer_and_bytes_needles() -> None:
    int_result = BytesContainsModel().apply([_bytes_receiver([65]), 65], {}, _state())
    bytes_result = BytesContainsModel().apply([_bytes_receiver([65]), b"A"], {}, _state())

    assert getattr(int_result.value, "value", None) is True
    assert getattr(bytes_result.value, "value", None) is True


def test_bytes_contains_invalid_int_reports_value_error() -> None:
    result = BytesContainsModel().apply([_bytes_receiver([65]), 300], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"


def test_bytearray_contains_invalid_type_reports_type_error() -> None:
    result = BytearrayContainsModel().apply([_bytearray_receiver([65]), "A"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
