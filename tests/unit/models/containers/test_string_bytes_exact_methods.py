"""Focused model tests for exact string and bytes method materialization."""

from __future__ import annotations

from typing import cast

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.registry.models import get_default_model_registry
from pysymex._internal.models.builtins.types.containers.bytes.classification import (
    BytearrayIsasciiModel,
    BytesIsasciiModel,
    BytesIsdigitModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.formatting import (
    BytesCenterModel,
    BytesFromHexModel,
    BytesLjustModel,
    BytesRjustModel,
    BytesZfillModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.search.affixes import (
    BytesEndswithModel,
    BytesStartswithModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.search.counts import (
    BytesContainsModel,
    BytesCountModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.search.indexing import (
    BytesFindModel,
    BytesIndexModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.shared import concrete_bytes_literal
from pysymex._internal.models.builtins.types.containers.bytes.splitting import (
    BytesJoinModel,
    BytesPartitionModel,
    BytesRpartitionModel,
    BytesRsplitModel,
    BytesSplitlinesModel,
    BytesSplitModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.transforms.case import (
    BytesLowerModel,
    BytesUpperModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.transforms.replace import (
    BytearrayReplaceModel,
    BytesReplaceModel,
)
from pysymex._internal.models.builtins.types.containers.bytes.transforms.trimming import (
    BytearrayRemovePrefixModel,
    BytearrayRemoveSuffixModel,
    BytearrayStripModel,
    BytesLstripModel,
    BytesRemovePrefixModel,
    BytesRemoveSuffixModel,
    BytesRstripModel,
    BytesStripModel,
)
from pysymex._internal.models.builtins.types.containers.strings.classification.content import (
    StrIsdigitModel,
)
from pysymex._internal.models.builtins.types.containers.strings.classification.special import (
    StrIsasciiModel,
)
from pysymex._internal.models.builtins.types.containers.strings.formatting import (
    StrCenterModel,
    StrLjustModel,
    StrRjustModel,
    StrZfillModel,
)
from pysymex._internal.models.builtins.types.containers.strings.search.affixes import (
    StrReplaceModel,
)
from pysymex._internal.models.builtins.types.containers.strings.search.indexing import StrRfindModel
from pysymex._internal.models.builtins.types.containers.strings.splitting import (
    StrJoinModel,
    StrPartitionModel,
    StrRpartitionModel,
    StrRsplitModel,
    StrSplitlinesModel,
    StrSplitModel,
)
from pysymex._internal.models.builtins.types.containers.strings.trimming import (
    StrLstripModel,
    StrRemovePrefixModel,
    StrRemoveSuffixModel,
    StrRstripModel,
    StrStripModel,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import (
    SideEffects,
)
from pysymex._internal.typing.protocols import StackValue


def _state() -> VMState:
    return VMState(pc=0)


def _raw_bytearray_fillchar() -> StackValue:
    return cast("StackValue", bytearray(b"x"))


def _raw_memoryview(value: bytes) -> StackValue:
    return cast("StackValue", memoryview(value))


def _raw_bytearray(value: bytes) -> StackValue:
    return cast("StackValue", bytearray(value))


def test_str_split_materializes_exact_parts() -> None:
    result = StrSplitModel().apply([SymbolicString.from_const("a,b"), ","], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a", "b"]


def test_str_rsplit_materializes_exact_parts() -> None:
    result = StrRsplitModel().apply([SymbolicString.from_const("a,b,c"), ",", 1], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a,b", "c"]


def test_str_split_accepts_none_separator_and_bool_maxsplit() -> None:
    split = StrSplitModel().apply([SymbolicString.from_const(" a "), None], {}, _state())
    rsplit = StrRsplitModel().apply([SymbolicString.from_const("a,b,c"), ",", True], {}, _state())

    assert isinstance(split.value, SymbolicList)
    assert isinstance(rsplit.value, SymbolicList)
    assert split.value.concrete_items == ["a"]
    assert rsplit.value.concrete_items == ["a,b", "c"]
    assert "raised_exception" not in split.side_effects
    assert "raised_exception" not in rsplit.side_effects


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (StrSplitModel(), [""]),
        (StrRsplitModel(), [""]),
    ],
)
def test_str_split_models_reject_empty_separator(
    model: FunctionModel,
    args: list[StackValue],
) -> None:
    result = model.apply([SymbolicString.from_const("a,b"), *args], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"
    assert effect["message"] == "empty separator"


@pytest.mark.parametrize(
    ("model", "args", "message"),
    [
        (StrSplitModel(), [SymbolicValue.from_const(1)], "must be str or None, not int"),
        (StrRsplitModel(), [SymbolicValue.from_const(1)], "must be str or None, not int"),
        (
            StrSplitModel(),
            [",", SymbolicString.from_const("x")],
            "'str' object cannot be interpreted as an integer",
        ),
        (
            StrRsplitModel(),
            [",", SymbolicString.from_const("x")],
            "'str' object cannot be interpreted as an integer",
        ),
    ],
)
def test_str_split_models_reject_definite_invalid_arguments(
    model: FunctionModel,
    args: list[StackValue],
    message: str,
) -> None:
    result = model.apply([SymbolicString.from_const("a,b"), *args], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


@pytest.mark.parametrize(
    ("iterable", "message"),
    [
        (SymbolicValue.from_const(1), "can only join an iterable"),
        (None, "can only join an iterable"),
        (["a", SymbolicValue.from_const(1)], "sequence item 1: expected str instance, int found"),
        ([b"a"], "sequence item 0: expected str instance, bytes found"),
    ],
)
def test_str_join_rejects_definite_invalid_iterable_or_items(
    iterable: StackValue,
    message: str,
) -> None:
    result = StrJoinModel().apply([SymbolicString.from_const(","), iterable], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


def test_str_replace_materializes_exact_string() -> None:
    result = StrReplaceModel().apply(
        [SymbolicString.from_const("a0a"), "a", "b", 1],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "b0a"


def test_str_replace_accepts_wrapped_exact_count() -> None:
    result = StrReplaceModel().apply(
        [SymbolicString.from_const("aa"), "a", "", SymbolicValue.from_const(1)],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "a"


def test_bytes_split_materializes_exact_bytes_parts() -> None:
    result = BytesSplitModel().apply([b"\x01,\x02", b","], {}, _state())

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [concrete_bytes_literal(part) for part in parts] == [b"\x01", b"\x02"]


def test_bytes_split_accepts_wrapped_exact_maxsplit() -> None:
    result = BytesSplitModel().apply(
        [b"\x01,\x02,\x03", b",", SymbolicValue.from_const(1)],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [concrete_bytes_literal(part) for part in parts] == [b"\x01", b"\x02,\x03"]


def test_bytes_rsplit_materializes_exact_bytes_parts() -> None:
    result = BytesRsplitModel().apply([b"\x01,\x02,\x03", b",", 1], {}, _state())

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [concrete_bytes_literal(part) for part in parts] == [b"\x01,\x02", b"\x03"]


def test_bytes_split_accepts_none_separator_and_bool_maxsplit() -> None:
    split = BytesSplitModel().apply([b" \x01 ", None], {}, _state())
    rsplit = BytesRsplitModel().apply([b"\x01,\x02,\x03", b",", True], {}, _state())

    assert isinstance(split.value, SymbolicList)
    assert isinstance(rsplit.value, SymbolicList)
    split_parts = split.value.concrete_items
    rsplit_parts = rsplit.value.concrete_items
    assert split_parts is not None
    assert rsplit_parts is not None
    assert [concrete_bytes_literal(part) for part in split_parts] == [b"\x01"]
    assert [concrete_bytes_literal(part) for part in rsplit_parts] == [b"\x01,\x02", b"\x03"]
    assert "raised_exception" not in split.side_effects
    assert "raised_exception" not in rsplit.side_effects


@pytest.mark.parametrize(
    ("model", "args", "message"),
    [
        (
            BytesSplitModel(),
            [SymbolicValue.from_const(1)],
            "a bytes-like object is required, not 'int'",
        ),
        (
            BytesRsplitModel(),
            [SymbolicValue.from_const(1)],
            "a bytes-like object is required, not 'int'",
        ),
        (
            BytesSplitModel(),
            [b",", None],
            "'NoneType' object cannot be interpreted as an integer",
        ),
        (
            BytesRsplitModel(),
            [b",", "x"],
            "'str' object cannot be interpreted as an integer",
        ),
    ],
)
def test_bytes_split_models_reject_definite_invalid_arguments(
    model: FunctionModel,
    args: list[StackValue],
    message: str,
) -> None:
    result = model.apply([b"\x01,\x02", *args], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


@pytest.mark.parametrize(
    ("iterable", "message"),
    [
        (SymbolicValue.from_const(1), "can only join an iterable"),
        (None, "can only join an iterable"),
        (
            [b"a", SymbolicValue.from_const(1)],
            "sequence item 1: expected a bytes-like object, int found",
        ),
        (["a"], "sequence item 0: expected a bytes-like object, str found"),
    ],
)
def test_bytes_join_rejects_definite_invalid_iterable_or_items(
    iterable: StackValue,
    message: str,
) -> None:
    result = BytesJoinModel().apply([b",", iterable], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


def test_bytes_replace_materializes_exact_bytes() -> None:
    result = BytesReplaceModel().apply([b"\x00", b"\x00", b"\x01"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytes_replace_accepts_wrapped_exact_count() -> None:
    result = BytesReplaceModel().apply(
        [b"\x00\x00", b"\x00", b"\x01", SymbolicValue.from_const(1)],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01\x00"


def test_bytes_replace_accepts_bytearray_and_memoryview_operands_exactly() -> None:
    result = BytesReplaceModel().apply(
        [b"\x00\x01", _raw_bytearray(b"\x00"), _raw_memoryview(b"\x02")],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x02\x01"


def test_bytearray_replace_accepts_memoryview_operands_exactly() -> None:
    result = BytearrayReplaceModel().apply(
        [_raw_bytearray(b"\x00\x01"), _raw_memoryview(b"\x00"), b"\x02"],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type", None) == "bytearray"
    assert concrete_bytes_literal(result.value) == b"\x02\x01"


@pytest.mark.parametrize(
    ("model", "args", "message"),
    [
        (
            BytesReplaceModel(),
            [SymbolicValue.from_const(1), b"x"],
            "a bytes-like object is required, not 'int'",
        ),
        (
            BytesReplaceModel(),
            [b"x", SymbolicString.from_const("y")],
            "a bytes-like object is required, not 'str'",
        ),
        (
            BytesReplaceModel(),
            [b"x", b"y", SymbolicString.from_const("1")],
            "'str' object cannot be interpreted as an integer",
        ),
        (
            BytesReplaceModel(),
            [b"x", b"y", None],
            "'NoneType' object cannot be interpreted as an integer",
        ),
        (
            BytearrayReplaceModel(),
            ["x", b"y"],
            "a bytes-like object is required, not 'str'",
        ),
        (
            BytearrayReplaceModel(),
            [b"x", SymbolicValue.from_const(1)],
            "a bytes-like object is required, not 'int'",
        ),
    ],
)
def test_bytes_replace_models_reject_definite_invalid_operands(
    model: FunctionModel,
    args: list[StackValue],
    message: str,
) -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_replace_receiver")

    result = model.apply([receiver, *args], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


def test_bytes_replace_keeps_valid_symbolic_receiver_non_error() -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_replace_receiver")
    count, _count_constraint = SymbolicValue.symbolic_int("bytes_replace_count")

    result = BytesReplaceModel().apply([receiver, b"x", b"y", count], {}, _state())

    assert "raised_exception" not in result.side_effects
    assert isinstance(result.value, SymbolicList)


def test_bytes_strip_materializes_exact_bytes() -> None:
    result = BytesStripModel().apply([b"\x00\x01\x00", b"\x00"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


@pytest.mark.parametrize(
    ("model", "chars", "message"),
    [
        (StrStripModel(), SymbolicValue.from_const(1), "strip arg must be None or str"),
        (StrLstripModel(), b"a", "lstrip arg must be None or str"),
        (StrRstripModel(), SymbolicValue.from_const(False), "rstrip arg must be None or str"),
    ],
)
def test_str_strip_models_reject_definite_invalid_chars(
    model: FunctionModel,
    chars: StackValue,
    message: str,
) -> None:
    receiver, _constraint = SymbolicString.symbolic("strip_receiver")

    result = model.apply([receiver, chars], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


@pytest.mark.parametrize(
    ("model", "chars"),
    [
        (StrStripModel(), None),
        (StrLstripModel(), SymbolicString.symbolic("lstrip_chars")[0]),
        (StrRstripModel(), "x"),
    ],
)
def test_str_strip_models_keep_valid_symbolic_receiver_non_error(
    model: FunctionModel,
    chars: StackValue,
) -> None:
    receiver, _constraint = SymbolicString.symbolic("strip_receiver")

    result = model.apply([receiver, chars], {}, _state())

    assert "raised_exception" not in result.side_effects
    assert isinstance(result.value, SymbolicString)


def test_str_removeprefix_materializes_exact_string() -> None:
    result = StrRemovePrefixModel().apply(
        [SymbolicString.from_const("abc"), "a"],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "bc"


def test_str_removesuffix_materializes_exact_string() -> None:
    result = StrRemoveSuffixModel().apply(
        [SymbolicString.from_const("abc"), "c"],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "ab"


@pytest.mark.parametrize(
    ("model", "operand", "message"),
    [
        (
            StrRemovePrefixModel(),
            SymbolicValue.from_const(1),
            "removeprefix() argument must be str, not int",
        ),
        (
            StrRemoveSuffixModel(),
            None,
            "removesuffix() argument must be str, not None",
        ),
    ],
)
def test_str_affix_removal_models_reject_definite_invalid_operand(
    model: FunctionModel,
    operand: StackValue,
    message: str,
) -> None:
    receiver, _constraint = SymbolicString.symbolic("str_affix_receiver")

    result = model.apply([receiver, operand], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


def test_bytes_removeprefix_materializes_exact_bytes() -> None:
    result = BytesRemovePrefixModel().apply([b"\x00\x01", b"\x00"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytes_removesuffix_materializes_exact_bytes() -> None:
    result = BytesRemoveSuffixModel().apply([b"\x01\x00", b"\x00"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytes_strip_accepts_bytearray_chars_exactly() -> None:
    result = BytesStripModel().apply([b"\x00\x01", _raw_bytearray(b"\x00")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytes_strip_accepts_wrapped_bytearray_chars_exactly() -> None:
    result = BytesStripModel().apply(
        [b"\x00\x01", SymbolicValue.from_const(bytearray(b"\x00"))],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytes_removeprefix_accepts_memoryview_prefix_exactly() -> None:
    result = BytesRemovePrefixModel().apply([b"\x00\x01", _raw_memoryview(b"\x00")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytearray_removesuffix_accepts_bytes_suffix_exactly() -> None:
    result = BytearrayRemoveSuffixModel().apply(
        [_raw_bytearray(b"\x01\x00"), b"\x00"],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type", None) == "bytearray"
    assert concrete_bytes_literal(result.value) == b"\x01"


@pytest.mark.parametrize(
    ("model", "chars", "message"),
    [
        (
            BytesStripModel(),
            SymbolicValue.from_const(1),
            "a bytes-like object is required, not 'int'",
        ),
        (BytesLstripModel(), "x", "a bytes-like object is required, not 'str'"),
        (
            BytesRstripModel(),
            SymbolicString.from_const("x"),
            "a bytes-like object is required, not 'str'",
        ),
    ],
)
def test_bytes_strip_models_reject_definite_invalid_chars(
    model: FunctionModel,
    chars: StackValue,
    message: str,
) -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_strip_receiver")

    result = model.apply([receiver, chars], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


@pytest.mark.parametrize(
    ("model", "operand", "message"),
    [
        (
            BytesRemovePrefixModel(),
            SymbolicValue.from_const(1),
            "a bytes-like object is required, not 'int'",
        ),
        (
            BytesRemoveSuffixModel(),
            None,
            "a bytes-like object is required, not 'NoneType'",
        ),
        (
            BytearrayRemovePrefixModel(),
            "x",
            "a bytes-like object is required, not 'str'",
        ),
        (
            BytearrayStripModel(),
            "x",
            "a bytes-like object is required, not 'str'",
        ),
    ],
)
def test_bytes_affix_and_bytearray_models_reject_definite_invalid_operand(
    model: FunctionModel,
    operand: StackValue,
    message: str,
) -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_affix_receiver")

    result = model.apply([receiver, operand], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


def test_bytes_startswith_materializes_exact_false() -> None:
    result = BytesStartswithModel().apply([b"\x01", b"\x02"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is False


def test_bytes_startswith_accepts_tuple_affixes_exactly() -> None:
    result = BytesStartswithModel().apply(
        [b"\x01\x02", (_raw_bytearray(b"\x00"), b"\x01")],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_bytes_startswith_invalid_tuple_member_after_miss_emits_type_error() -> None:
    result = BytesStartswithModel().apply([b"\x01", (b"\x00", 1)], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == "a bytes-like object is required, not 'int'"


def test_bytes_startswith_rejects_definite_invalid_operand() -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_startswith_receiver")

    result = BytesStartswithModel().apply([receiver, SymbolicString.from_const("x")], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == "startswith first arg must be bytes or a tuple of bytes, not str"


def test_bytes_startswith_rejects_definite_invalid_slice_bound() -> None:
    result = BytesStartswithModel().apply([b"\x01", b"\x01", "0"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == "slice indices must be integers or None or have an __index__ method"


def test_bytes_startswith_empty_affix_is_true_for_symbolic_receiver() -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_empty_prefix_receiver")

    result = BytesStartswithModel().apply([receiver, b""], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_bytes_endswith_materializes_exact_true_for_empty_suffix() -> None:
    result = BytesEndswithModel().apply([b"", b""], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_bytes_endswith_accepts_memoryview_affix_exactly() -> None:
    result = BytesEndswithModel().apply([b"\x01\x02", _raw_memoryview(b"\x02")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_bytes_endswith_empty_tuple_is_false_for_symbolic_receiver() -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_empty_tuple_receiver")

    result = BytesEndswithModel().apply([receiver, ()], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is False


def test_bytes_endswith_empty_tuple_member_is_true_for_symbolic_receiver() -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_empty_suffix_receiver")

    result = BytesEndswithModel().apply([receiver, (b"",)], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_str_rfind_materializes_exact_index() -> None:
    result = StrRfindModel().apply([SymbolicString.from_const("ba"), "a"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value == 1


def test_bytes_find_materializes_exact_index() -> None:
    result = BytesFindModel().apply([b"ba", b"a"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value == 1


def test_bytes_count_materializes_exact_count() -> None:
    result = BytesCountModel().apply([b"aa", b"a"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value == 2


def test_bytes_fromhex_materializes_exact_bytes() -> None:
    result = BytesFromHexModel().apply(["00 ff"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x00\xff"


def test_bytes_fromhex_invalid_literal_emits_value_error() -> None:
    result = BytesFromHexModel().apply(["zz"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "ValueError"
    assert concrete_bytes_literal(result.value) == b""


def test_default_registry_dispatches_real_bytes_fromhex_method() -> None:
    result = get_default_model_registry().apply(bytes.fromhex, ["00"], {}, _state())

    assert result is not None
    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x00"


def test_bytes_index_missing_emits_value_error_side_effect() -> None:
    result = BytesIndexModel().apply([b"abc", b"z"], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"


def test_bytes_contains_materializes_exact_false() -> None:
    result = BytesContainsModel().apply([b"abc", b"z"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is False


def test_bytes_zfill_materializes_exact_bytes() -> None:
    result = BytesZfillModel().apply([b"\x01", 2], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"0\x01"


def test_bytes_ljust_materializes_exact_bytes() -> None:
    result = BytesLjustModel().apply([b"\x01", 2, b"\x00"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01\x00"


def test_bytes_center_accepts_bytearray_fillchar() -> None:
    result = BytesCenterModel().apply([b"a", 3, _raw_bytearray_fillchar()], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"xax"


@pytest.mark.parametrize(
    ("model", "args", "message"),
    [
        (
            StrCenterModel(),
            ["3"],
            "'str' object cannot be interpreted as an integer",
        ),
        (
            StrLjustModel(),
            [3, ""],
            "The fill character must be exactly one character long",
        ),
        (
            StrRjustModel(),
            [3, 0],
            "The fill character must be a unicode character, not int",
        ),
        (
            StrCenterModel(),
            [3, None],
            "The fill character must be a unicode character, not NoneType",
        ),
        (
            StrZfillModel(),
            [None],
            "'NoneType' object cannot be interpreted as an integer",
        ),
    ],
)
def test_str_padding_models_reject_invalid_operands_for_symbolic_receiver(
    model: FunctionModel,
    args: list[StackValue],
    message: str,
) -> None:
    receiver, _constraint = SymbolicString.symbolic("padding_receiver")

    result = model.apply([receiver, *args], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (StrCenterModel(), [3, SymbolicString.symbolic("fill")[0]]),
        (StrCenterModel(), [SymbolicValue.symbolic_int("str_padding_width")[0]]),
        (StrLjustModel(), [3, "x"]),
        (StrRjustModel(), [3, SymbolicString.symbolic("fill")[0]]),
        (StrZfillModel(), [3]),
    ],
)
def test_str_padding_models_keep_valid_symbolic_receiver_non_error(
    model: FunctionModel,
    args: list[StackValue],
) -> None:
    receiver, _constraint = SymbolicString.symbolic("padding_receiver")

    result = model.apply([receiver, *args], {}, _state())

    assert "raised_exception" not in result.side_effects
    assert isinstance(result.value, SymbolicString)


@pytest.mark.parametrize(
    ("model", "args", "message"),
    [
        (
            BytesCenterModel(),
            ["3"],
            "'str' object cannot be interpreted as an integer",
        ),
        (
            BytesLjustModel(),
            [3, b""],
            "ljust() argument 2 must be a byte string of length 1, not bytes",
        ),
        (
            BytesRjustModel(),
            [3, 0],
            "rjust() argument 2 must be a byte string of length 1, not int",
        ),
        (
            BytesCenterModel(),
            [3, None],
            "center() argument 2 must be a byte string of length 1, not None",
        ),
        (
            BytesZfillModel(),
            [None],
            "'NoneType' object cannot be interpreted as an integer",
        ),
    ],
)
def test_bytes_padding_models_reject_invalid_operands_for_symbolic_receiver(
    model: FunctionModel,
    args: list[StackValue],
    message: str,
) -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_padding_receiver")

    result = model.apply([receiver, *args], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


@pytest.mark.parametrize(
    ("model", "args"),
    [
        (BytesCenterModel(), [3, b"x"]),
        (BytesCenterModel(), [3, _raw_bytearray_fillchar()]),
        (BytesCenterModel(), [SymbolicValue.symbolic_int("bytes_padding_width")[0]]),
        (BytesLjustModel(), [3, b"x"]),
        (BytesRjustModel(), [3, b"x"]),
        (BytesZfillModel(), [3]),
    ],
)
def test_bytes_padding_models_keep_valid_symbolic_receiver_non_error(
    model: FunctionModel,
    args: list[StackValue],
) -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_padding_receiver")

    result = model.apply([receiver, *args], {}, _state())

    assert "raised_exception" not in result.side_effects
    assert isinstance(result.value, SymbolicList)


def test_bytes_center_invalid_fill_emits_type_error() -> None:
    result = BytesCenterModel().apply([b"a", 3, b""], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_str_center_invalid_fill_emits_type_error() -> None:
    result = StrCenterModel().apply([SymbolicString.from_const("a"), 3, ""], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_bytes_upper_materializes_exact_bytes() -> None:
    result = BytesUpperModel().apply([b"a"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"A"


def test_bytes_lower_materializes_exact_bytes() -> None:
    result = BytesLowerModel().apply([b"A"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"a"


def test_bytes_isdigit_materializes_exact_false() -> None:
    result = BytesIsdigitModel().apply([b"a"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is False


def test_bytes_isascii_materializes_exact_false() -> None:
    result = BytesIsasciiModel().apply([b"\xff"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is False


def test_str_isascii_empty_symbolic_receiver_is_constrained_true() -> None:
    receiver, receiver_constraint = SymbolicString.symbolic("str_isascii_empty_receiver")

    result = StrIsasciiModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(receiver_constraint)
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 0)
    solver.add(z3.Not(result.value.z3_bool))
    assert solver.check() == z3.unsat


def test_bytes_isascii_empty_symbolic_receiver_is_constrained_true() -> None:
    receiver = SymbolicBytes.symbolic("bytes_isascii_empty_receiver")

    result = BytesIsasciiModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 0)
    solver.add(z3.Not(result.value.z3_bool))
    assert solver.check() == z3.unsat


def test_bytearray_isascii_empty_symbolic_receiver_is_constrained_true() -> None:
    receiver, receiver_constraint = SymbolicList.symbolic("bytearray_isascii_empty_receiver")
    receiver.set_runtime_type("bytearray")

    result = BytearrayIsasciiModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    solver = z3.Solver()
    solver.add(receiver_constraint)
    solver.add(*result.constraints)
    solver.add(receiver.z3_len == 0)
    solver.add(z3.Not(result.value.z3_bool))
    assert solver.check() == z3.unsat


def test_str_isdigit_materializes_exact_true() -> None:
    result = StrIsdigitModel().apply([SymbolicString.from_const("1")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is True


def test_str_isascii_materializes_exact_false() -> None:
    result = StrIsasciiModel().apply([SymbolicString.from_const("\u00e9")], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is False


def test_str_partition_materializes_exact_parts() -> None:
    result = StrPartitionModel().apply([SymbolicString.from_const("a:b"), ":"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a", ":", "b"]


def test_str_partition_empty_separator_emits_value_error() -> None:
    result = StrPartitionModel().apply([SymbolicString.from_const("a"), ""], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"


def test_str_partition_empty_separator_is_receiver_independent() -> None:
    receiver, _constraint = SymbolicString.symbolic("partition_source")
    result = StrPartitionModel().apply([receiver, ""], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"
    assert effect["message"] == "empty separator"


@pytest.mark.parametrize(
    ("model", "separator", "message"),
    [
        (StrPartitionModel(), SymbolicValue.from_const(1), "must be str, not int"),
        (StrRpartitionModel(), None, "must be str, not NoneType"),
    ],
)
def test_str_partition_models_reject_definite_invalid_separator(
    model: FunctionModel,
    separator: StackValue,
    message: str,
) -> None:
    result = model.apply([SymbolicString.from_const("a:b"), separator], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


def test_str_rpartition_materializes_exact_parts() -> None:
    result = StrRpartitionModel().apply([SymbolicString.from_const("a:b"), ":"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a", ":", "b"]


def test_str_splitlines_materializes_exact_lines() -> None:
    result = StrSplitlinesModel().apply([SymbolicString.from_const("a\nb")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a", "b"]


@pytest.mark.parametrize(
    ("keepends", "expected"),
    [
        ([], ["a", "b"]),
        ([1], ["a\n", "b"]),
        ({}, ["a", "b"]),
        ({"x": 1}, ["a\n", "b"]),
    ],
)
def test_str_splitlines_uses_concrete_keepends_truthiness(
    keepends: StackValue,
    expected: list[str],
) -> None:
    result = StrSplitlinesModel().apply([SymbolicString.from_const("a\nb"), keepends], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == expected


def test_bytes_partition_materializes_exact_parts() -> None:
    result = BytesPartitionModel().apply([b"a:b", b":"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [concrete_bytes_literal(part) for part in parts] == [b"a", b":", b"b"]


def test_bytes_partition_empty_separator_emits_value_error() -> None:
    result = BytesPartitionModel().apply([b"a", b""], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"


def test_bytes_partition_empty_separator_is_receiver_independent() -> None:
    receiver, _constraint = SymbolicList.symbolic("bytes_partition_source")
    result = BytesPartitionModel().apply([receiver, b""], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"
    assert effect["message"] == "empty separator"


@pytest.mark.parametrize(
    ("model", "separator", "message"),
    [
        (
            BytesPartitionModel(),
            SymbolicValue.from_const(1),
            "a bytes-like object is required, not 'int'",
        ),
        (
            BytesRpartitionModel(),
            None,
            "a bytes-like object is required, not 'NoneType'",
        ),
    ],
)
def test_bytes_partition_models_reject_definite_invalid_separator(
    model: FunctionModel,
    separator: StackValue,
    message: str,
) -> None:
    result = model.apply([b"a:b", separator], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
    assert effect["message"] == message


def test_bytes_rpartition_materializes_exact_parts() -> None:
    result = BytesRpartitionModel().apply([b"a:b", b":"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [concrete_bytes_literal(part) for part in parts] == [b"a", b":", b"b"]


def test_bytes_splitlines_materializes_exact_lines() -> None:
    result = BytesSplitlinesModel().apply([b"a\nb"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [concrete_bytes_literal(part) for part in parts] == [b"a", b"b"]


@pytest.mark.parametrize(
    ("keepends", "expected"),
    [
        ([], [b"a", b"b"]),
        ((1,), [b"a\n", b"b"]),
        ({}, [b"a", b"b"]),
        ({"x": 1}, [b"a\n", b"b"]),
    ],
)
def test_bytes_splitlines_uses_concrete_keepends_truthiness(
    keepends: StackValue,
    expected: list[bytes],
) -> None:
    result = BytesSplitlinesModel().apply([b"a\nb", keepends], {}, _state())

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [concrete_bytes_literal(part) for part in parts] == expected
