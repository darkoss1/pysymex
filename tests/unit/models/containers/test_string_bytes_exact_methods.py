"""Focused model tests for exact string and bytes method materialization."""

from __future__ import annotations

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.results import (
    is_potential_exception_effect,
    is_raised_exception_effect,
)
from pysymex.models.containers.bytes.formatting import (
    BytesCenterModel,
    BytesLjustModel,
    BytesZfillModel,
)
from pysymex.models.containers.bytes.classification import BytesIsasciiModel, BytesIsdigitModel
from pysymex.models.containers.bytes.shared import concrete_bytes_literal
from pysymex.models.containers.bytes.search.counts import BytesContainsModel, BytesCountModel
from pysymex.models.containers.bytes.search.affixes import (
    BytesEndswithModel,
    BytesStartswithModel,
)
from pysymex.models.containers.bytes.search.indexing import BytesFindModel, BytesIndexModel
from pysymex.models.containers.bytes.splitting import (
    BytesPartitionModel,
    BytesRpartitionModel,
    BytesRsplitModel,
    BytesSplitlinesModel,
    BytesSplitModel,
)
from pysymex.models.containers.bytes.transforms.case import BytesLowerModel, BytesUpperModel
from pysymex.models.containers.bytes.transforms.replace import BytesReplaceModel
from pysymex.models.containers.bytes.transforms.trimming import (
    BytesRemovePrefixModel,
    BytesRemoveSuffixModel,
    BytesStripModel,
)
from pysymex.models.containers.strings.classification.content import StrIsdigitModel
from pysymex.models.containers.strings.classification.special import StrIsasciiModel
from pysymex.models.containers.strings.formatting import StrCenterModel
from pysymex.models.containers.strings.search.affixes import StrReplaceModel
from pysymex.models.containers.strings.search.indexing import StrRfindModel
from pysymex.models.containers.strings.splitting import (
    StrPartitionModel,
    StrRpartitionModel,
    StrRsplitModel,
    StrSplitlinesModel,
    StrSplitModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def test_str_split_materializes_exact_parts() -> None:
    result = StrSplitModel().apply([SymbolicString.from_const("a,b"), ","], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a", "b"]


def test_str_rsplit_materializes_exact_parts() -> None:
    result = StrRsplitModel().apply([SymbolicString.from_const("a,b,c"), ",", 1], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a,b", "c"]


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


def test_bytes_strip_materializes_exact_bytes() -> None:
    result = BytesStripModel().apply([b"\x00\x01\x00", b"\x00"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytes_removeprefix_materializes_exact_bytes() -> None:
    result = BytesRemovePrefixModel().apply([b"\x00\x01", b"\x00"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytes_removesuffix_materializes_exact_bytes() -> None:
    result = BytesRemoveSuffixModel().apply([b"\x01\x00", b"\x00"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytes_startswith_materializes_exact_false() -> None:
    result = BytesStartswithModel().apply([b"\x01", b"\x02"], {}, _state())

    assert isinstance(result.value, SymbolicValue)
    assert result.value.value is False


def test_bytes_endswith_materializes_exact_true_for_empty_suffix() -> None:
    result = BytesEndswithModel().apply([b"", b""], {}, _state())

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


def test_bytes_index_missing_emits_value_error_side_effect() -> None:
    result = BytesIndexModel().apply([b"abc", b"z"], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert is_potential_exception_effect(effect)
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


def test_bytes_center_invalid_fill_emits_type_error() -> None:
    result = BytesCenterModel().apply([b"a", 3, b""], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_str_center_invalid_fill_emits_type_error() -> None:
    result = StrCenterModel().apply([SymbolicString.from_const("a"), 3, ""], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
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
    assert is_potential_exception_effect(effect)
    assert effect["type"] == "ValueError"


def test_str_rpartition_materializes_exact_parts() -> None:
    result = StrRpartitionModel().apply([SymbolicString.from_const("a:b"), ":"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a", ":", "b"]


def test_str_splitlines_materializes_exact_lines() -> None:
    result = StrSplitlinesModel().apply([SymbolicString.from_const("a\nb")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert result.value.concrete_items == ["a", "b"]


def test_bytes_partition_materializes_exact_parts() -> None:
    result = BytesPartitionModel().apply([b"a:b", b":"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    parts = result.value.concrete_items
    assert parts is not None
    assert [concrete_bytes_literal(part) for part in parts] == [b"a", b":", b"b"]


def test_bytes_partition_empty_separator_emits_value_error() -> None:
    result = BytesPartitionModel().apply([b"a", b""], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert is_potential_exception_effect(effect)
    assert effect["type"] == "ValueError"


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
