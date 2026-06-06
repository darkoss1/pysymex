"""Focused model tests for exact string/bytes translation methods."""

from __future__ import annotations

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.models.builtins.results import is_potential_exception_effect
from pysymex.models.containers.bytes.shared import concrete_bytes_literal
from pysymex.models.containers.bytes.translation import (
    BytesExpandtabsModel,
    BytesMaketransModel,
    BytesTranslateModel,
)
from pysymex.models.containers.strings.encoding import (
    StrExpandtabsModel,
    StrMaketransModel,
    StrTranslateModel,
)


def _state() -> VMState:
    return VMState(pc=0)


def test_str_expandtabs_materializes_exact_string() -> None:
    result = StrExpandtabsModel().apply([SymbolicString.from_const("a\t"), 4], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "a   "


def test_bytes_expandtabs_materializes_exact_bytes() -> None:
    result = BytesExpandtabsModel().apply([b"\x01\t", 4], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01   "


def test_str_translate_materializes_exact_string() -> None:
    table = SymbolicDict.from_const({97: "b"})
    result = StrTranslateModel().apply([SymbolicString.from_const("a"), table], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "b"


def test_str_maketrans_materializes_exact_table_from_instance_form() -> None:
    result = StrMaketransModel().apply(
        [SymbolicString.from_const(""), "a", "b"],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicDict)
    assert result.value.concrete_items == {97: 98}


def test_bytes_translate_none_table_materializes_exact_bytes() -> None:
    result = BytesTranslateModel().apply([b"\x01", SymbolicNone()], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01"


def test_bytes_translate_delete_materializes_empty_bytes() -> None:
    result = BytesTranslateModel().apply([b"\x01", SymbolicNone(), b"\x01"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b""


def test_bytes_maketrans_materializes_exact_table() -> None:
    result = BytesMaketransModel().apply([b"a", b"b"], {}, _state())

    assert isinstance(result.value, SymbolicList)
    table = concrete_bytes_literal(result.value)
    assert table is not None
    assert table[97] == 98


def test_bytes_maketrans_bad_lengths_emits_value_error() -> None:
    result = BytesMaketransModel().apply([b"a", b"bc"], {}, _state())

    effect = result.side_effects.get("potential_exception")
    assert is_potential_exception_effect(effect)
    assert effect["type"] == "ValueError"
