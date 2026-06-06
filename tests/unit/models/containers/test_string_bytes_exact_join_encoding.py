"""Focused model tests for exact string/bytes join and codec methods."""

from __future__ import annotations

from pysymex.core.state.record import VMState
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.models.builtins.results import is_raised_exception_effect
from pysymex.models.containers.bytes.decoding import BytesDecodeModel
from pysymex.models.containers.bytes.shared import concrete_bytes_literal, symbolic_bytes_literal
from pysymex.models.containers.bytes.splitting import BytesJoinModel
from pysymex.models.containers.strings.encoding import StrEncodeModel
from pysymex.models.containers.strings.splitting import StrJoinModel


def _state() -> VMState:
    return VMState(pc=0)


def test_str_join_materializes_exact_string() -> None:
    result = StrJoinModel().apply(
        [SymbolicString.from_const(","), SymbolicList.from_const(["a", "b"])],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "a,b"


def test_bytes_join_materializes_exact_bytes() -> None:
    result = BytesJoinModel().apply(
        [b",", SymbolicList.from_const([symbolic_bytes_literal(b"\x01"), b"\x02"])],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"\x01,\x02"


def test_str_encode_materializes_exact_bytes() -> None:
    result = StrEncodeModel().apply([SymbolicString.from_const("a")], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert concrete_bytes_literal(result.value) == b"a"


def test_bytes_decode_materializes_exact_string() -> None:
    result = BytesDecodeModel().apply([b"a"], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "a"


def test_str_encode_invalid_encoding_type_emits_type_error() -> None:
    result = StrEncodeModel().apply([SymbolicString.from_const("a"), 1], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"


def test_bytes_decode_invalid_encoding_type_emits_type_error() -> None:
    result = BytesDecodeModel().apply([b"a", 1], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert is_raised_exception_effect(effect)
    assert effect["exception_type"] == "TypeError"
