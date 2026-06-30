"""Focused model tests for exact string/bytes join and codec methods."""

from __future__ import annotations

import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.builtins.types.containers.bytes.decoding import BytesDecodeModel
from pysymex._internal.models.builtins.types.containers.bytes.shared import (
    concrete_bytes_literal,
    symbolic_bytes_literal,
)
from pysymex._internal.models.builtins.types.containers.bytes.splitting import BytesJoinModel
from pysymex._internal.models.builtins.types.containers.strings.encoding import StrEncodeModel
from pysymex._internal.models.builtins.types.containers.strings.splitting import StrJoinModel
from pysymex._internal.models.contracts.results import SideEffects


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


def test_str_encode_default_preserves_symbolic_nonempty_bytes_length() -> None:
    source, source_constraint = SymbolicString.symbolic("str_encode_source")

    result = StrEncodeModel().apply([source], {}, _state())

    assert isinstance(result.value, SymbolicList)
    assert getattr(result.value, "_type", None) == "bytes"
    solver = z3.Solver()
    solver.add(source_constraint, *result.constraints)
    solver.add(source.z3_len > 0)
    solver.add(result.value.z3_len == 0)
    assert solver.check() == z3.unsat


def test_str_encode_ignore_can_shrink_symbolic_nonempty_text() -> None:
    source, source_constraint = SymbolicString.symbolic("str_encode_ignore_source")

    result = StrEncodeModel().apply(
        [source, SymbolicString.from_const("ascii"), SymbolicString.from_const("ignore")],
        {},
        _state(),
    )

    assert isinstance(result.value, SymbolicList)
    solver = z3.Solver()
    solver.add(source_constraint, *result.constraints)
    solver.add(source.z3_len == 1)
    solver.add(result.value.z3_len == 0)
    assert solver.check() == z3.sat


def test_bytes_decode_materializes_exact_string() -> None:
    result = BytesDecodeModel().apply([b"a"], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "a"


def test_str_encode_invalid_encoding_type_emits_type_error() -> None:
    result = StrEncodeModel().apply([SymbolicString.from_const("a"), 1], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_str_encode_invalid_encoding_type_rejected_with_symbolic_receiver() -> None:
    source, _source_constraint = SymbolicString.symbolic("str_encode_bad_encoding_source")

    result = StrEncodeModel().apply([source, 1], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


def test_bytes_decode_invalid_encoding_type_emits_type_error() -> None:
    result = BytesDecodeModel().apply([b"a", 1], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"
