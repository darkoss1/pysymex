"""Focused model tests for exact string/bytes translation methods."""

from __future__ import annotations

import pytest
import z3

from pysymex._internal.core.state.record import VMState
from pysymex._internal.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.models.builtins.types.containers.bytes.shared import concrete_bytes_literal
from pysymex._internal.models.builtins.types.containers.bytes.translation import (
    BytesExpandtabsModel,
    BytesMaketransModel,
    BytesTranslateModel,
)
from pysymex._internal.models.builtins.types.containers.strings.encoding import (
    StrExpandtabsModel,
    StrMaketransModel,
    StrTranslateModel,
)
from pysymex._internal.models.contracts.results import SideEffects


def _state() -> VMState:
    return VMState(pc=0)


def test_str_expandtabs_materializes_exact_string() -> None:
    result = StrExpandtabsModel().apply([SymbolicString.from_const("a\t"), 4], {}, _state())

    assert isinstance(result.value, SymbolicString)
    assert result.value.z3_str.as_string() == "a   "


def test_str_expandtabs_positive_tabsize_preserves_symbolic_nonempty_result() -> None:
    receiver, receiver_constraint = SymbolicString.symbolic("str_expandtabs_positive_receiver")

    result = StrExpandtabsModel().apply([receiver, 1], {}, _state())

    assert isinstance(result.value, SymbolicString)
    solver = z3.Solver()
    solver.add(receiver_constraint, *result.constraints)
    solver.add(receiver.z3_len > 0)
    solver.add(result.value.z3_len == 0)
    assert solver.check() == z3.unsat


@pytest.mark.parametrize("tabsize", [0, -1])
def test_str_expandtabs_nonpositive_tabsize_can_shrink_symbolic_text(
    tabsize: int,
) -> None:
    receiver, receiver_constraint = SymbolicString.symbolic("str_expandtabs_nonpositive_receiver")

    result = StrExpandtabsModel().apply([receiver, tabsize], {}, _state())

    assert isinstance(result.value, SymbolicString)
    solver = z3.Solver()
    solver.add(receiver_constraint, *result.constraints)
    solver.add(receiver.z3_len == 1)
    solver.add(result.value.z3_len == 0)
    assert solver.check() == z3.sat


def test_str_expandtabs_empty_symbolic_text_remains_empty() -> None:
    receiver, receiver_constraint = SymbolicString.symbolic("str_expandtabs_empty_receiver")

    result = StrExpandtabsModel().apply([receiver], {}, _state())

    assert isinstance(result.value, SymbolicString)
    solver = z3.Solver()
    solver.add(receiver_constraint, *result.constraints)
    solver.add(receiver.z3_len == 0)
    solver.add(result.value.z3_len != 0)
    assert solver.check() == z3.unsat


def test_str_expandtabs_invalid_tabsize_rejected_with_symbolic_receiver() -> None:
    receiver, _receiver_constraint = SymbolicString.symbolic("str_expandtabs_bad_tabsize_receiver")

    result = StrExpandtabsModel().apply([receiver, "wide"], {}, _state())

    effect = result.side_effects.get("raised_exception")
    assert SideEffects.is_raised_exception(effect)
    assert effect["exception_type"] == "TypeError"


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
    assert SideEffects.is_potential_exception(effect)
    assert effect["type"] == "ValueError"
