from __future__ import annotations

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_ZERO
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.string_search import (
    concrete_optional_string_index,
    concrete_string_index,
    concrete_string_slice_args,
    string_slice_bounds_are_definitely_invalid,
    string_type_name_if_definitely_not_string,
)
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


def test_string_type_name_if_definitely_not_string_classifies_precise_operands() -> None:
    symbolic_int, _ = SymbolicValue.symbolic_int("string_search_symbolic_int")
    unknown, _ = SymbolicValue.symbolic("string_search_unknown")

    assert string_type_name_if_definitely_not_string("x") is None
    assert string_type_name_if_definitely_not_string(SymbolicString.from_const("x")) is None
    assert string_type_name_if_definitely_not_string(1) == "int"
    assert string_type_name_if_definitely_not_string(None) == "NoneType"
    assert string_type_name_if_definitely_not_string(SymbolicNoneType()) == "NoneType"
    assert string_type_name_if_definitely_not_string(symbolic_int) == "int"
    assert string_type_name_if_definitely_not_string(unknown) is None


def test_string_slice_bounds_accept_none_and_int_like_values() -> None:
    symbolic_none = SymbolicValue(
        _name="string_search_symbolic_none",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_none=z3.BoolVal(True),
    )

    assert not string_slice_bounds_are_definitely_invalid([None, SymbolicNoneType(), True, 1])
    assert not string_slice_bounds_are_definitely_invalid([symbolic_none])
    assert string_slice_bounds_are_definitely_invalid(["0"])


def test_concrete_string_indexes_preserve_cpython_bool_and_none_rules() -> None:
    unresolved, _ = SymbolicValue.symbolic_int("string_search_unresolved_index")

    assert concrete_string_index(True) == 1
    assert concrete_string_index(-2) == -2
    assert concrete_string_index("1") is None
    assert concrete_string_index(unresolved) is None
    assert concrete_optional_string_index(SymbolicNoneType()) == (True, None)
    assert concrete_optional_string_index(None) == (True, None)
    assert concrete_optional_string_index(False) == (True, 0)
    assert concrete_optional_string_index(unresolved) == (False, None)
    assert concrete_string_slice_args([None, True, -1]) == [None, 1, -1]
    assert concrete_string_slice_args([None, "1"]) is None
