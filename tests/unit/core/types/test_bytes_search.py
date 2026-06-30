from __future__ import annotations

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.bytes import SymbolicBytes
from pysymex._internal.core.types.containers.bytes_search import (
    bytes_index_type_name_if_definitely_invalid,
    bytes_slice_bounds_are_definitely_invalid,
    bytes_type_name_if_definitely_not_bytes_like,
    concrete_bytes_index,
    concrete_bytes_search_literal,
    concrete_bytes_slice_args,
    concrete_optional_bytes_index,
)
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue


def test_concrete_bytes_search_literal_reads_core_bytes_carriers() -> None:
    assert concrete_bytes_search_literal(b"abc") == b"abc"
    assert concrete_bytes_search_literal(bytearray(b"abc")) == b"abc"
    assert concrete_bytes_search_literal(memoryview(b"abc")) == b"abc"
    assert concrete_bytes_search_literal(SymbolicBytes.concrete(b"abc")) == b"abc"


def test_bytes_type_name_if_definitely_not_bytes_like_classifies_precise_operands() -> None:
    symbolic_bytes = SymbolicValue(
        _name="bytes_search_symbolic_bytes",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_bytes=Z3_TRUE,
    )
    symbolic_str = SymbolicValue(
        _name="bytes_search_symbolic_str",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_TRUE,
    )
    unknown, _ = SymbolicValue.symbolic("bytes_search_unknown")

    assert bytes_type_name_if_definitely_not_bytes_like(b"x") is None
    assert bytes_type_name_if_definitely_not_bytes_like(symbolic_bytes) is None
    assert bytes_type_name_if_definitely_not_bytes_like(SymbolicString.from_const("x")) == "str"
    assert bytes_type_name_if_definitely_not_bytes_like(symbolic_str) == "str"
    assert bytes_type_name_if_definitely_not_bytes_like(None) == "NoneType"
    assert bytes_type_name_if_definitely_not_bytes_like(SymbolicNoneType()) == "NoneType"
    assert bytes_type_name_if_definitely_not_bytes_like(1) == "int"
    assert bytes_type_name_if_definitely_not_bytes_like(unknown) is None


def test_bytes_slice_bounds_and_indexes_preserve_cpython_rules() -> None:
    symbolic_none = SymbolicValue(
        _name="bytes_search_symbolic_none",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_none=z3.BoolVal(True),
    )
    unresolved, _ = SymbolicValue.symbolic_int("bytes_search_unresolved_index")

    assert not bytes_slice_bounds_are_definitely_invalid([None, SymbolicNoneType(), True, 1])
    assert not bytes_slice_bounds_are_definitely_invalid([symbolic_none, unresolved])
    assert bytes_slice_bounds_are_definitely_invalid(["0"])
    assert concrete_bytes_index(True) == 1
    assert concrete_bytes_index(-2) == -2
    assert concrete_bytes_index("1") is None
    assert concrete_optional_bytes_index(SymbolicNoneType()) == (True, None)
    assert concrete_optional_bytes_index(None) == (True, None)
    assert concrete_optional_bytes_index(False) == (True, 0)
    assert concrete_optional_bytes_index(symbolic_none) == (True, None)
    assert concrete_optional_bytes_index(unresolved) == (False, None)
    assert concrete_bytes_slice_args([None, True, -1]) == [None, 1, -1]
    assert concrete_bytes_slice_args([None, unresolved]) is None


def test_bytes_index_type_name_if_definitely_invalid_classifies_count_operands() -> None:
    symbolic_bool, _ = SymbolicValue.symbolic_bool("bytes_search_count_bool")
    symbolic_int, _ = SymbolicValue.symbolic_int("bytes_search_count_int")
    symbolic_float = SymbolicValue(
        _name="bytes_search_count_float",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_float=Z3_TRUE,
    )
    unknown, _ = SymbolicValue.symbolic("bytes_search_count_unknown")

    assert bytes_index_type_name_if_definitely_invalid(True) is None
    assert bytes_index_type_name_if_definitely_invalid(3) is None
    assert bytes_index_type_name_if_definitely_invalid(symbolic_bool) is None
    assert bytes_index_type_name_if_definitely_invalid(symbolic_int) is None
    assert bytes_index_type_name_if_definitely_invalid(symbolic_float) == "float"
    assert bytes_index_type_name_if_definitely_invalid(SymbolicString.from_const("1")) == "str"
    assert bytes_index_type_name_if_definitely_invalid(SymbolicNoneType()) == "NoneType"
    assert bytes_index_type_name_if_definitely_invalid(unknown) is None
