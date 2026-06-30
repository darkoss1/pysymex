"""Focused model tests for sequence edge-case retained-item precision."""

from __future__ import annotations

import dataclasses

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.containers.sequence_precision import (
    repeat_concrete_backed_sequence,
    slice_concrete_backed_sequence,
)
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue


def test_negative_repeat_materializes_empty_sequence() -> None:
    source = SymbolicList.from_const([1])

    result = repeat_concrete_backed_sequence(source, -1)

    assert isinstance(result, SymbolicList)
    assert result.concrete_items == []


def test_large_repeat_uses_exact_lazy_element_mapping() -> None:
    source = SymbolicList.from_const([7, 11])

    result = repeat_concrete_backed_sequence(source, 100)

    assert isinstance(result, SymbolicList)
    assert result.concrete_items is None
    assert simplify_expr(result.z3_len).as_long() == 200
    assert simplify_expr(result[SymbolicValue.from_const(199)].z3_int).as_long() == 11


def test_negative_start_slice_preserves_tail_item() -> None:
    source = SymbolicList.from_const([1, 2])

    result = slice_concrete_backed_sequence(source, slice(-1, None))

    assert isinstance(result, SymbolicList)
    assert result.concrete_items == [2]


def test_reverse_slice_preserves_item_order_and_tuple_type() -> None:
    source = dataclasses.replace(SymbolicList.from_const([1, 2]), _type="tuple")

    result = slice_concrete_backed_sequence(source, slice(None, None, -1))

    assert isinstance(result, SymbolicList)
    assert result.concrete_items == [2, 1]
    assert getattr(result, "_type") == "tuple"
