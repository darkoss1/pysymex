"""Focused model tests for sequence edge-case retained-item precision."""

from __future__ import annotations

import dataclasses

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.models.containers.sequence_precision import (
    repeat_concrete_backed_sequence,
    slice_concrete_backed_sequence,
)


def test_negative_repeat_materializes_empty_sequence() -> None:
    source = SymbolicList.from_const([1])

    result = repeat_concrete_backed_sequence(source, -1)

    assert isinstance(result, SymbolicList)
    assert result.concrete_items == []


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
