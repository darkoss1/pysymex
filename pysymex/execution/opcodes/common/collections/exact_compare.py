# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Exact retained-container comparison helpers for ``COMPARE_OP``."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, TypeAlias, cast

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.types.containers.bytes import SymbolicBytes
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.containers.sequence_precision import exact_concrete_items

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.typing import StackValue

_ExactSequenceKind: TypeAlias = Literal["list", "bytes", "bytearray"]
_UNKNOWN_EQUALITY_VALUE = object()


def exact_list_comparison_condition(
    left: StackValue,
    right: StackValue,
    op_name: str,
    state: VMState,
) -> z3.BoolRef | None:
    """Return exact retained sequence equality or inequality when both operands are retained."""
    if op_name not in {"==", "!="}:
        return None
    left_sequence = _exact_sequence_items(left, state)
    right_sequence = _exact_sequence_items(right, state)
    if left_sequence is None or right_sequence is None:
        return None
    left_kind, left_items = left_sequence
    right_kind, right_items = right_sequence
    if not _sequence_kinds_can_compare_equal(left_kind, right_kind):
        equal = False
    else:
        sequence_equal = _exact_item_sequence_equal(left_items, right_items)
        if sequence_equal is None:
            return None
        equal = sequence_equal
    if op_name == "!=":
        equal = not equal
    return Z3_TRUE if equal else Z3_FALSE


def _exact_sequence_items(
    value: object,
    state: VMState,
) -> tuple[_ExactSequenceKind, list[object]] | None:
    resolved = _resolve_heap_operand(value, state)
    if isinstance(resolved, list):
        return "list", list(cast("list[object]", resolved))
    if isinstance(resolved, bytes):
        return "bytes", list(resolved)
    if isinstance(resolved, bytearray):
        return "bytearray", list(resolved)
    if isinstance(resolved, SymbolicBytes):
        concrete_value = resolved.concrete_value
        return None if concrete_value is None else ("bytes", list(concrete_value))
    if isinstance(resolved, SymbolicList):
        sequence_type = getattr(resolved, "_type", None)
        if sequence_type in {None, "list"}:
            kind: _ExactSequenceKind = "list"
        elif sequence_type == "bytes":
            kind = "bytes"
        elif sequence_type == "bytearray":
            kind = "bytearray"
        else:
            return None
        items = exact_concrete_items(resolved)
        return None if items is None else (kind, list(items))
    return None


def _sequence_kinds_can_compare_equal(
    left_kind: _ExactSequenceKind,
    right_kind: _ExactSequenceKind,
) -> bool:
    if left_kind == "list" or right_kind == "list":
        return left_kind == "list" and right_kind == "list"
    return True


def _resolve_heap_operand(value: object, state: VMState) -> object:
    if isinstance(value, SymbolicObject) and value.address in state.memory:
        return state.memory[value.address]
    return value


def _exact_item_sequence_equal(left: list[object], right: list[object]) -> bool | None:
    if len(left) != len(right):
        return False
    saw_unknown = False
    for left_item, right_item in zip(left, right, strict=True):
        equal = _exact_item_equal(left_item, right_item)
        if equal is False:
            return False
        if equal is None:
            saw_unknown = True
    return None if saw_unknown else True


def _exact_item_equal(left: object, right: object) -> bool | None:
    left_value = _exact_item_payload(left)
    right_value = _exact_item_payload(right)
    if left_value is _UNKNOWN_EQUALITY_VALUE or right_value is _UNKNOWN_EQUALITY_VALUE:
        return None
    return left_value == right_value


def _exact_item_payload(value: object) -> object:
    if isinstance(value, SymbolicValue):
        if value.value is not None:
            return value.value
        if z3.is_true(z3.simplify(value.is_none)):
            return None
        if z3.is_true(z3.simplify(value.is_str)) and z3.is_string_value(value.z3_str):
            try:
                return value.z3_str.as_string()
            except z3.Z3Exception:
                return _UNKNOWN_EQUALITY_VALUE
        return _UNKNOWN_EQUALITY_VALUE
    if isinstance(value, SymbolicString):
        if z3.is_string_value(value.z3_str):
            return value.z3_str.as_string()
        return _UNKNOWN_EQUALITY_VALUE
    return value
