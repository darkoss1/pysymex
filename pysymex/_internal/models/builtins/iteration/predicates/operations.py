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

"""Exact operation evaluation for modeled iterator predicates."""

from __future__ import annotations

from typing import cast

from pysymex._internal.models.builtins.iteration.predicates.inputs import (
    ExactFilterValue,
    exact_filter_predicate_input,
)
from pysymex._internal.models.builtins.iteration.predicates.literals import ARG_TRUTH_BRANCH


def contains_exact_python_value(left: ExactFilterValue, right: object) -> bool | None:
    if isinstance(right, dict):
        right = tuple(cast("dict[object, object]", right).keys())
    if isinstance(right, str):
        return left in right if isinstance(left, str) else None
    if isinstance(right, bytes):
        return _contains_exact_bytes_value(left, right)
    if isinstance(right, bytearray):
        return _contains_exact_bytearray_value(left, right)
    if isinstance(right, (list, tuple)):
        return left in right
    if isinstance(right, (set, frozenset)):
        try:
            hash(left)
        except TypeError:
            return None
        try:
            return left in right
        except (TypeError, ValueError):
            return None
    if isinstance(right, range):
        try:
            return left in right
        except TypeError:
            return None
    return None


def _contains_exact_bytes_value(left: ExactFilterValue, right: bytes) -> bool | None:
    try:
        if isinstance(left, (int, bool)):
            return left in right
        if isinstance(left, bytes):
            return left in right
        if isinstance(left, bytearray):
            return bytes(left) in right
    except (TypeError, ValueError):
        return None
    return None


def _contains_exact_bytearray_value(left: ExactFilterValue, right: bytearray) -> bool | None:
    try:
        if isinstance(left, (int, bool)):
            return left in right
        if isinstance(left, bytes):
            return left in right
        if isinstance(left, bytearray):
            return bytes(left) in right
    except (TypeError, ValueError):
        return None
    return None


def affix_exact_python_value(
    value: ExactFilterValue,
    affix: object,
    method_name: str,
) -> bool | None:
    try:
        if isinstance(value, str) and _is_str_prefix(affix):
            str_affix = cast("str | tuple[str, ...]", affix)
            return (
                value.startswith(str_affix)
                if method_name == "startswith"
                else value.endswith(str_affix)
            )
        if isinstance(value, bytes) and _is_bytes_prefix(affix):
            bytes_affix = cast("bytes | tuple[bytes, ...]", affix)
            return (
                value.startswith(bytes_affix)
                if method_name == "startswith"
                else value.endswith(bytes_affix)
            )
        if isinstance(value, bytearray) and _is_bytearray_prefix(affix):
            bytearray_affix = cast("bytes | bytearray | tuple[bytes | bytearray, ...]", affix)
            return (
                value.startswith(bytearray_affix)
                if method_name == "startswith"
                else value.endswith(bytearray_affix)
            )
    except TypeError:
        return None
    return None


def _is_str_prefix(prefix: object) -> bool:
    if isinstance(prefix, str):
        return True
    if isinstance(prefix, tuple):
        return all(isinstance(item, str) for item in cast("tuple[object, ...]", prefix))
    return False


def _is_bytes_prefix(prefix: object) -> bool:
    if isinstance(prefix, bytes):
        return True
    if isinstance(prefix, tuple):
        return all(isinstance(item, bytes) for item in cast("tuple[object, ...]", prefix))
    return False


def _is_bytearray_prefix(prefix: object) -> bool:
    if isinstance(prefix, (bytes, bytearray)):
        return True
    if isinstance(prefix, tuple):
        return all(
            isinstance(item, (bytes, bytearray)) for item in cast("tuple[object, ...]", prefix)
        )
    return False


def exact_filter_predicate_slice(
    value: ExactFilterValue,
    slice_operand: slice[int | None, int | None, int | None],
) -> ExactFilterValue | None:
    if isinstance(value, str):
        return value[slice_operand]
    if isinstance(value, bytes):
        return value[slice_operand]
    if isinstance(value, bytearray):
        return value[slice_operand]
    if isinstance(value, list):
        return value[slice_operand]
    if isinstance(value, tuple):
        return value[slice_operand]
    return None


def exact_filter_predicate_unary_value(
    value: ExactFilterValue,
    operator_name: str,
) -> ExactFilterValue | None:
    if operator_name == "negative" and isinstance(value, (int, float, bool)):
        return -value
    if operator_name == "positive" and isinstance(value, (int, float, bool)):
        return +value
    if operator_name == "invert" and isinstance(value, (int, bool)):
        if isinstance(value, bool):
            return ~int(value)
        return ~value
    return None


def exact_filter_predicate_truth_value(value: ExactFilterValue) -> bool:
    return bool(value)


def exact_filter_predicate_len_value(value: ExactFilterValue) -> int | None:
    if isinstance(value, (str, bytes, bytearray, list, tuple)):
        return len(value)
    return None


def evaluate_conditional_truth_branch(
    branch_truth: object,
    item_value: ExactFilterValue,
) -> bool | None:
    if branch_truth is ARG_TRUTH_BRANCH:
        return exact_filter_predicate_truth_value(item_value)
    if isinstance(branch_truth, bool):
        return branch_truth
    return None


def compare_exact_python_value(
    left: ExactFilterValue,
    op_name: str,
    right: object,
) -> bool | None:
    right_value = exact_filter_predicate_input(right)
    if right_value is None:
        return None
    try:
        if op_name == "==":
            return left == right_value
        if op_name == "!=":
            return left != right_value
        return _order_compare_exact_python_values(left, op_name, right_value)
    except TypeError:
        return None


def _order_compare_exact_python_values(
    left: ExactFilterValue,
    op_name: str,
    right: ExactFilterValue,
) -> bool | None:
    if isinstance(left, (int, float, bool)) and isinstance(right, (int, float, bool)):
        return _order_compare_numeric(left, op_name, right)
    if isinstance(left, str) and isinstance(right, str):
        return _order_compare_str(left, op_name, right)
    if isinstance(left, bytes) and isinstance(right, bytes):
        return _order_compare_bytes(left, op_name, right)
    if isinstance(left, bytearray) and isinstance(right, bytearray):
        return _order_compare_bytearray(left, op_name, right)
    return None


def _order_compare_numeric(
    left: float | bool,
    op_name: str,
    right: float | bool,
) -> bool | None:
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    return None


def _order_compare_str(left: str, op_name: str, right: str) -> bool | None:
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    return None


def _order_compare_bytes(left: bytes, op_name: str, right: bytes) -> bool | None:
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    return None


def _order_compare_bytearray(
    left: bytearray,
    op_name: str,
    right: bytearray,
) -> bool | None:
    if op_name == "<":
        return left < right
    if op_name == "<=":
        return left <= right
    if op_name == ">":
        return left > right
    if op_name == ">=":
        return left >= right
    return None
