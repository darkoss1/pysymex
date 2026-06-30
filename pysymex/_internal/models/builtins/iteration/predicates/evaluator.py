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

"""Exact map/filter callable support for finite iterator materialization."""

from __future__ import annotations

from typing import cast

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.models.builtins.iteration.predicates.inputs import (
    callable_payload,
    exact_filter_predicate_input,
    exact_filter_predicate_str_input,
    exact_int_map_input,
    truth_predicate,
)
from pysymex._internal.models.builtins.iteration.predicates.operations import (
    affix_exact_python_value,
    compare_exact_python_value,
    contains_exact_python_value,
    evaluate_conditional_truth_branch,
    exact_filter_predicate_len_value,
    exact_filter_predicate_slice,
    exact_filter_predicate_truth_value,
    exact_filter_predicate_unary_value,
)
from pysymex._internal.models.builtins.iteration.predicates.specs import simple_filter_predicate


def supports_exact_single_iterable_map(function: object) -> bool:
    """Return whether PySyMex can exactly model this single-iterable map callable."""
    callable_obj = callable_payload(function)
    return callable_obj in {abs, bool, int}


def realize_single_iterable_map(
    function: object,
    items: list[object],
) -> list[object] | None:
    """Return exact mapped items for supported map callables, or ``None``."""
    callable_obj = callable_payload(function)
    if callable_obj is abs:
        return _exact_abs_map(items)
    if callable_obj is bool:
        return _exact_bool_map(items)
    if callable_obj is int:
        return _exact_int_map(items)
    return None


def is_truth_filter_predicate(predicate: object) -> bool:
    """Return whether ``filter`` can be modeled with item truthiness only."""
    return predicate is None or isinstance(predicate, SymbolicNoneType) or predicate is bool


def supports_exact_filter_predicate(predicate: object) -> bool:
    """Return whether ``filter`` can exactly evaluate this predicate for concrete items."""
    return is_truth_filter_predicate(predicate) or simple_filter_predicate(predicate) is not None


def _exact_abs_map(items: list[object]) -> list[object] | None:
    mapped: list[object] = []
    for item in items:
        exact_item = exact_int_map_input(item)
        if exact_item is None:
            return None
        if not isinstance(exact_item, (int, float, bool)):
            return None
        mapped.append(abs(exact_item))
    return mapped


def _exact_int_map(items: list[object]) -> list[object] | None:
    mapped: list[object] = []
    for item in items:
        exact_item = exact_int_map_input(item)
        if exact_item is None:
            return None
        try:
            mapped.append(int(exact_item))
        except (TypeError, ValueError):
            return None
    return mapped


def _exact_bool_map(items: list[object]) -> list[object] | None:
    mapped: list[object] = []
    for item in items:
        truth = truth_predicate(item)
        if truth is None:
            return None
        simplified = simplify_expr(truth)
        if z3.is_true(simplified):
            mapped.append(True)
        elif z3.is_false(simplified):
            mapped.append(False)
        else:
            return None
    return mapped


def filter_item_truth(predicate: object, item: object) -> z3.BoolRef | None:
    if is_truth_filter_predicate(predicate):
        return truth_predicate(item)
    result = _evaluate_simple_filter_predicate(predicate, item)
    if result is None:
        return None
    return Z3_TRUE if result else Z3_FALSE


def _evaluate_simple_filter_predicate(predicate: object, item: object) -> bool | None:
    spec = simple_filter_predicate(predicate)
    if spec is None:
        return None
    kind, op_name, operand, expected = spec
    try:
        if kind == "str_contains":
            str_value = exact_filter_predicate_str_input(item)
            if str_value is None:
                return None
            contains = contains_exact_python_value(str_value, operand)
            if contains is None:
                return None
            return not contains if op_name == "not in" else contains

        item_value = exact_filter_predicate_input(item)
        if item_value is None:
            return None
        if kind == "not_truth":
            return not exact_filter_predicate_truth_value(item_value)
        if kind == "contains":
            contains = contains_exact_python_value(item_value, operand)
            if contains is None:
                return None
            return not contains if op_name == "not in" else contains
        if kind in {"startswith", "endswith"}:
            return affix_exact_python_value(item_value, operand, kind)
        if kind == "compare":
            return compare_exact_python_value(item_value, op_name, operand)
        if kind == "slice_compare":
            if not isinstance(operand, slice):
                return None
            sliced_value = exact_filter_predicate_slice(
                item_value,
                cast("slice[int | None, int | None, int | None]", operand),
            )
            if sliced_value is None:
                return None
            return compare_exact_python_value(sliced_value, op_name, expected)
        if kind == "unary_compare":
            if not isinstance(operand, str):
                return None
            unary_value = exact_filter_predicate_unary_value(item_value, operand)
            if unary_value is None:
                return None
            return compare_exact_python_value(unary_value, op_name, expected)
        if kind == "abs_compare":
            if not isinstance(item_value, (int, float, bool)):
                return None
            return compare_exact_python_value(abs(item_value), op_name, operand)
        if kind == "len_compare":
            length = exact_filter_predicate_len_value(item_value)
            if length is None:
                return None
            return compare_exact_python_value(length, op_name, operand)
        if kind == "chained_compare":
            if not isinstance(expected, tuple):
                return None
            chain_expected = cast("tuple[object, ...]", expected)
            if len(chain_expected) != 2:
                return None
            upper_op, upper_bound = chain_expected
            if not isinstance(upper_op, str):
                return None
            lower_value = exact_filter_predicate_input(operand)
            if lower_value is None:
                return None
            lower_result = compare_exact_python_value(lower_value, op_name, item_value)
            if lower_result is None:
                return None
            if not lower_result:
                return False
            return compare_exact_python_value(item_value, upper_op, upper_bound)
        if kind == "and_compare_mod_compare":
            if not isinstance(expected, tuple):
                return None
            and_expected = cast("tuple[object, ...]", expected)
            if len(and_expected) != 3:
                return None
            mod_value, second_op, second_expected = and_expected
            if not isinstance(mod_value, int) or not isinstance(second_op, str):
                return None
            if not isinstance(item_value, (int, float, bool)):
                return None
            first_result = compare_exact_python_value(item_value, op_name, operand)
            if first_result is None:
                return None
            if not first_result:
                return False
            return compare_exact_python_value(item_value % mod_value, second_op, second_expected)
        if kind == "or_compare":
            if not isinstance(expected, tuple):
                return None
            or_expected = cast("tuple[object, ...]", expected)
            if len(or_expected) != 2:
                return None
            second_op, second_bound = or_expected
            if not isinstance(second_op, str):
                return None
            first_result = compare_exact_python_value(item_value, op_name, operand)
            if first_result is None:
                return None
            if first_result:
                return True
            return compare_exact_python_value(item_value, second_op, second_bound)
        if kind == "or_compare_mod_compare":
            if not isinstance(expected, tuple):
                return None
            or_expected = cast("tuple[object, ...]", expected)
            if len(or_expected) != 3:
                return None
            mod_value, second_op, second_expected = or_expected
            if not isinstance(mod_value, int) or not isinstance(second_op, str):
                return None
            first_result = compare_exact_python_value(item_value, op_name, operand)
            if first_result is None:
                return None
            if first_result:
                return True
            if not isinstance(item_value, (int, float, bool)):
                return None
            return compare_exact_python_value(item_value % mod_value, second_op, second_expected)
        if kind == "conditional_compare_truth":
            if not isinstance(expected, tuple):
                return None
            conditional_expected = cast("tuple[object, ...]", expected)
            if len(conditional_expected) != 2:
                return None
            true_truth, false_truth = conditional_expected
            condition = compare_exact_python_value(item_value, op_name, operand)
            if condition is None:
                return None
            return evaluate_conditional_truth_branch(
                true_truth if condition else false_truth,
                item_value,
            )
        if kind == "mod_compare":
            if not isinstance(item_value, (int, float, bool)):
                return None
            if not isinstance(operand, (int, bool)) or isinstance(operand, bool):
                return None
            if operand == 0:
                return None
            return compare_exact_python_value(item_value % operand, op_name, expected)
    except (ArithmeticError, TypeError, ValueError):
        return None
    return None
