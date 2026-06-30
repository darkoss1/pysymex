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

"""Supported filter predicate bytecode patterns."""

from __future__ import annotations

import dis
from typing import cast

from pysymex._internal.models.builtins.iteration.predicates.bytecode import (
    is_load_arg,
    is_load_global,
    is_not_filter_predicate,
    unary_filter_operator,
)
from pysymex._internal.models.builtins.iteration.predicates.inputs import callable_payload
from pysymex._internal.models.builtins.iteration.predicates.literals import (
    literal_and_compare_mod_compare_operand,
    literal_chained_compare_operand,
    literal_conditional_compare_truth_operand,
    literal_dict_keys_operand,
    literal_list_operand,
    literal_or_compare_mod_compare_operand,
    literal_or_compare_operand,
    literal_range_operand,
)
from pysymex._internal.models.builtins.iteration.predicates.slices import literal_slice_operand


def simple_filter_predicate(predicate: object) -> tuple[str, str, object, object | None] | None:
    callable_obj = callable_payload(predicate)
    code = getattr(callable_obj, "__code__", None)
    if code is None or getattr(code, "co_argcount", 0) != 1:
        return None
    instructions = [
        instruction
        for instruction in dis.get_instructions(code)
        if instruction.opname not in {"CACHE", "EXTENDED_ARG", "NOP", "PRECALL", "RESUME"}
    ]
    if len(instructions) == 4 and is_load_arg(instructions[0]):
        load_const, op, ret = instructions[1:]
        if (
            load_const.opname == "LOAD_CONST"
            and op.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("compare", cast("str", op.argval), load_const.argval, None)
        if (
            load_const.opname == "LOAD_CONST"
            and op.opname == "CONTAINS_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            op_name = "not in" if op.arg == 1 else "in"
            return ("contains", op_name, load_const.argval, None)
    if is_not_filter_predicate(instructions):
        return ("not_truth", "", None, None)
    chained_compare = literal_chained_compare_operand(instructions)
    if chained_compare is not None:
        lower_bound, lower_op, upper_op, upper_bound = chained_compare
        return ("chained_compare", lower_op, lower_bound, (upper_op, upper_bound))
    and_compare_mod = literal_and_compare_mod_compare_operand(instructions)
    if and_compare_mod is not None:
        first_op, first_bound, mod_value, second_op, second_expected = and_compare_mod
        return (
            "and_compare_mod_compare",
            first_op,
            first_bound,
            (mod_value, second_op, second_expected),
        )
    or_compare = literal_or_compare_operand(instructions)
    if or_compare is not None:
        first_op, first_bound, second_op, second_bound = or_compare
        return ("or_compare", first_op, first_bound, (second_op, second_bound))
    or_compare_mod = literal_or_compare_mod_compare_operand(instructions)
    if or_compare_mod is not None:
        first_op, first_bound, mod_value, second_op, second_expected = or_compare_mod
        return (
            "or_compare_mod_compare",
            first_op,
            first_bound,
            (mod_value, second_op, second_expected),
        )
    conditional_compare = literal_conditional_compare_truth_operand(instructions)
    if conditional_compare is not None:
        op_name, bound, true_truth, false_truth = conditional_compare
        return ("conditional_compare_truth", op_name, bound, (true_truth, false_truth))
    if len(instructions) >= 4 and is_load_arg(instructions[0]):
        op, ret = instructions[-2:]
        slice_operand = literal_slice_operand(instructions[1:-3])
        if (
            slice_operand is not None
            and instructions[-3].opname == "LOAD_CONST"
            and op.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("slice_compare", cast("str", op.argval), slice_operand, instructions[-3].argval)
        dict_keys_operand = literal_dict_keys_operand(instructions[1:-2])
        if (
            dict_keys_operand is not None
            and op.opname == "CONTAINS_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            op_name = "not in" if op.arg == 1 else "in"
            return ("contains", op_name, dict_keys_operand, None)
        range_operand = literal_range_operand(instructions[1:-2])
        if (
            range_operand is not None
            and op.opname == "CONTAINS_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            op_name = "not in" if op.arg == 1 else "in"
            return ("contains", op_name, range_operand, None)
        list_operand = literal_list_operand(instructions[1:-2])
        if list_operand is not None and op.opname == "COMPARE_OP" and ret.opname == "RETURN_VALUE":
            return ("compare", cast("str", op.argval), list_operand, None)
        if list_operand is not None and op.opname == "CONTAINS_OP" and ret.opname == "RETURN_VALUE":
            op_name = "not in" if op.arg == 1 else "in"
            return ("contains", op_name, list_operand, None)
    if len(instructions) == 6 and is_load_arg(instructions[0]):
        load_mod, binary, load_expected, compare, ret = instructions[1:]
        if (
            load_mod.opname == "LOAD_CONST"
            and binary.opname == "BINARY_OP"
            and binary.argrepr == "%"
            and load_expected.opname == "LOAD_CONST"
            and compare.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return (
                "mod_compare",
                cast("str", compare.argval),
                load_mod.argval,
                load_expected.argval,
            )
    if len(instructions) == 5 and is_load_arg(instructions[0]):
        unary, load_expected, compare, ret = instructions[1:]
        unary_name = unary_filter_operator(unary)
        if (
            unary_name is not None
            and load_expected.opname == "LOAD_CONST"
            and compare.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("unary_compare", cast("str", compare.argval), unary_name, load_expected.argval)
    if len(instructions) == 5 and is_load_arg(instructions[0]):
        load_method, load_prefix, call, ret = instructions[1:]
        if (
            load_method.opname == "LOAD_ATTR"
            and load_method.argval in {"startswith", "endswith"}
            and load_prefix.opname == "LOAD_CONST"
            and call.opname == "CALL"
            and call.arg == 1
            and ret.opname == "RETURN_VALUE"
        ):
            return (cast("str", load_method.argval), "", load_prefix.argval, None)
    if len(instructions) == 6 and is_load_global(instructions[0], abs):
        load_arg, call, load_expected, compare, ret = instructions[1:]
        if (
            is_load_arg(load_arg)
            and call.opname == "CALL"
            and call.arg == 1
            and load_expected.opname == "LOAD_CONST"
            and compare.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("abs_compare", cast("str", compare.argval), load_expected.argval, None)
    if len(instructions) == 6 and is_load_global(instructions[0], len):
        load_arg, call, load_expected, compare, ret = instructions[1:]
        if (
            is_load_arg(load_arg)
            and call.opname == "CALL"
            and call.arg == 1
            and load_expected.opname == "LOAD_CONST"
            and compare.opname == "COMPARE_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            return ("len_compare", cast("str", compare.argval), load_expected.argval, None)
    if len(instructions) == 6 and is_load_global(instructions[0], str):
        load_arg, call, load_container, contains, ret = instructions[1:]
        if (
            is_load_arg(load_arg)
            and call.opname == "CALL"
            and load_container.opname == "LOAD_CONST"
            and contains.opname == "CONTAINS_OP"
            and ret.opname == "RETURN_VALUE"
        ):
            op_name = "not in" if contains.arg == 1 else "in"
            return ("str_contains", op_name, load_container.argval, None)
    return None
