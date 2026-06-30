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

"""Literal operand recognition for modeled iterator predicates."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.models.builtins.iteration.predicates.bytecode import (
    is_load_arg,
    is_load_global,
)
from pysymex._internal.models.builtins.iteration.predicates.inputs import exact_constant_truth_value

if TYPE_CHECKING:
    import dis

ARG_TRUTH_BRANCH = object()


def literal_list_operand(instructions: list[dis.Instruction]) -> list[object] | None:
    if not instructions:
        return None
    build_list = instructions[-1]
    if build_list.opname != "BUILD_LIST":
        return None
    item_count = build_list.arg
    if item_count is None:
        return None
    item_instructions = instructions[:-1]
    if len(item_instructions) != item_count:
        return None
    if any(instruction.opname != "LOAD_CONST" for instruction in item_instructions):
        return None
    return [instruction.argval for instruction in item_instructions]


def literal_dict_keys_operand(instructions: list[dis.Instruction]) -> tuple[object, ...] | None:
    if not instructions:
        return None
    build_map = instructions[-1]
    if build_map.opname != "BUILD_CONST_KEY_MAP":
        return None
    item_count = build_map.arg
    if item_count is None or len(instructions) != item_count + 2:
        return None
    value_instructions = instructions[:-2]
    keys_instruction = instructions[-2]
    if any(instruction.opname != "LOAD_CONST" for instruction in value_instructions):
        return None
    keys_value: object = keys_instruction.argval
    if keys_instruction.opname != "LOAD_CONST" or not isinstance(keys_value, tuple):
        return None
    keys = cast("tuple[object, ...]", keys_value)
    return keys if len(keys) == item_count else None


def literal_range_operand(instructions: list[dis.Instruction]) -> range | None:
    if len(instructions) < 3:
        return None
    load_range = instructions[0]
    call = instructions[-1]
    if not is_load_global(load_range, range) or call.opname != "CALL":
        return None
    arg_count = call.arg
    if arg_count is None or arg_count not in {1, 2, 3}:
        return None
    arg_instructions = instructions[1:-1]
    if len(arg_instructions) != arg_count:
        return None
    args: list[int] = []
    for instruction in arg_instructions:
        if instruction.opname != "LOAD_CONST" or not isinstance(instruction.argval, int):
            return None
        args.append(instruction.argval)
    try:
        if len(args) == 1:
            return range(args[0])
        if len(args) == 2:
            return range(args[0], args[1])
        return range(args[0], args[1], args[2])
    except ValueError:
        return None


def literal_chained_compare_operand(
    instructions: list[dis.Instruction],
) -> tuple[object, str, str, object] | None:
    if len(instructions) != 15:
        return None
    (
        load_lower,
        load_arg,
        swap_before_first_compare,
        copy_before_first_compare,
        first_compare,
        copy_first_result,
        to_bool,
        jump_if_false,
        pop_middle,
        load_upper,
        second_compare,
        success_return,
        swap_cleanup,
        pop_cleanup,
        failure_return,
    ) = instructions
    if (
        load_lower.opname != "LOAD_CONST"
        or not is_load_arg(load_arg)
        or swap_before_first_compare.opname != "SWAP"
        or copy_before_first_compare.opname != "COPY"
        or first_compare.opname != "COMPARE_OP"
        or copy_first_result.opname != "COPY"
        or to_bool.opname != "TO_BOOL"
        or jump_if_false.opname != "POP_JUMP_IF_FALSE"
        or pop_middle.opname != "POP_TOP"
        or load_upper.opname != "LOAD_CONST"
        or second_compare.opname != "COMPARE_OP"
        or success_return.opname != "RETURN_VALUE"
        or swap_cleanup.opname != "SWAP"
        or pop_cleanup.opname != "POP_TOP"
        or failure_return.opname != "RETURN_VALUE"
    ):
        return None
    return (
        load_lower.argval,
        cast("str", first_compare.argval),
        cast("str", second_compare.argval),
        load_upper.argval,
    )


def literal_and_compare_mod_compare_operand(
    instructions: list[dis.Instruction],
) -> tuple[str, object, int, str, object] | None:
    if len(instructions) != 13:
        return None
    (
        first_load_arg,
        first_load_bound,
        first_compare,
        copy_first_result,
        to_bool,
        jump_if_false,
        pop_first_result,
        second_load_arg,
        load_mod,
        binary_mod,
        load_expected,
        second_compare,
        ret,
    ) = instructions
    if (
        not is_load_arg(first_load_arg)
        or first_load_bound.opname != "LOAD_CONST"
        or first_compare.opname != "COMPARE_OP"
        or copy_first_result.opname != "COPY"
        or to_bool.opname != "TO_BOOL"
        or jump_if_false.opname != "POP_JUMP_IF_FALSE"
        or pop_first_result.opname != "POP_TOP"
        or not is_load_arg(second_load_arg)
        or load_mod.opname != "LOAD_CONST"
        or binary_mod.opname != "BINARY_OP"
        or binary_mod.argrepr != "%"
        or load_expected.opname != "LOAD_CONST"
        or second_compare.opname != "COMPARE_OP"
        or ret.opname != "RETURN_VALUE"
    ):
        return None
    mod_value = load_mod.argval
    if not isinstance(mod_value, int) or isinstance(mod_value, bool) or mod_value == 0:
        return None
    return (
        cast("str", first_compare.argval),
        first_load_bound.argval,
        mod_value,
        cast("str", second_compare.argval),
        load_expected.argval,
    )


def literal_or_compare_operand(
    instructions: list[dis.Instruction],
) -> tuple[str, object, str, object] | None:
    if len(instructions) != 11:
        return None
    (
        first_load_arg,
        first_load_bound,
        first_compare,
        copy_first_result,
        to_bool,
        jump_if_true,
        pop_first_result,
        second_load_arg,
        second_load_bound,
        second_compare,
        ret,
    ) = instructions
    if (
        not is_load_arg(first_load_arg)
        or first_load_bound.opname != "LOAD_CONST"
        or first_compare.opname != "COMPARE_OP"
        or copy_first_result.opname != "COPY"
        or to_bool.opname != "TO_BOOL"
        or jump_if_true.opname != "POP_JUMP_IF_TRUE"
        or pop_first_result.opname != "POP_TOP"
        or not is_load_arg(second_load_arg)
        or second_load_bound.opname != "LOAD_CONST"
        or second_compare.opname != "COMPARE_OP"
        or ret.opname != "RETURN_VALUE"
    ):
        return None
    return (
        cast("str", first_compare.argval),
        first_load_bound.argval,
        cast("str", second_compare.argval),
        second_load_bound.argval,
    )


def literal_or_compare_mod_compare_operand(
    instructions: list[dis.Instruction],
) -> tuple[str, object, int, str, object] | None:
    if len(instructions) != 13:
        return None
    (
        first_load_arg,
        first_load_bound,
        first_compare,
        copy_first_result,
        to_bool,
        jump_if_true,
        pop_first_result,
        second_load_arg,
        load_mod,
        binary_mod,
        load_expected,
        second_compare,
        ret,
    ) = instructions
    if (
        not is_load_arg(first_load_arg)
        or first_load_bound.opname != "LOAD_CONST"
        or first_compare.opname != "COMPARE_OP"
        or copy_first_result.opname != "COPY"
        or to_bool.opname != "TO_BOOL"
        or jump_if_true.opname != "POP_JUMP_IF_TRUE"
        or pop_first_result.opname != "POP_TOP"
        or not is_load_arg(second_load_arg)
        or load_mod.opname != "LOAD_CONST"
        or binary_mod.opname != "BINARY_OP"
        or binary_mod.argrepr != "%"
        or load_expected.opname != "LOAD_CONST"
        or second_compare.opname != "COMPARE_OP"
        or ret.opname != "RETURN_VALUE"
    ):
        return None
    mod_value = load_mod.argval
    if not isinstance(mod_value, int) or isinstance(mod_value, bool) or mod_value == 0:
        return None
    return (
        cast("str", first_compare.argval),
        first_load_bound.argval,
        mod_value,
        cast("str", second_compare.argval),
        load_expected.argval,
    )


def literal_conditional_compare_truth_operand(
    instructions: list[dis.Instruction],
) -> tuple[str, object, object, object] | None:
    if len(instructions) != 8:
        return None
    (
        load_arg,
        load_bound,
        compare,
        jump_if_false,
        load_true_value,
        true_return,
        load_false_value,
        false_return,
    ) = instructions
    if (
        not is_load_arg(load_arg)
        or load_bound.opname != "LOAD_CONST"
        or compare.opname != "COMPARE_OP"
        or jump_if_false.opname != "POP_JUMP_IF_FALSE"
        or true_return.opname != "RETURN_VALUE"
        or false_return.opname != "RETURN_VALUE"
    ):
        return None
    true_truth = literal_conditional_truth_branch(load_true_value)
    false_truth = literal_conditional_truth_branch(load_false_value)
    if true_truth is None or false_truth is None:
        return None
    return (cast("str", compare.argval), load_bound.argval, true_truth, false_truth)


def literal_conditional_truth_branch(instruction: dis.Instruction) -> object | None:
    if is_load_arg(instruction):
        return ARG_TRUTH_BRANCH
    if instruction.opname != "LOAD_CONST":
        return None
    return exact_constant_truth_value(instruction.argval)
