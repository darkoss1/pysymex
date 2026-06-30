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

"""Conservative abstract stack simulation for callable contract safety."""

from __future__ import annotations

import dis
from typing import TYPE_CHECKING, cast

from pysymex._internal.contracts.callable.introspection import (
    closure_values,
    code_instructions,
    global_value,
)
from pysymex._internal.contracts.callable.markers import (
    SafeAttributeBaseValue,
    SafeValue,
    UnknownValue,
    is_safe_expression_marker,
    loaded_value_marker,
)
from pysymex._internal.contracts.callable.policy import (
    APPROVED_CALL_TARGETS,
    HOST_FORMAT_OPCODES,
    HOST_ITERATION_OPCODES,
    HOST_MEMBERSHIP_OPCODES,
    HOST_RUNTIME_EFFECT_OPCODES,
    HOST_SUBSCRIPT_OPCODES,
    TRUTHINESS_OPCODES,
)
from pysymex._internal.core.bytecode import global_name_from_argval

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import CodeType


def reject_unapproved_calls(
    predicate: Callable[..., object],
    code: CodeType,
    *,
    safe_attribute_names: frozenset[str],
    safe_value_names: frozenset[str],
) -> None:
    """Reject call/import opcodes unless the call target is a trusted combinator."""
    stack: list[object] = []
    safe_local_names: set[str] = set(safe_value_names)
    globals_map = getattr(predicate, "__globals__", {})
    closure_map = closure_values(predicate, code)

    for instruction in code_instructions(code):
        opname = instruction.opname
        if opname in {
            "RESUME",
            "CACHE",
            "COPY_FREE_VARS",
            "EXTENDED_ARG",
            "NOP",
            "PRECALL",
            "KW_NAMES",
        }:
            continue
        if opname == "PUSH_NULL":
            stack.append(None)
            continue
        if opname == "LOAD_GLOBAL":
            push_null = "NULL" in instruction.argrepr
            if not push_null and instruction.arg is not None:
                push_null = bool(instruction.arg & 1)
            if push_null:
                stack.append(None)
            stack.append(
                loaded_value_marker(global_value(globals_map, _global_name(instruction, code))),
            )
            continue
        if opname == "LOAD_DEREF":
            stack.append(
                loaded_value_marker(closure_map.get(str(instruction.argval), UnknownValue)),
            )
            continue
        if opname == "LOAD_FAST":
            _push_fast_value(stack, str(instruction.argval), safe_attribute_names, safe_local_names)
            continue
        if opname == "LOAD_FAST_LOAD_FAST":
            argval: object = instruction.argval
            if isinstance(argval, tuple):
                for name_obj in cast("tuple[object, ...]", argval):
                    _push_fast_value(
                        stack,
                        str(name_obj),
                        safe_attribute_names,
                        safe_local_names,
                    )
            else:
                _apply_generic_stack_effect(stack, instruction)
            continue
        if opname == "STORE_FAST":
            _handle_store_fast(stack, str(instruction.argval), safe_local_names)
            continue
        if opname in {"LOAD_CONST", "LOAD_NAME"}:
            if opname == "LOAD_NAME":
                stack.append(
                    loaded_value_marker(global_value(globals_map, _global_name(instruction, code))),
                )
            else:
                stack.append(SafeValue)
            continue
        if opname in {"LOAD_ATTR", "LOAD_METHOD"}:
            _handle_load_attr(stack, instruction)
            continue
        if opname == "BINARY_OP":
            _handle_safe_binary_stack_op(stack, instruction)
            continue
        if opname == "COMPARE_OP":
            _handle_safe_binary_stack_op(stack, instruction)
            continue
        if opname in TRUTHINESS_OPCODES:
            _handle_truthiness_stack_op(stack, instruction)
            continue
        if opname in {
            "POP_JUMP_IF_FALSE",
            "POP_JUMP_IF_TRUE",
            "JUMP_IF_FALSE_OR_POP",
            "JUMP_IF_TRUE_OR_POP",
            "POP_JUMP_FORWARD_IF_FALSE",
            "POP_JUMP_FORWARD_IF_TRUE",
            "POP_JUMP_BACKWARD_IF_FALSE",
            "POP_JUMP_BACKWARD_IF_TRUE",
        }:
            if not stack:
                msg = (
                    "Callable contract predicates with host-runtime effect opcode "
                    f"{opname} are unsupported"
                )
                raise ValueError(
                    msg,
                )
            value = stack.pop()
            if not is_safe_expression_marker(value):
                msg = (
                    "Callable contract predicates with host-runtime effect opcode "
                    f"{opname} are unsupported"
                )
                raise ValueError(
                    msg,
                )
            continue
        if opname in HOST_FORMAT_OPCODES:
            msg = (
                "Callable contract predicates with host-runtime effect opcode "
                f"{opname} are unsupported"
            )
            raise ValueError(
                msg,
            )
        if opname in HOST_SUBSCRIPT_OPCODES:
            msg = (
                "Callable contract predicates with host-runtime effect opcode "
                f"{opname} are unsupported"
            )
            raise ValueError(
                msg,
            )
        if opname in HOST_ITERATION_OPCODES or opname in HOST_MEMBERSHIP_OPCODES:
            msg = (
                "Callable contract predicates with host-runtime effect opcode "
                f"{opname} are unsupported"
            )
            raise ValueError(
                msg,
            )
        if opname in HOST_RUNTIME_EFFECT_OPCODES:
            _handle_call_opcode(stack, instruction)
            continue
        if opname in {"IMPORT_NAME", "IMPORT_FROM", "IMPORT_STAR"}:
            msg = (
                "Callable contract predicates with host-runtime effect opcode "
                f"{opname} are unsupported"
            )
            raise ValueError(
                msg,
            )

        _apply_generic_stack_effect(stack, instruction)


def _global_name(instruction: dis.Instruction, code: CodeType) -> str:
    """Resolve the global/name operand for contract stack simulation."""
    argval = instruction.argval
    if isinstance(argval, str) and argval:
        return argval
    if instruction.arg is not None:
        return code.co_names[instruction.arg >> 1]
    return global_name_from_argval(argval)


def _push_fast_value(
    stack: list[object],
    name: str,
    safe_attribute_names: frozenset[str],
    safe_local_names: set[str],
) -> None:
    """Push an abstract local value, preserving safe traced parameter identity."""
    if name in safe_attribute_names:
        stack.append(SafeAttributeBaseValue)
    elif name in safe_local_names:
        stack.append(SafeValue)
    else:
        stack.append(UnknownValue)


def _handle_store_fast(stack: list[object], name: str, safe_local_names: set[str]) -> None:
    """Track local names assigned from safe symbolic/scalar expressions."""
    value = stack.pop() if stack else UnknownValue
    if is_safe_expression_marker(value):
        safe_local_names.add(name)
    else:
        safe_local_names.discard(name)


def _handle_load_attr(stack: list[object], instruction: dis.Instruction) -> None:
    """Handle attribute loads while rejecting host descriptor execution."""
    if not stack:
        msg = (
            "Callable contract predicates with host-runtime effect opcode "
            f"{instruction.opname} are unsupported"
        )
        raise ValueError(
            msg,
        )
    base = stack.pop()
    if base is not SafeAttributeBaseValue:
        msg = (
            "Callable contract predicates with host-runtime effect opcode "
            f"{instruction.opname} are unsupported"
        )
        raise ValueError(
            msg,
        )
    if "NULL" in instruction.argrepr:
        stack.append(None)
    stack.append(SafeValue)


def _handle_safe_binary_stack_op(stack: list[object], instruction: dis.Instruction) -> None:
    """Handle binary/comparison ops while rejecting host-object operands."""
    if len(stack) < 2:
        msg = (
            "Callable contract predicates with host-runtime effect opcode "
            f"{instruction.opname} are unsupported"
        )
        raise ValueError(
            msg,
        )
    right = stack.pop()
    left = stack.pop()
    if not is_safe_expression_marker(left) or not is_safe_expression_marker(right):
        msg = (
            "Callable contract predicates with host-runtime effect opcode "
            f"{instruction.opname} are unsupported"
        )
        raise ValueError(
            msg,
        )
    stack.append(SafeValue)


def _handle_truthiness_stack_op(stack: list[object], instruction: dis.Instruction) -> None:
    """Handle truthiness checks while rejecting host-object boolean protocol calls."""
    if not stack:
        msg = (
            "Callable contract predicates with host-runtime effect opcode "
            f"{instruction.opname} are unsupported"
        )
        raise ValueError(
            msg,
        )
    value = stack.pop()
    if not is_safe_expression_marker(value):
        msg = (
            "Callable contract predicates with host-runtime effect opcode "
            f"{instruction.opname} are unsupported"
        )
        raise ValueError(
            msg,
        )
    stack.append(SafeValue)


def _handle_call_opcode(stack: list[object], instruction: dis.Instruction) -> None:
    """Handle a CPython call opcode using a conservative abstract stack."""
    argument_count = int(instruction.arg or 0)
    target_index = len(stack) - argument_count - 1
    if target_index < 0:
        msg = (
            "Callable contract predicates with host-runtime effect opcode "
            f"{instruction.opname} are unsupported"
        )
        raise ValueError(
            msg,
        )

    target = stack[target_index]
    if target not in APPROVED_CALL_TARGETS:
        msg = (
            "Callable contract predicates with host-runtime effect opcode "
            f"{instruction.opname} are unsupported"
        )
        raise ValueError(
            msg,
        )

    del stack[target_index:]
    if stack and stack[-1] is None:
        stack.pop()
    stack.append(UnknownValue)


def _apply_generic_stack_effect(stack: list[object], instruction: dis.Instruction) -> None:
    """Apply a generic stack effect while discarding precise value identity."""
    try:
        if instruction.arg is None:
            effect = dis.stack_effect(instruction.opcode)
        else:
            effect = dis.stack_effect(instruction.opcode, instruction.arg)
    except ValueError:
        effect = dis.stack_effect(instruction.opcode)
    if effect < 0:
        _pop_items(stack, -effect)
        return
    stack.extend(UnknownValue for _ in range(effect))


def _pop_items(stack: list[object], count: int) -> None:
    """Pop up to ``count`` abstract stack values."""
    if count <= 0:
        return
    del stack[max(0, len(stack) - count) :]
