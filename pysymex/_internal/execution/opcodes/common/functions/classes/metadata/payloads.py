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

"""Reconstruct bounded MAKE_FUNCTION metadata from class-body bytecode."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.calls.payload import (
    SymbolicFunctionPayload,
    with_annotations,
    with_closure,
    with_defaults,
    with_kwdefaults,
)
from pysymex._internal.execution.opcodes.common.functions.classes.metadata.stack import (
    UNKNOWN_METADATA,
    build_tuple,
    previous_class_body_store_index,
)

if TYPE_CHECKING:
    import dis
    import types
    from collections.abc import Mapping, Sequence


def payload_from_make_function(
    instructions: Sequence[dis.Instruction],
    code: types.CodeType,
    closure_by_name: Mapping[str, object] | None,
) -> SymbolicFunctionPayload | None:
    """Reconstruct metadata attached by MAKE_FUNCTION in a bounded class-body slice."""
    make_index = _make_function_index_for_code(instructions, code)
    if make_index is None:
        return None

    boundary = previous_class_body_store_index(instructions, make_index)
    stack: list[object] = []
    for index, instr in enumerate(instructions[boundary + 1 :], start=boundary + 1):
        if instr.opname == "LOAD_CONST":
            stack.append(instr.argval)
        elif instr.opname in {
            "LOAD_FAST",
            "LOAD_FAST_CHECK",
            "LOAD_DEREF",
            "LOAD_CLOSURE",
            "LOAD_CLASSDEREF",
            "LOAD_FROM_DICT_OR_DEREF",
        }:
            stack.append(_closure_operand(instr.argval, closure_by_name))
        elif instr.opname == "LOAD_NAME":
            stack.append(UNKNOWN_METADATA)
        elif instr.opname == "BUILD_TUPLE":
            build_tuple(stack, int(instr.arg or 0))
        elif instr.opname == "MAKE_FUNCTION":
            if not stack:
                return None
            raw_code = stack.pop()
            if raw_code is not code:
                return None
            payload = SymbolicFunctionPayload(code=code)
            payload = _attach_make_function_flags(payload, stack, int(instr.arg or 0))
            stack.append(payload)
        elif instr.opname == "SET_FUNCTION_ATTRIBUTE":
            _attach_set_function_attribute(stack, int(instr.arg or 0))
        elif instr.opname in {"STORE_NAME", "STORE_GLOBAL"} or instr.opname == "CALL":
            break

        if stack and isinstance(stack[-1], SymbolicFunctionPayload):
            next_index = index + 1
            if next_index >= len(instructions):
                break
            next_op = instructions[next_index].opname
            if next_op != "SET_FUNCTION_ATTRIBUTE":
                break

    if stack and isinstance(stack[-1], SymbolicFunctionPayload):
        return stack[-1]
    return None


def payload_with_closure(
    code: types.CodeType,
    closure_by_name: Mapping[str, object] | None,
) -> types.CodeType | SymbolicFunctionPayload:
    """Attach class-body closure cells to nested method/property code when complete."""
    closure = closure_from_names(code, closure_by_name)
    if closure is None:
        return code
    return SymbolicFunctionPayload(code=code, closure=closure)


def has_call_semantic_metadata(payload: SymbolicFunctionPayload) -> bool:
    """Return whether payload metadata can affect call binding or closure resolution."""
    return bool(
        payload.defaults
        or payload.kwdefaults is not None
        or payload.closure
        or payload.contract is not None,
    )


def closure_from_names(
    code: types.CodeType,
    closure_by_name: Mapping[str, object] | None,
) -> tuple[object, ...] | None:
    """Return closure cells ordered by free variable name when all cells are known."""
    if not code.co_freevars or not closure_by_name:
        return None
    closure: list[object] = []
    for name in code.co_freevars:
        if name not in closure_by_name:
            return None
        closure.append(closure_by_name[name])
    return tuple(closure)


def _make_function_index_for_code(
    instructions: Sequence[dis.Instruction],
    code: types.CodeType,
) -> int | None:
    """Return the MAKE_FUNCTION index fed by *code*."""
    for index, instr in enumerate(instructions[:-1]):
        if instr.opname != "LOAD_CONST" or instr.argval is not code:
            continue
        for make_index in range(index + 1, len(instructions)):
            candidate = instructions[make_index]
            if candidate.opname == "MAKE_FUNCTION":
                return make_index
            if candidate.opname in {"STORE_NAME", "STORE_GLOBAL", "RETURN_VALUE", "RETURN_CONST"}:
                break
    return None


def _closure_operand(
    raw_name: object,
    closure_by_name: Mapping[str, object] | None,
) -> object:
    """Return the retained closure value for class-body closure tuple construction."""
    if not isinstance(raw_name, str) or closure_by_name is None:
        return UNKNOWN_METADATA
    return closure_by_name.get(raw_name, UNKNOWN_METADATA)


def _attach_make_function_flags(
    payload: SymbolicFunctionPayload,
    stack: list[object],
    flags: int,
) -> SymbolicFunctionPayload:
    """Return *payload* with Python 3.11-style MAKE_FUNCTION flag operands attached."""
    updated = payload
    if flags & 0x08 and stack:
        closure = stack.pop()
        if closure is not UNKNOWN_METADATA:
            updated = with_closure(updated, closure)
    if flags & 0x04 and stack:
        annotations = stack.pop()
        if annotations is not UNKNOWN_METADATA:
            updated = with_annotations(updated, annotations)
    if flags & 0x02 and stack:
        kwdefaults = stack.pop()
        if kwdefaults is not UNKNOWN_METADATA:
            updated = with_kwdefaults(updated, kwdefaults)
    if flags & 0x01 and stack:
        defaults = stack.pop()
        if defaults is not UNKNOWN_METADATA:
            updated = with_defaults(updated, defaults)
    return updated


def _attach_set_function_attribute(stack: list[object], flag: int) -> None:
    """Attach Python 3.13 SET_FUNCTION_ATTRIBUTE metadata in place."""
    if len(stack) < 2:
        return
    func_obj = stack.pop()
    attr_value = stack.pop()
    if not isinstance(func_obj, SymbolicFunctionPayload):
        stack.append(func_obj)
        return
    if attr_value is UNKNOWN_METADATA:
        stack.append(func_obj)
        return
    if flag & 0x08:
        stack.append(with_closure(func_obj, attr_value))
    elif flag & 0x04:
        stack.append(with_annotations(func_obj, attr_value))
    elif flag & 0x02:
        stack.append(with_kwdefaults(func_obj, attr_value))
    elif flag & 0x01:
        stack.append(with_defaults(func_obj, attr_value))
    else:
        stack.append(func_obj)
