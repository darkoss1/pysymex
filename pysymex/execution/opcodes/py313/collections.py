# pysymex: Python Symbolic Execution & Formal Verification
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

"""Collection opcodes (lists, tuples, dicts, sets)."""

from __future__ import annotations

import dataclasses
import dis
import logging
from typing import TYPE_CHECKING, TypeGuard, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.memory.addressing import next_address
from pysymex.core.types.havoc import HavocValue
from pysymex.core.solver.engine import get_model, is_satisfiable
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types.scalars import (
    Z3_FALSE,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
)
from pysymex.core.types.containers import (
    SymbolicDict,
    SymbolicList,
    SymbolicObject,
)
from pysymex.execution.dispatcher import OpcodeResult, opcode_handler

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.memory.cow import CowDict
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher

logger = logging.getLogger(__name__)


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _is_object_tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    return isinstance(value, tuple)


def _is_object_dict(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _state_memory(state: VMState) -> CowDict[int, StackValue]:
    return state.memory


def _coerce_symbolic_value(value: StackValue) -> SymbolicValue:
    if isinstance(value, SymbolicValue):
        return value
    if hasattr(value, "type_tag"):
        return SymbolicValue.from_specialized(value)
    return SymbolicValue.from_const(value)


def _coerce_symbolic_index(value: StackValue) -> SymbolicValue | None:
    if isinstance(value, SymbolicValue):
        return value
    if isinstance(value, (int, bool)):
        return SymbolicValue.from_const(int(value))
    return None


def _coerce_symbolic_key(value: StackValue) -> SymbolicString | None:
    if isinstance(value, SymbolicString):
        return value
    if isinstance(value, str):
        return SymbolicString.from_const(value)
    if isinstance(value, SymbolicValue):
        return SymbolicString(_name=value.name, _unified=value)
    return None


def _extract_concrete_sequence(value: object) -> list[object] | tuple[object, ...] | None:
    if _is_object_list(value) or _is_object_tuple(value):
        return value
    if isinstance(value, SymbolicValue):
        enhanced = getattr(value, "_enhanced_object", None)
        if _is_object_list(enhanced) or _is_object_tuple(enhanced):
            return enhanced
        const_value = value.value
        if _is_object_list(const_value) or _is_object_tuple(const_value):
            return const_value
    concrete_items = getattr(value, "_concrete_items", None)
    if _is_object_list(concrete_items) or _is_object_tuple(concrete_items):
        return concrete_items
    return None


def _extract_concrete_mapping(value: object) -> SymbolicDict | dict[str, object] | None:
    if isinstance(value, SymbolicDict):
        return value
    if isinstance(value, SymbolicValue):
        const_value = value.value
        if _is_object_dict(const_value):
            return {str(k): v for k, v in const_value.items()}
    concrete_items = getattr(value, "_concrete_items", None)
    if _is_object_dict(concrete_items):
        return {str(k): v for k, v in concrete_items.items()}
    return None


def _resolve_runtime_container(container: StackValue, state: VMState) -> object:
    memory = _state_memory(state)
    if isinstance(container, SymbolicObject):
        return memory.get(container.address, container)

    if isinstance(container, SymbolicValue):
        enhanced = getattr(container, "_enhanced_object", None)
        if isinstance(enhanced, SymbolicObject):
            return memory.get(enhanced.address, enhanced)
        if enhanced is not None:
            return enhanced
        const_value = container.value
        if const_value is not None:
            return const_value

    return container


def _extract_none_expr(value: object) -> z3.BoolRef | None:
    if isinstance(value, SymbolicValue):
        return value.is_none
    if isinstance(value, SymbolicObject):
        return value.is_none
    return None


def _extract_length_expr(value: object) -> z3.ArithRef | None:
    if isinstance(value, (SymbolicList, SymbolicDict, SymbolicString)):
        return value.z3_len
    return None


def _symbolic_int_expr(name: str, expr: z3.ArithRef) -> SymbolicValue:
    return SymbolicValue(
        _name=name,
        z3_int=expr,
        is_int=z3.BoolVal(True),
        z3_bool=z3.BoolVal(False),
        is_bool=z3.BoolVal(False),
    )


@opcode_handler("BUILD_LIST")
def handle_build_list(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a list from stack items, preserving concrete values in Z3 Array."""
    count = int(instr.argval) if instr.argval else 0
    items: list[StackValue] = []
    for _ in range(count):
        if state.stack:
            items.insert(0, state.pop())
    sym_list, constraint = SymbolicList.symbolic(f"list_{state.pc}")
    z3_array = sym_list.z3_array
    for i, item in enumerate(items):
        if isinstance(item, SymbolicValue):
            z3_array = z3.Store(z3_array, i, item.z3_int)
        elif isinstance(item, (int, bool)):
            z3_array = z3.Store(z3_array, i, z3.IntVal(int(item)))
        elif isinstance(item, SymbolicList):
            z3_array = z3.Store(z3_array, i, z3.IntVal(next_address()))
        else:
            z3_array = z3.Store(z3_array, i, _coerce_symbolic_value(item).z3_int)

    concrete_items: list[object] = list(items)
    sym_list = dataclasses.replace(
        sym_list,
        z3_array=z3_array,
        z3_len=z3.IntVal(count),
        _concrete_items=concrete_items,
    )

    addr = next_address()
    memory = _state_memory(state)
    memory[addr] = sym_list
    obj_handle = SymbolicObject(f"list_{addr}", addr, z3.IntVal(addr), {addr})

    state = state.push(obj_handle)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_TUPLE")
def handle_build_tuple(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a tuple from stack items, preserving concrete values in Z3 Array."""
    count = int(instr.argval) if instr.argval else 0
    items: list[StackValue] = []
    for _ in range(count):
        if state.stack:
            items.insert(0, state.pop())
    sym_list, constraint = SymbolicList.symbolic(f"tuple_{state.pc}")
    z3_array = sym_list.z3_array
    for i, item in enumerate(items):
        if isinstance(item, SymbolicValue):
            z3_array = z3.Store(z3_array, i, item.z3_int)
        elif isinstance(item, (int, bool)):
            z3_array = z3.Store(z3_array, i, z3.IntVal(int(item)))
        else:
            z3_array = z3.Store(z3_array, i, _coerce_symbolic_value(item).z3_int)
    concrete_items: list[object] = list(items)
    sym_list = dataclasses.replace(
        sym_list,
        z3_array=z3_array,
        z3_len=z3.IntVal(count),
        _concrete_items=concrete_items,
    )
    state = state.push(sym_list)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_SET")
def handle_build_set(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Build a set from stack items."""
    count = int(instr.argval) if instr.argval else 0
    for _ in range(count):
        if state.stack:
            state.pop()
    sym_val, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
    state = state.push(sym_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_MAP")
def handle_build_map(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Build a dict from stack items."""
    count = int(instr.argval) if instr.argval else 0
    items: list[tuple[object, object]] = []
    for _ in range(count):
        if state.stack and len(state.stack) >= 2:
            val = state.pop()
            key = state.pop()
            items.append((key, val))
    items.reverse()
    sym_dict, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
    sym_dict = dataclasses.replace(sym_dict, _concrete_items={})
    for key, val in items:
        s_key = (
            SymbolicString.from_const(key)
            if type(key) is str
            else (key if isinstance(key, SymbolicString) else SymbolicString.from_const(str(key)))
        )
        s_val = _coerce_symbolic_value(cast("StackValue", val))
        sym_dict = sym_dict.__setitem__(s_key, s_val)
    sym_dict = dataclasses.replace(sym_dict, z3_len=z3.IntVal(count))

    state = state.push(sym_dict)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_CONST_KEY_MAP")
def handle_build_const_key_map(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a dict with constant keys, preserving key-value pairs."""
    count = int(instr.argval) if instr.argval else 0

    # Check if stack has enough elements (1 for keys_tuple + count for values)
    if len(state.stack) < 1 + count:
        # Stack is empty, use symbolic dict
        sym_dict, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
        state = state.push(sym_dict)
        state = state.add_constraint(constraint)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    keys_tuple = state.pop()

    values: list[StackValue] = []
    for _ in range(count):
        val = state.pop()
        values.append(val)
    values.reverse()

    sym_dict, constraint = SymbolicDict.symbolic(f"dict_{state.pc}")
    sym_dict = dataclasses.replace(sym_dict, _concrete_items={})

    concrete_keys: list[object] | None = None
    seq_keys = _extract_concrete_sequence(keys_tuple)
    if seq_keys is not None:
        concrete_keys = list(seq_keys)

    if concrete_keys and len(concrete_keys) == len(values):
        for key, val in zip(concrete_keys, values, strict=False):
            s_key = (
                SymbolicString.from_const(key)
                if type(key) is str
                else (
                    key if isinstance(key, SymbolicString) else SymbolicString.from_const(str(key))
                )
            )
            s_val = _coerce_symbolic_value(val)
            sym_dict = sym_dict.__setitem__(s_key, s_val)
    sym_dict = dataclasses.replace(sym_dict, z3_len=z3.IntVal(count))

    state = state.push(sym_dict)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_STRING")
def handle_build_string(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a string from stack items (f-string) with precise concatenation."""
    count = int(instr.argval) if instr.argval else 0
    items: list[object] = []
    for _ in range(count):
        if state.stack:
            items.insert(0, state.pop())

    if not items:
        state = state.push(SymbolicString.from_const(""))
        return OpcodeResult.continue_with(state.advance_pc())

    result_sym = None
    for item in items:
        if isinstance(item, SymbolicString):
            part = item
        elif isinstance(item, SymbolicValue):
            affinity = item.affinity_type

            if affinity == "int":
                z3_expr = item.z3_int
            elif affinity == "bool":
                z3_expr = z3.If(item.z3_bool, z3.IntVal(1), z3.IntVal(0))
            else:
                z3_expr = z3.If(
                    item.is_int,
                    item.z3_int,
                    z3.If(
                        item.is_bool, z3.If(item.z3_bool, z3.IntVal(1), z3.IntVal(0)), z3.IntVal(0)
                    ),
                )

            new_z3_str = z3.IntToStr(z3_expr)
            part = SymbolicString(
                _name=f"str({item.name})",
                _z3_str=new_z3_str,
                _z3_len=z3.Length(new_z3_str),
            )
        else:
            part = SymbolicString.from_const(str(item))

        if result_sym is None:
            result_sym = part
        else:
            result_sym = result_sym + part

    state = state.push(result_sym)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BUILD_SLICE")
def handle_build_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a slice object."""
    argc = int(instr.argval) if instr.argval else 2
    for _ in range(argc):
        if state.stack:
            state.pop()
    sym_val, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
    state = state.push(sym_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LIST_EXTEND")
def handle_list_extend(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Extend a list precisely, especially for constant sequences."""
    # Check if stack has at least 1 element to pop
    if not state.stack:
        # Stack is empty, skip this operation
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    val = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1
    # Check if stack has enough elements to peek
    if len(state.stack) < index:
        # Stack is empty, skip this operation
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    container = state.peek(index - 1)
    container_addr: int | None = None
    memory = _state_memory(state)
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = memory.get(container.address, container)

    if isinstance(real_container, SymbolicList):
        extend_source: SymbolicList | list[object] | tuple[object, ...] | None = None
        if isinstance(val, SymbolicList):
            extend_source = val
        else:
            seq = _extract_concrete_sequence(val)
            if seq is not None:
                extend_source = seq

        if extend_source is not None:
            new_container = real_container.extend(extend_source)
            if container_addr is not None:
                memory[container_addr] = new_container
            else:
                new_stack = list(state.stack)
                new_stack[-index] = new_container
                state = state.replace(stack=new_stack)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SET_UPDATE", "DICT_UPDATE", "DICT_MERGE")
def handle_collection_update(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Basic update for other collections."""
    val = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1
    container = state.peek(index - 1)

    if instr.opname in ("DICT_UPDATE", "DICT_MERGE") and isinstance(container, SymbolicDict):
        update_arg = _extract_concrete_mapping(val)
        if update_arg is not None:
            new_container, constraint = container.update(update_arg)
            new_stack = list(state.stack)
            new_stack[-index] = new_container
            state = state.replace(stack=new_stack)
            state = state.add_constraint(constraint)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("LIST_APPEND")
def handle_list_append(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Append to a list (used in list comprehensions)."""
    # Check if stack has at least 1 element to pop
    if not state.stack:
        # Stack is empty, skip this operation
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    val = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1
    # Check if stack has enough elements to peek
    if len(state.stack) < index:
        # Stack is empty, skip this operation
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    container = state.peek(index - 1)
    container_addr: int | None = None
    memory = _state_memory(state)
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = memory.get(container.address, container)

    if isinstance(real_container, SymbolicList):
        s_item = _coerce_symbolic_value(val)
        new_list = real_container.append(s_item)
        if container_addr is not None:
            memory[container_addr] = new_list
        else:
            new_stack = list(state.stack)
            new_stack[-index] = new_list
            state = state.replace(stack=new_stack)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("SET_ADD")
def handle_set_add(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Add to a set (used in set comprehensions)."""
    state.pop()

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("MAP_ADD")
def handle_map_add(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Add to a dict (used in dict comprehensions)."""
    # Check if stack has at least 2 elements to prevent stack underflow
    if len(state.stack) < 2:
        # Stack is empty, skip this operation
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    val = state.pop()
    key = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1
    container = state.peek(index - 1)
    if isinstance(container, SymbolicDict) and isinstance(key, SymbolicString):
        s_val = val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)
        new_dict = container.__setitem__(key, s_val)
        new_stack = list(state.stack)
        new_stack[-index] = new_dict
        state = state.replace(stack=new_stack)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_SUBSCR")
def handle_binary_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Subscript operation (obj[key])."""
    # Check if stack has at least 2 elements to prevent stack underflow
    if len(state.stack) < 2:
        # Stack is empty, use symbolic value
        sym_val, type_constraint = SymbolicValue.symbolic(f"subscr_{state.pc}")
        state = state.add_constraint(type_constraint)
        state = state.push(sym_val)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    index = state.pop()
    container = state.pop()

    if isinstance(container, HavocValue):
        ret, tc = HavocValue.havoc(
            f"{getattr(container, 'name', 'havoc')}[{state.pc}]",
        )
        state = state.push(ret)
        state = state.add_constraint(tc)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    if is_type_subscription(container):
        result, constraint = SymbolicValue.symbolic(f"generic_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    issues: list[Issue] = []
    real_container = _resolve_runtime_container(container, state)
    symbolic_index = _coerce_symbolic_index(index)

    if isinstance(real_container, SymbolicList) and symbolic_index is not None:
        state = state.add_constraint(
            z3.And(
                symbolic_index.z3_int >= -real_container.z3_len,
                symbolic_index.z3_int < real_container.z3_len,
            )
        )
        result = real_container[symbolic_index]
    elif isinstance(real_container, SymbolicString) and symbolic_index is not None:
        state = state.add_constraint(
            z3.And(
                symbolic_index.z3_int >= -real_container.z3_len,
                symbolic_index.z3_int < real_container.z3_len,
            )
        )
        real_idx = z3.If(
            symbolic_index.z3_int < 0,
            symbolic_index.z3_int + real_container.z3_len,
            symbolic_index.z3_int,
        )
        start_idx = _symbolic_int_expr(f"str_index_start_{state.pc}", real_idx)
        end_idx = _symbolic_int_expr(f"str_index_end_{state.pc}", real_idx + 1)
        result = real_container.substring(start_idx, end_idx)
    elif isinstance(real_container, SymbolicDict):
        dict_key = _coerce_symbolic_key(index)
        if dict_key is not None:
            result, presence_check = real_container[dict_key]

            state_continue = state.fork().add_constraint(presence_check)
            state_continue = state_continue.push(result)
            state_continue = state_continue.advance_pc()

            state_error = state.fork().add_constraint(z3.Not(presence_check))
            issue = Issue(
                kind=IssueKind.KEY_ERROR,
                message=f"Possible KeyError: {dict_key.name} not in {real_container.name}",
                constraints=[],
                model=None,
                pc=state.pc,
            )

            handler_pc = ctx.find_exception_handler(instr.offset)
            if handler_pc is None:
                block = state.current_block()
                if (
                    block
                    and block.block_type in ("finally", "except", "cleanup")
                    and block.handler_pc is not None
                ):
                    handler_pc = block.handler_pc

            if handler_pc is not None:
                from pysymex.core.exceptions.analyzer import SymbolicException

                exc_obj = SymbolicException.symbolic(
                    f"key_error_{state.pc}", KeyError, z3.Not(presence_check), state.pc
                )
                state_error = state_error.set_pc(handler_pc).push(exc_obj)
                return OpcodeResult(new_states=[state_continue, state_error], issues=[issue])

            return OpcodeResult(new_states=[state_continue], issues=[issue])

            state = state.add_constraint(presence_check)
            state = state.push(result)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

        result, constraint = SymbolicValue.symbolic(f"subscr_{state.pc}")
        state = state.add_constraint(constraint)
    else:
        if _is_object_dict(real_container):
            if isinstance(index, (int, str, bool, bytes)):
                try:
                    res = real_container[index]
                    res_sym = (
                        res if isinstance(res, SymbolicValue) else SymbolicValue.from_const(res)
                    )
                    state = state.push(res_sym)
                    state = state.advance_pc()
                    return OpcodeResult.continue_with(state)
                except (KeyError, IndexError, TypeError) as exc:
                    logger.debug("Concrete indexing failed: %s", exc)
        elif _is_object_list(real_container) or _is_object_tuple(real_container):
            if isinstance(index, int):
                try:
                    res = real_container[index]
                    res_sym = (
                        res if isinstance(res, SymbolicValue) else SymbolicValue.from_const(res)
                    )
                    state = state.push(res_sym)
                    state = state.advance_pc()
                    return OpcodeResult.continue_with(state)
                except (IndexError, TypeError) as exc:
                    logger.debug("Concrete indexing failed: %s", exc)
            elif isinstance(index, SymbolicValue) and z3.is_int_value(index.z3_int):
                try:
                    res = real_container[index.z3_int.as_long()]
                    res_sym = (
                        res if isinstance(res, SymbolicValue) else SymbolicValue.from_const(res)
                    )
                    state = state.push(res_sym)
                    state = state.advance_pc()
                    return OpcodeResult.continue_with(state)
                except (IndexError, TypeError, ValueError) as exc:
                    logger.debug("Concrete indexing with z3.IntVal failed: %s", exc)
        elif isinstance(real_container, (str, bytes)):
            if isinstance(index, int):
                try:
                    res = real_container[index]
                    res_sym = (
                        res if isinstance(res, SymbolicValue) else SymbolicValue.from_const(res)
                    )
                    state = state.push(res_sym)
                    state = state.advance_pc()
                    return OpcodeResult.continue_with(state)
                except (IndexError, TypeError) as exc:
                    logger.debug("Concrete indexing failed: %s", exc)
            elif isinstance(index, SymbolicValue):
                if z3.is_int_value(index.z3_int):
                    try:
                        res = real_container[index.z3_int.as_long()]
                        res_sym = (
                            res if isinstance(res, SymbolicValue) else SymbolicValue.from_const(res)
                        )
                        state = state.push(res_sym)
                        state = state.advance_pc()
                        return OpcodeResult.continue_with(state)
                    except (IndexError, TypeError, ValueError) as exc:
                        logger.debug("Concrete indexing with z3.IntVal failed: %s", exc)

        try:
            import collections.abc

            from pysymex.core.types.havoc import is_havoc

            if is_havoc(real_container):
                result, constraint = real_container[index]
                state = state.add_constraint(constraint)
            elif isinstance(
                real_container, (collections.abc.Sequence, collections.abc.Mapping, SymbolicValue)
            ):
                result, constraint = SymbolicValue.symbolic(f"subscr_{state.pc}")
                state = state.add_constraint(constraint)
            else:
                issue = Issue(
                    kind=IssueKind.TYPE_ERROR,
                    message=f"Object is not subscriptable: {type(real_container).__name__}",
                    constraints=list(state.path_constraints),
                    model=get_model(state.path_constraints),
                    pc=state.pc,
                )
                return OpcodeResult.error(issue, state)
        except ImportError:
            result, constraint = SymbolicValue.symbolic(f"subscr_{state.pc}")
            state = state.add_constraint(constraint)
    state = state.push(result)
    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_SUBSCR")
def handle_store_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store subscript (obj[key] = value) with mandatory error detection."""
    # Check if stack has at least 3 elements to prevent stack underflow
    if len(state.stack) < 3:
        # Stack is empty, skip this operation
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    key = state.pop()
    container = state.pop()
    val = state.pop()
    issues: list[Issue] = []

    memory = _state_memory(state)
    real_container: object = container
    container_addr = -1
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = memory.get(container_addr, container)

    symbolic_key = _coerce_symbolic_index(key)
    if isinstance(real_container, (SymbolicList, SymbolicString)) and symbolic_key is not None:
        state = state.add_constraint(
            z3.And(
                symbolic_key.is_int,
                symbolic_key.z3_int >= -real_container.z3_len,
                symbolic_key.z3_int < real_container.z3_len,
            )
        )

        if isinstance(real_container, SymbolicList):
            new_container = real_container.__setitem__(symbolic_key, _coerce_symbolic_value(val))
            if container_addr != -1:
                memory[container_addr] = new_container

    elif isinstance(real_container, SymbolicDict):
        dict_key = _coerce_symbolic_key(key)
        if dict_key is None:
            state = state.advance_pc()
            if issues:
                return OpcodeResult(new_states=[state], issues=issues)
            return OpcodeResult.continue_with(state)

        new_container = real_container.__setitem__(dict_key, _coerce_symbolic_value(val))
        if container_addr != -1:
            memory[container_addr] = new_container

    else:
        none_expr = _extract_none_expr(real_container)
        can_be_none = real_container is None or (
            none_expr is not None and is_satisfiable([*state.path_constraints, none_expr])
        )
        if not can_be_none:
            state = state.advance_pc()
            if issues:
                return OpcodeResult(new_states=[state], issues=issues)
            return OpcodeResult.continue_with(state)

        must_be_none = real_container is None or not is_satisfiable(
            [*state.path_constraints, z3.Not(none_expr if none_expr is not None else Z3_FALSE)]
        )
        is_unconstrained_var = (
            none_expr is not None
            and z3.is_const(none_expr)
            and none_expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
        )

        if must_be_none or not is_unconstrained_var:
            issue = Issue(
                IssueKind.NULL_DEREFERENCE,
                "Store to None object",
                list(state.path_constraints),
                get_model(state.path_constraints),
                state.pc,
            )
            if must_be_none:
                return OpcodeResult.error(issue, state)
            issues.append(issue)

        if none_expr is not None:
            state = state.add_constraint(z3.Not(none_expr))

    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("DELETE_SUBSCR")
def handle_delete_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete subscript (del obj[key]) with error detection (KeyError / IndexError)."""
    key = state.pop()
    container = state.pop()
    issues: list[Issue] = []

    if isinstance(container, SymbolicDict) and isinstance(key, SymbolicString):
        state = state.add_constraint(container.contains_key(key).z3_bool)
    elif isinstance(container, SymbolicList) and isinstance(key, SymbolicValue):
        state = state.add_constraint(
            z3.And(key.is_int, key.z3_int >= -container.z3_len, key.z3_int < container.z3_len)
        )

    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("BINARY_SLICE")
def handle_binary_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Slice operation (obj[start:stop])."""
    stop = state.pop()
    start = state.pop()
    container = state.pop()

    if not isinstance(start, SymbolicValue):
        start = SymbolicValue.from_const(start)
    if not isinstance(stop, SymbolicValue):
        stop = SymbolicValue.from_const(stop)

    if isinstance(container, SymbolicNone):
        issue = Issue(
            kind=IssueKind.TYPE_ERROR,
            message="TypeError: 'NoneType' object is not subscriptable",
            constraints=list(state.path_constraints),
            model=get_model(state.path_constraints),
            pc=state.pc,
        )
        return OpcodeResult(new_states=[], issues=[issue], terminal=True)

    if isinstance(container, SymbolicString):
        length_val = stop.z3_int - start.z3_int
        real_start = z3.If(start.z3_int < 0, start.z3_int + container.z3_len, start.z3_int)
        result = container.substring(
            SymbolicValue(
                _name=f"start_{state.pc}",
                z3_int=real_start,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
            ),
            SymbolicValue(
                _name=f"len_{state.pc}",
                z3_int=length_val,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
            ),
        )
        state = state.push(result)
    elif isinstance(container, SymbolicList):
        result_len = z3.Int(f"slice_len_{state.pc}")
        result, constraint = SymbolicList.symbolic(f"slice_{state.pc}")
        result.z3_len = result_len
        state = state.add_constraint(constraint)
        state = state.add_constraint(result_len >= 0)
        state = state.push(result)
    else:
        result, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("STORE_SLICE")
def handle_store_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store slice (obj[start:stop] = value)."""
    # Check if stack has at least 4 elements to prevent stack underflow
    if len(state.stack) < 4:
        # Stack is empty, skip this operation
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    state.pop()
    state.pop()
    state.pop()
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("UNPACK_SEQUENCE")
def handle_unpack_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unpack a sequence into individual values with length validation."""
    count = int(instr.argval) if instr.argval else 0
    container = state.pop() if state.stack else None

    issues: list[Issue] = []
    container_len = _extract_length_expr(container)
    if container_len is not None:
        state = state.add_constraint(container_len == count)
    else:
        none_expr = _extract_none_expr(container)
        can_be_none = container is None or (
            none_expr is not None and is_satisfiable([*state.path_constraints, none_expr])
        )
        if not can_be_none:
            for i in range(count):
                if isinstance(container, SymbolicList):
                    val = container[SymbolicValue.from_const(i)]
                else:
                    val, constraint = SymbolicValue.symbolic(f"unpack_{state.pc}_{i}")
                    state = state.add_constraint(constraint)
                state = state.push(val)
            state = state.advance_pc()
            if issues:
                return OpcodeResult(new_states=[state], issues=issues)
            return OpcodeResult.continue_with(state)

        must_be_none = container is None or not is_satisfiable(
            [*state.path_constraints, z3.Not(none_expr if none_expr is not None else Z3_FALSE)]
        )
        is_unconstrained_var = (
            none_expr is not None
            and z3.is_const(none_expr)
            and none_expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
        )

        if must_be_none or not is_unconstrained_var:
            issue = Issue(
                IssueKind.NULL_DEREFERENCE,
                "Unpacking None",
                list(state.path_constraints),
                get_model(state.path_constraints),
                state.pc,
            )
            if must_be_none:
                return OpcodeResult.error(issue, state)
            issues.append(issue)

        if none_expr is not None:
            state = state.add_constraint(z3.Not(none_expr))

    for i in range(count):
        if isinstance(container, SymbolicList):
            val = container[SymbolicValue.from_const(i)]
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_{state.pc}_{i}")
            state = state.add_constraint(constraint)
        state = state.push(val)

    state = state.advance_pc()
    if issues:
        return OpcodeResult(new_states=[state], issues=issues)
    return OpcodeResult.continue_with(state)


@opcode_handler("UNPACK_EX")
def handle_unpack_ex(instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher) -> OpcodeResult:
    """Unpack with starred target."""
    if state.stack:
        state.pop()
    arg = int(instr.argval) if instr.argval else 0
    before = arg & 0xFF
    after = (arg >> 8) & 0xFF
    for i in range(before + 1 + after):
        val, constraint = SymbolicValue.symbolic(f"unpack_ex_{state.pc}_{i}")
        state = state.push(val)
        state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


@opcode_handler("DICT_MERGE")
@opcode_handler("DICT_UPDATE")
def handle_dict_merge_update(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle DICT_MERGE and DICT_UPDATE (Python 3.9+)."""
    # Check if stack has at least 1 element to prevent stack underflow
    if not state.stack:
        # Stack is empty, skip this operation
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    _ = state.pop()
    dict_idx = instr.arg if instr.arg is not None else 1

    # Check if stack has enough elements to peek
    if len(state.stack) < dict_idx:
        # Stack is empty, skip this operation
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)
    _ = state.peek(dict_idx - 1)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
