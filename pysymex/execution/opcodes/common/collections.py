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

"""Common collection opcodes (lists, tuples, dicts, sets)."""

from __future__ import annotations

from collections.abc import Sequence, Sized
import dis
import logging
from typing import TYPE_CHECKING, TypeGuard, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.state import VMStateError
from pysymex.core.types.havoc import HavocValue
from pysymex.core.solver.constraints import quick_contradiction_check
from pysymex.core.solver.engine import is_satisfiable
from pysymex.core.types.checks import is_type_subscription
from pysymex.core.types.scalars import (
    Z3_FALSE,
    SymbolicNone,
    SymbolicString,
    SymbolicValue,
    fresh_name,
)
from pysymex.core.types import (
    SymbolicDict,
    SymbolicList,
    SymbolicObject,
)
from pysymex.execution.dispatcher import OpcodeResult
from pysymex.execution.opcodes.common.lowering import CollectionLowerer

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState
    from pysymex.execution.dispatcher import OpcodeDispatcher

logger = logging.getLogger(__name__)


def _require_stack_depth(
    state: VMState,
    instr: dis.Instruction,
    required_depth: int,
    purpose: str,
) -> None:
    if len(state.stack) < required_depth:
        raise VMStateError(
            f"{instr.opname} at pc {state.pc}: stack depth {len(state.stack)} "
            f"cannot satisfy {required_depth} item(s) for {purpose}"
        )


def _path_is_sat(constraints: list[z3.BoolRef]) -> bool:
    """Check path satisfiability with a cheap fallback on deep paths."""
    if len(constraints) < 12:
        return is_satisfiable(constraints)
    return not quick_contradiction_check(constraints)


def _is_object_list(value: object) -> TypeGuard[list[object]]:
    return isinstance(value, list)


def _is_object_tuple(value: object) -> TypeGuard[tuple[object, ...]]:
    return isinstance(value, tuple)


def _is_object_dict(value: object) -> TypeGuard[dict[object, object]]:
    return isinstance(value, dict)


def _add_lowered_constraints(state: VMState, constraints: list[z3.BoolRef]) -> VMState:
    for constraint in constraints:
        state = state.add_constraint(constraint)
    return state


def _apply_heap_updates(state: VMState, updates: list[tuple[int, StackValue]]) -> VMState:
    """Apply a sequence of heap updates while maintaining VMState hash invariants."""
    for address, value in updates:
        state = state.store_heap(address, value)
    return state


def _branch_or_terminate_exception(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    exception_condition: z3.BoolRef,
) -> OpcodeResult:
    handler_pc = ctx.find_exception_handler(instr.offset)
    if handler_pc is None:
        return OpcodeResult.terminate()
    error_state = state.fork().add_constraint(exception_condition)
    return OpcodeResult.continue_with(error_state.set_pc(handler_pc))


def _as_stack_value(value: object) -> StackValue:
    if value is None:
        return None
    if isinstance(
        value,
        (
            SymbolicValue,
            SymbolicNone,
            SymbolicString,
            SymbolicList,
            SymbolicDict,
            SymbolicObject,
            int,
            bool,
            str,
            float,
            bytes,
            type,
            list,
            dict,
            tuple,
        ),
    ):
        return cast("StackValue", value)
    return SymbolicValue.from_const(value)


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
    if _is_object_dict(value):
        return {str(k): v for k, v in value.items()}
    if isinstance(value, SymbolicValue):
        const_value = value.value
        if _is_object_dict(const_value):
            return {str(k): v for k, v in const_value.items()}
    concrete_items = getattr(value, "_concrete_items", None)
    if _is_object_dict(concrete_items):
        return {str(k): v for k, v in concrete_items.items()}
    return None


def _resolve_runtime_container(container: StackValue, state: VMState) -> object:
    if isinstance(container, SymbolicObject):
        return state.load_heap(container.address, container)

    if isinstance(container, SymbolicValue):
        enhanced = getattr(container, "_enhanced_object", None)
        if isinstance(enhanced, SymbolicObject):
            return state.load_heap(enhanced.address, enhanced)
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
    if isinstance(value, SymbolicValue):
        if value.affinity_type in {"list", "dict"}:
            return value.z3_int
        if value.affinity_type == "str":
            return z3.Length(value.z3_str)
        if z3.is_true(z3.simplify(value.is_list)) or z3.is_true(z3.simplify(value.is_dict)):
            return value.z3_int
        if z3.is_true(z3.simplify(value.is_str)):
            return z3.Length(value.z3_str)
    return None


def _resolve_heap_container(state: VMState, value: StackValue) -> StackValue:
    if isinstance(value, SymbolicObject) and value.address != -1:
        resolved = state.memory.get(value.address)
        if resolved is not None:
            return _as_stack_value(resolved)
    return value


def _known_sequence_length(value: object) -> int | None:
    if isinstance(value, SymbolicList) and z3.is_int_value(value.z3_len):
        return value.z3_len.as_long()
    if isinstance(value, (list, tuple, str, bytes, bytearray, range)):
        return len(cast(Sized, value))
    return None


def _unpack_value_at(container: StackValue, index: int) -> StackValue:
    if isinstance(container, SymbolicList):
        concrete_items = container.concrete_items
        if concrete_items is not None and 0 <= index < len(concrete_items):
            return _as_stack_value(concrete_items[index])
        return container[index]

    if isinstance(container, (list, tuple, str, bytes, bytearray, range)):
        return _as_stack_value(cast(Sequence[object], container)[index])

    val, _constraint = SymbolicValue.symbolic(f"unpack_item_{index}")
    return val


def _unpack_arity_error(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    *,
    expected: int,
    actual: int,
) -> OpcodeResult:
    handler_pc = ctx.find_exception_handler(instr.offset)
    if handler_pc is not None:
        return OpcodeResult.continue_with(state.set_pc(handler_pc))

    relation = "not enough" if actual < expected else "too many"
    if actual < expected:
        message = f"{relation} values to unpack (expected {expected}, got {actual})"
    else:
        message = f"{relation} values to unpack (expected {expected})"
    issue = Issue(
        kind=IssueKind.VALUE_ERROR,
        message=f"Possible ValueError: {message}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def handle_common_build_list(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a list from stack items."""
    count = int(instr.argval) if instr.argval else 0
    _require_stack_depth(state, instr, count, "BUILD_LIST elements")
    items: list[StackValue] = []
    for _ in range(count):
        items.insert(0, state.pop())

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_list(items)

    for address, value in lowered.heap_updates:
        state = state.store_heap(address, value)
    state = state.store_heap(lowered.handle.address, lowered.storage)

    state = state.push(lowered.handle)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_tuple(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a tuple from stack items."""
    count = int(instr.argval) if instr.argval else 0
    _require_stack_depth(state, instr, count, "BUILD_TUPLE elements")
    items: list[StackValue] = []
    for _ in range(count):
        items.insert(0, state.pop())

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_tuple(items)

    state = _add_lowered_constraints(state, lowered.constraints)
    state = _apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_set(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a set from stack items."""
    count = int(instr.argval) if instr.argval else 0
    _require_stack_depth(state, instr, count, "BUILD_SET elements")
    items: list[StackValue] = []
    for _ in range(count):
        items.insert(0, state.pop())

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_set(items)

    if _path_is_sat([*state.path_constraints.to_list(), lowered.exception_condition]):
        return _branch_or_terminate_exception(instr, state, ctx, lowered.exception_condition)

    state = _add_lowered_constraints(state, lowered.constraints)
    state = _apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_map(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a dict from stack items."""
    count = int(instr.argval) if instr.argval else 0
    _require_stack_depth(state, instr, count * 2, "BUILD_MAP key/value pairs")
    items: list[tuple[StackValue, StackValue]] = []
    for _ in range(count):
        val = state.pop()
        key = state.pop()
        items.append((key, val))
    items.reverse()

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_map(items)

    state = _add_lowered_constraints(state, lowered.constraints)
    state = _apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_const_key_map(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a dict with constant keys."""
    count = int(instr.argval) if instr.argval else 0
    _require_stack_depth(state, instr, 1 + count, "BUILD_CONST_KEY_MAP values and keys")

    keys_tuple = state.pop()
    values: list[StackValue] = []
    for _ in range(count):
        val = state.pop()
        values.append(val)
    values.reverse()

    concrete_keys: list[StackValue] = []
    seq_keys = _extract_concrete_sequence(keys_tuple)
    if seq_keys is not None:
        concrete_keys = [_as_stack_value(item) for item in seq_keys]

    items: list[tuple[StackValue, StackValue]] = []
    if len(concrete_keys) == len(values):
        items = list(zip(concrete_keys, values, strict=False))

    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.build_map(items, expected_count=count)

    state = _add_lowered_constraints(state, lowered.constraints)
    state = _apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_string(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a string from stack items."""
    count = int(instr.argval) if instr.argval else 0
    _require_stack_depth(state, instr, count, "BUILD_STRING parts")
    items: list[StackValue] = []
    for _ in range(count):
        items.insert(0, state.pop())

    lowerer = CollectionLowerer(state.pc)
    result_sym = lowerer.build_string(items)

    state = state.push(result_sym)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_build_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Build a slice object."""
    argc = int(instr.argval) if instr.argval else 2
    _require_stack_depth(state, instr, argc, "BUILD_SLICE arguments")
    for _ in range(argc):
        state.pop()
    sym_val, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
    state = state.push(sym_val)
    state = state.add_constraint(constraint)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_list_extend(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Extend a list precisely."""
    index = int(instr.argval) if instr.argval is not None else 1
    _require_stack_depth(state, instr, index + 1, "LIST_EXTEND value and target container")
    val = state.pop()
    container = state.peek(index - 1)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

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
                state = state.store_heap(container_addr, new_container)
            else:
                new_stack = list(state.stack)
                new_stack[-index] = new_container
                state = state.replace(stack=new_stack)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_collection_update(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Basic update for collections."""
    val = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1
    container = state.peek(index - 1)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if instr.opname in ("DICT_UPDATE", "DICT_MERGE") and isinstance(real_container, SymbolicDict):
        update_arg = _extract_concrete_mapping(val)
        if update_arg is not None:
            new_container, constraint = real_container.update(update_arg)
            if container_addr is not None:
                state = state.store_heap(container_addr, new_container)
            else:
                new_stack = list(state.stack)
                new_stack[-index] = new_container
                state = state.replace(stack=new_stack)
            state = state.add_constraint(constraint)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_list_append(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Append to a list."""
    index = int(instr.argval) if instr.argval is not None else 1
    _require_stack_depth(state, instr, index + 1, "LIST_APPEND value and target container")
    val = state.pop()

    container = state.peek(index - 1)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if isinstance(real_container, SymbolicList):
        s_item = _coerce_symbolic_value(val)
        new_list = real_container.append(s_item)
        if container_addr is not None:
            state = state.store_heap(container_addr, new_list)
        else:
            new_stack = list(state.stack)
            new_stack[-index] = new_list
            state = state.replace(stack=new_stack)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_set_add(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Add to a set."""
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_map_add(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Add to a dict."""
    index = int(instr.argval) if instr.argval is not None else 1
    _require_stack_depth(state, instr, index + 2, "MAP_ADD key/value and target container")
    val = state.pop()
    key = state.pop()

    container = state.peek(index - 1)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if isinstance(real_container, SymbolicDict):
        s_key = _coerce_symbolic_key(key)
        if s_key is None:
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
        s_val = val if isinstance(val, SymbolicValue) else SymbolicValue.from_const(val)
        new_dict = real_container.__setitem__(s_key, s_val)
        if container_addr is not None:
            state = state.store_heap(container_addr, new_dict)
        else:
            new_stack = list(state.stack)
            new_stack[-index] = new_dict
            state = state.replace(stack=new_stack)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_binary_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Subscript operation (obj[key])."""
    _require_stack_depth(state, instr, 2, "BINARY_SUBSCR container and index")
    index = state.pop()
    container = state.pop()

    if isinstance(container, HavocValue):
        ret, tc = HavocValue.havoc(f"{getattr(container, 'name', 'havoc')}[{state.pc}]")
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

    real_container = _resolve_runtime_container(container, state)
    lowerer = CollectionLowerer(state.pc)
    lowered = lowerer.lower_subscript(real_container, index)

    path_constraints = state.path_constraints.to_list()
    exc_cond = lowered.exception_condition

    if _path_is_sat([*path_constraints, exc_cond]):
        not_exc = z3.Not(exc_cond)
        if _path_is_sat([*path_constraints, not_exc]):
            handler_pc = ctx.find_exception_handler(instr.offset)
            success_state = state.fork().add_constraint(not_exc)
            success_state = _add_lowered_constraints(success_state, lowered.constraints)
            success_state = _apply_heap_updates(success_state, lowered.heap_updates)
            success_state = success_state.push(lowered.value)
            success_state = success_state.advance_pc()
            if handler_pc is None:
                return OpcodeResult.continue_with(success_state)
            error_state = state.fork().add_constraint(exc_cond).set_pc(handler_pc)
            return OpcodeResult.branch([success_state, error_state])

        return _branch_or_terminate_exception(instr, state, ctx, exc_cond)

    state = _add_lowered_constraints(state, lowered.constraints)
    state = _apply_heap_updates(state, lowered.heap_updates)
    state = state.push(lowered.value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_store_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store subscript."""
    _require_stack_depth(state, instr, 3, "STORE_SUBSCR value, container, and key")
    key = state.pop()
    container = state.pop()
    val = state.pop()
    real_container: object = container
    container_addr = -1
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container_addr, container)

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
                state = state.store_heap(container_addr, new_container)

    elif isinstance(real_container, SymbolicDict):
        dict_key = _coerce_symbolic_key(key)
        if dict_key is None:
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

        new_container = real_container.__setitem__(dict_key, _coerce_symbolic_value(val))
        if container_addr != -1:
            state = state.store_heap(container_addr, new_container)

    else:
        none_expr = _extract_none_expr(real_container)
        can_be_none = real_container is None or (
            none_expr is not None and _path_is_sat([*state.path_constraints, none_expr])
        )
        if not can_be_none:
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

        must_be_none = real_container is None or not _path_is_sat(
            [*state.path_constraints, z3.Not(none_expr if none_expr is not None else Z3_FALSE)]
        )
        is_unconstrained_var = (
            none_expr is not None
            and z3.is_const(none_expr)
            and none_expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
        )

        if must_be_none or not is_unconstrained_var:
            if must_be_none:
                state = state.advance_pc()
                return OpcodeResult.continue_with(state)

        if none_expr is not None:
            state = state.add_constraint(z3.Not(none_expr))

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_delete_subscr(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Delete subscript."""
    _require_stack_depth(state, instr, 2, "DELETE_SUBSCR container and key")
    key = state.pop()
    container = state.pop()
    real_container = container
    container_addr = -1
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container_addr, container)

    if isinstance(real_container, SymbolicDict):
        dict_key = _coerce_symbolic_key(key)
        if dict_key is not None:
            state = state.add_constraint(real_container.contains_key(dict_key).z3_bool)
            new_container = real_container.__delitem__(dict_key)
            if container_addr != -1:
                state = state.store_heap(container_addr, new_container)
    elif isinstance(real_container, SymbolicList):
        symbolic_key = _coerce_symbolic_index(key)
        if symbolic_key is not None:
            state = state.add_constraint(
                z3.And(
                    symbolic_key.is_int,
                    symbolic_key.z3_int >= -real_container.z3_len,
                    symbolic_key.z3_int < real_container.z3_len,
                )
            )
            new_container = real_container.__delitem__(symbolic_key)
            if container_addr != -1:
                state = state.store_heap(container_addr, new_container)
    elif isinstance(real_container, list) and isinstance(key, int):
        real_list = cast("list[object]", real_container)
        if -len(real_list) <= key < len(real_list):
            del real_list[key]

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_binary_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Slice operation."""
    _require_stack_depth(state, instr, 3, "BINARY_SLICE container, start, and stop")
    stop = state.pop()
    start = state.pop()
    container = state.pop()

    if not isinstance(start, SymbolicValue):
        start = SymbolicValue.from_const(start)
    if not isinstance(stop, SymbolicValue):
        stop = SymbolicValue.from_const(stop)

    if isinstance(container, SymbolicNone):
        result, constraint = SymbolicValue.symbolic(f"slice_{state.pc}")
        state = state.add_constraint(constraint)
        state = state.push(result)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

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


def handle_common_store_slice(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Store slice."""
    _require_stack_depth(state, instr, 4, "STORE_SLICE container, start, stop, and value")
    state.pop()
    state.pop()
    state.pop()
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_unpack_sequence(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unpack a sequence."""
    count = int(instr.argval) if instr.argval else 0
    _require_stack_depth(state, instr, 1, "UNPACK_SEQUENCE source")
    container = _resolve_heap_container(state, state.pop())

    known_len = _known_sequence_length(container)
    if known_len is not None:
        if known_len != count:
            return _unpack_arity_error(
                instr,
                state,
                ctx,
                expected=count,
                actual=known_len,
            )
        for i in reversed(range(count)):
            state = state.push(_unpack_value_at(container, i))
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    container_len = _extract_length_expr(container)
    if container_len is not None:
        state = state.add_constraint(container_len == count)
    else:
        none_expr = _extract_none_expr(container)
        can_be_none = container is None or (
            none_expr is not None and _path_is_sat([*state.path_constraints, none_expr])
        )
        if not can_be_none:
            for i in reversed(range(count)):
                if isinstance(container, SymbolicList):
                    val = container[SymbolicValue.from_const(i)]
                else:
                    val, constraint = SymbolicValue.symbolic(f"unpack_{state.pc}_{i}")
                    state = state.add_constraint(constraint)
                state = state.push(val)
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)

        must_be_none = container is None or not _path_is_sat(
            [*state.path_constraints, z3.Not(none_expr if none_expr is not None else Z3_FALSE)]
        )
        is_unconstrained_var = (
            none_expr is not None
            and z3.is_const(none_expr)
            and none_expr.decl().kind() == z3.Z3_OP_UNINTERPRETED
        )

        if must_be_none or not is_unconstrained_var:
            if must_be_none:
                state = state.advance_pc()
                return OpcodeResult.continue_with(state)

        if none_expr is not None:
            state = state.add_constraint(z3.Not(none_expr))

    for i in reversed(range(count)):
        if isinstance(container, SymbolicList):
            val = container[SymbolicValue.from_const(i)]
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_{state.pc}_{i}")
            state = state.add_constraint(constraint)
        state = state.push(val)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_unpack_ex(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Unpack with starred target."""
    _require_stack_depth(state, instr, 1, "UNPACK_EX source")
    container = _resolve_heap_container(state, state.pop())
    arg = int(instr.argval) if instr.argval else 0
    before = arg & 0xFF
    after = (arg >> 8) & 0xFF

    sequence = _extract_concrete_sequence(container)
    if sequence is not None:
        actual = len(sequence)
        required = before + after
        if actual < required:
            return _unpack_arity_error(instr, state, ctx, expected=required, actual=actual)

        output_values: list[StackValue] = []
        output_values.extend(_as_stack_value(item) for item in sequence[:before])
        star_stop = actual - after if after else actual
        output_values.append([_as_stack_value(item) for item in sequence[before:star_stop]])
        if after:
            output_values.extend(_as_stack_value(item) for item in sequence[-after:])

        for value in reversed(output_values):
            state = state.push(value)
        state = state.advance_pc()
        return OpcodeResult.continue_with(state)

    output_values: list[StackValue] = []
    for i in range(before):
        if isinstance(container, SymbolicList):
            val = container[SymbolicValue.from_const(i)]
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_ex_{state.pc}_before_{i}")
            state = state.add_constraint(constraint)
        output_values.append(val)
    if isinstance(container, SymbolicList):
        required = z3.IntVal(before + after)
        star_idx = z3.Int(fresh_name("unpack_ex_star_idx"))
        star_array = cast(
            "z3.ArrayRef",
            z3.Lambda(
                [star_idx],
                z3.Select(container.z3_array, star_idx + z3.IntVal(before)),
            ),
        )
        star = SymbolicList(
            _name=f"unpack_ex_{state.pc}_star",
            z3_array=star_array,
            z3_len=container.z3_len - required,
            element_type=container.element_type,
        )
        state = state.add_constraint(container.z3_len >= required)
        state = state.add_constraint(star.z3_len >= 0)
    else:
        star, star_constraint = SymbolicList.symbolic(f"unpack_ex_{state.pc}_star")
        state = state.add_constraint(star_constraint)
        container_len = _extract_length_expr(container)
        if container_len is not None:
            required = z3.IntVal(before + after)
            star.z3_len = container_len - required
            state = state.add_constraint(container_len >= required)
            state = state.add_constraint(star.z3_len >= 0)
    output_values.append(star)
    for i in range(after):
        if isinstance(container, SymbolicList):
            item_index = container.z3_len - z3.IntVal(after - i)
            val = SymbolicValue(
                _name=f"unpack_ex_{state.pc}_after_{i}",
                z3_int=cast("z3.ArithRef", z3.Select(container.z3_array, item_index)),
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
                is_str=Z3_FALSE,
                is_obj=Z3_FALSE,
                is_list=Z3_FALSE,
                is_dict=Z3_FALSE,
                is_path=Z3_FALSE,
                is_none=Z3_FALSE,
            )
        else:
            val, constraint = SymbolicValue.symbolic(f"unpack_ex_{state.pc}_after_{i}")
            state = state.add_constraint(constraint)
        output_values.append(val)
    for value in reversed(output_values):
        state = state.push(value)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_dict_merge_update(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle DICT_MERGE and DICT_UPDATE."""
    dict_idx = instr.arg if instr.arg is not None else 1
    _require_stack_depth(state, instr, dict_idx + 1, "DICT_UPDATE value and target container")
    val = state.pop()
    container = state.peek(dict_idx - 1)
    container_addr = -1
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if isinstance(real_container, SymbolicDict):
        update_arg = _extract_concrete_mapping(val)
        if update_arg is not None:
            new_container, constraint = real_container.update(update_arg)
            if container_addr != -1:
                state = state.store_heap(container_addr, new_container)
            else:
                new_stack = list(state.stack)
                new_stack[-dict_idx] = new_container
                state = state.replace(stack=new_stack)
            state = state.add_constraint(constraint)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
