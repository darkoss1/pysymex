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

"""LIST_*, DICT_*, SET_*, and MAP_* mutation opcode handlers.

Updates modeled :class:`~pysymex.core.types.containers.lists.SymbolicList` and
:class:`~pysymex.core.types.containers.dicts.SymbolicDict` storage in place or via heap aliases.
``SET_ADD`` is currently a stack pop stub; other handlers skip unsupported
operands without inventing container state.
"""

from __future__ import annotations

from collections.abc import Hashable, Mapping
import dis
from typing import TYPE_CHECKING, cast

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.core.exceptions.objects import SymbolicException
from pysymex.core.effects.events import WriteEvent, WriteKind
from pysymex.core.effects.locations import WriteLocation, item_write_location
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.containers.objects import SymbolicObject
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.strings import SymbolicString
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.execution.dispatch.result import OpcodeResult
from pysymex.execution.opcodes.common.collections.helpers import (
    coerce_symbolic_value,
    extract_concrete_mapping,
    extract_concrete_sequence,
    require_stack_depth,
)
from pysymex.execution.opcodes.common.collections import mapping_protocol
from pysymex.execution.opcodes.common.collections.fallbacks import collection_fallback_events
from pysymex.execution.opcodes.common.exceptions.helpers import jump_to_exception_handler
from pysymex.execution.opcodes.common.exceptions.type_errors import type_error_result

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.dispatch.dispatcher import OpcodeDispatcher


def handle_common_list_extend(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``LIST_EXTEND``: append another iterable to a modeled list when precise.

    CPython stack effect: pops the iterable operand; mutates ``SymbolicList`` storage
    or heap alias when elements are concrete. Skips unsupported operands silently.
    """
    index = int(instr.argval) if instr.argval is not None else 1
    require_stack_depth(state, instr, index + 1, "LIST_EXTEND value and target container")
    val = state.pop()
    container = state.peek(index - 1)
    write_location = item_write_location(state, container)
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
            seq = extract_concrete_sequence(val)
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
            state = _record_item_write(state, write_location, instr)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_collection_update(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Basic update for collections."""
    val = state.pop()
    index = int(instr.argval) if instr.argval is not None else 1
    container = state.peek(index - 1)
    write_location = item_write_location(state, container)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if instr.opname in ("DICT_UPDATE", "DICT_MERGE") and isinstance(real_container, SymbolicDict):
        update_arg = extract_concrete_mapping(val)
        if update_arg is not None:
            new_container, constraint = real_container.update(update_arg)
            if container_addr is not None:
                state = state.store_heap(container_addr, new_container)
            else:
                new_stack = list(state.stack)
                new_stack[-index] = new_container
                state = state.replace(stack=new_stack)
            state = state.add_constraint(constraint)
            state = _record_item_write(state, write_location, instr)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_list_append(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``LIST_APPEND``: push one value onto a modeled or concrete list tail.

    CPython stack effect: pops the value operand; updates list storage in place when
    the container is a tracked ``SymbolicList`` or heap object.
    """
    index = int(instr.argval) if instr.argval is not None else 1
    require_stack_depth(state, instr, index + 1, "LIST_APPEND value and target container")
    val = state.pop()

    container = state.peek(index - 1)
    write_location = item_write_location(state, container)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if isinstance(real_container, SymbolicList):
        s_item = coerce_symbolic_value(val)
        new_list = real_container.append(s_item)
        if container_addr is not None:
            state = state.store_heap(container_addr, new_list)
        else:
            new_stack = list(state.stack)
            new_stack[-index] = new_list
            state = state.replace(stack=new_stack)
        state = _record_item_write(state, write_location, instr)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_set_add(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``SET_ADD`` (currently pops the value operand without set mutation).

    Limitations:
        Set membership and hashing are not modeled; no container state is updated.
    """
    state.pop()
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_map_add(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Execute ``MAP_ADD``: associate a stack key with a value on a modeled dict.

    CPython stack effect: pops key then value; updates ``SymbolicDict`` when the
    container under the key slot is tracked.
    """
    index = int(instr.argval) if instr.argval is not None else 1
    require_stack_depth(state, instr, index + 2, "MAP_ADD key/value and target container")
    val = state.pop()
    key = state.pop()

    container = state.peek(index - 1)
    write_location = item_write_location(state, container)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if isinstance(real_container, SymbolicDict):
        if not _is_supported_map_add_key(key):
            state = state.advance_pc()
            return OpcodeResult.continue_with(state)
        new_dict = real_container.__setitem__(key, coerce_symbolic_value(val))
        if container_addr is not None:
            state = state.store_heap(container_addr, new_dict)
        else:
            new_stack = list(state.stack)
            new_stack[-index] = new_dict
            state = state.replace(stack=new_stack)
        state = _record_item_write(state, write_location, instr)
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def _is_supported_map_add_key(key: object) -> bool:
    """Return whether ``MAP_ADD`` can retain this key without executing hashing hooks."""
    if isinstance(key, (SymbolicString, SymbolicValue)):
        return True
    if isinstance(key, (SymbolicNone, SymbolicDict, SymbolicList, SymbolicObject)):
        return False
    return isinstance(key, Hashable)


def handle_common_dict_merge_update(
    instr: dis.Instruction, state: VMState, ctx: OpcodeDispatcher
) -> OpcodeResult:
    """Handle DICT_MERGE and DICT_UPDATE."""
    dict_idx = instr.arg if instr.arg is not None else 1
    require_stack_depth(state, instr, dict_idx + 1, "DICT_UPDATE value and target container")
    val = state.pop()
    container = state.peek(dict_idx - 1)
    write_location = item_write_location(state, container)
    container_addr = -1
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    try:
        update_arg = extract_concrete_mapping(val)
    except TypeError as exc:
        return type_error_result(state, ctx, instr.offset, str(exc))
    except KeyError as exc:
        return _dict_merge_update_exception_result(instr, state, ctx, IssueKind.KEY_ERROR, exc)

    type_error_message = _dict_merge_update_type_error(instr, state, val, dict_idx, update_arg)
    if type_error_message is not None:
        return type_error_result(state, ctx, instr.offset, type_error_message)
    degraded_passes = (
        [mapping_protocol.UNSUPPORTED_MAPPING_PROTOCOL]
        if update_arg is None and mapping_protocol.modeled_mapping_protocol_is_inconclusive(val)
        else []
    )
    fallback_events = collection_fallback_events(
        state=state,
        degraded_passes=degraded_passes,
        reason=f"modeled mapping protocol was inconclusive for {instr.opname}",
    )

    if isinstance(real_container, SymbolicDict):
        if update_arg is not None:
            new_container, constraint = real_container.update(update_arg)
            if container_addr != -1:
                state = state.store_heap(container_addr, new_container)
            else:
                new_stack = list(state.stack)
                new_stack[-dict_idx] = new_container
                state = state.replace(stack=new_stack)
            state = state.add_constraint(constraint)
            state = _record_item_write(state, write_location, instr)

    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=degraded_passes,
        fallback_events=fallback_events,
    )


def _record_item_write(state: VMState, location: WriteLocation, instr: dis.Instruction) -> VMState:
    """Record a successful modeled collection mutation."""
    return state.record_write_event(
        WriteEvent(WriteKind.ITEM, location.name, state.pc, location.precise, instr.opname)
    )


def _dict_merge_update_type_error(
    instr: dis.Instruction,
    state: VMState,
    value: object,
    dict_idx: int,
    update_arg: SymbolicDict | Mapping[object, object] | None,
) -> str | None:
    """Return a CPython mapping-unpack TypeError for definite invalid operands."""
    if update_arg is not None:
        if instr.opname == "DICT_MERGE" and _has_non_string_key(update_arg):
            return "keywords must be strings"
        return None
    modeled_type_name = mapping_protocol.definite_modeled_non_mapping_type_name(value)
    if modeled_type_name is None:
        raw_value = _dict_merge_update_payload(value)
        if isinstance(raw_value, SymbolicValue):
            return None
        if _is_mapping_payload(raw_value):
            return None
        modeled_type_name = _dict_merge_update_type_name(raw_value)

    if instr.opname == "DICT_MERGE":
        return (
            f"{_dict_merge_callable_name(state, dict_idx)}() argument after ** "
            f"must be a mapping, not {modeled_type_name}"
        )
    return f"'{modeled_type_name}' object is not a mapping"


def _dict_merge_update_payload(value: object) -> object:
    """Return a concrete mapping-update payload when a stack carrier has one."""
    if isinstance(value, SymbolicValue) and value.value is not None:
        return value.value
    concrete_items = getattr(value, "_concrete_items", None)
    if concrete_items is not None:
        return concrete_items
    return value


def _is_mapping_payload(value: object) -> bool:
    """Return whether *value* is definitely a mapping payload."""
    return isinstance(value, (SymbolicDict, Mapping))


def _has_non_string_key(value: object) -> bool:
    """Return whether a mapping payload contains a key CPython rejects for kwargs."""
    if isinstance(value, SymbolicDict):
        concrete_items = value.concrete_items
        return concrete_items is not None and any(
            not isinstance(key, str) for key in concrete_items
        )
    if isinstance(value, Mapping):
        mapping = cast("Mapping[object, object]", value)
        return any(not isinstance(key, str) for key in mapping)
    return False


def _dict_merge_update_exception_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    kind: IssueKind,
    exc: Exception,
) -> OpcodeResult:
    """Route a concrete mapping-unpack exception or emit a deterministic issue."""
    modeled_exc = SymbolicException.concrete(type(exc), str(exc), raised_at=state.pc)
    handler_state = jump_to_exception_handler(state, ctx, instr.offset, modeled_exc)
    if handler_state is not None:
        return OpcodeResult.continue_with(handler_state)

    issue = Issue(
        kind=kind,
        message=f"Possible {type(exc).__name__}: {exc}",
        constraints=list(state.path_constraints),
        pc=state.pc,
    )
    return OpcodeResult.error(issue)


def _dict_merge_update_type_name(value: object) -> str:
    """Return a CPython-style type name for mapping-unpack diagnostics."""
    if value is None or isinstance(value, SymbolicNone):
        return "NoneType"
    return type(value).__name__


def _dict_merge_callable_name(state: VMState, dict_idx: int) -> str:
    """Best-effort callable name for ``DICT_MERGE`` call-kwargs diagnostics."""
    candidate_index = len(state.stack) - dict_idx - 3
    if candidate_index < 0 or candidate_index >= len(state.stack):
        return "function"
    candidate = state.stack[candidate_index]
    qualname = getattr(candidate, "__qualname__", None)
    if isinstance(qualname, str) and qualname:
        return qualname
    name = getattr(candidate, "__name__", None)
    if isinstance(name, str) and name:
        return name
    return "function"
