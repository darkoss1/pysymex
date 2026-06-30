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

"""DICT_UPDATE and DICT_MERGE mutation opcode handlers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import TYPE_CHECKING, cast

import pysymex._internal.core.classes.mapping_protocol.extraction as mapping_protocol
from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.effects.locations import item_write_location
from pysymex._internal.core.exceptions.policy import from_native_exception
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.concrete_extraction import ConcreteExtractionPolicy
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.dispatch.result import OpcodeResult
from pysymex._internal.execution.opcodes.common.collections.fallbacks import (
    CollectionFallbackEvents,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.sets import (
    handle_common_set_update,
)
from pysymex._internal.execution.opcodes.common.collections.mutation.writes import record_item_write
from pysymex._internal.execution.opcodes.common.collections.stack_ops import CollectionStackOps
from pysymex._internal.execution.opcodes.common.exceptions.exception_flow import ExceptionFlow
from pysymex._internal.execution.opcodes.common.exceptions.type_errors import type_error_result
from pysymex._internal.execution.opcodes.common.symbolic_types import definite_symbolic_type_name

if TYPE_CHECKING:
    import dis

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def handle_common_collection_update(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Basic update for collections."""
    if instr.opname == "SET_UPDATE":
        return handle_common_set_update(instr, state, ctx)

    index = int(instr.argval) if instr.argval is not None else 1
    CollectionStackOps.require_depth(state, instr, index + 1, f"{instr.opname} value and target")
    val = state.pop()
    container = state.peek(index - 1)
    write_location = item_write_location(state, container)
    container_addr: int | None = None
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    if instr.opname in ("DICT_UPDATE", "DICT_MERGE") and isinstance(real_container, SymbolicDict):
        update_arg = ConcreteExtractionPolicy.mapping(val)
        if update_arg is not None:
            new_container, constraint = real_container.update(update_arg)
            if container_addr is not None:
                state = state.store_heap(container_addr, new_container)
            else:
                new_stack = list(state.stack)
                new_stack[-index] = new_container
                state = state.replace(stack=new_stack)
            state = state.add_constraint(constraint)
            state = record_item_write(state, write_location, instr)

    state = state.advance_pc()
    return OpcodeResult.continue_with(state)


def handle_common_dict_merge_update(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> OpcodeResult:
    """Handle DICT_MERGE and DICT_UPDATE."""
    dict_idx = instr.arg if instr.arg is not None else 1
    CollectionStackOps.require_depth(
        state,
        instr,
        dict_idx + 1,
        "DICT_UPDATE value and target container",
    )
    val = state.pop()
    container = state.peek(dict_idx - 1)
    write_location = item_write_location(state, container)
    container_addr = -1
    real_container: object = container
    if isinstance(container, SymbolicObject):
        container_addr = container.address
        real_container = state.load_heap(container.address, container)

    try:
        update_arg = ConcreteExtractionPolicy.mapping(val)
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
    fallback_events = CollectionFallbackEvents.for_degraded_passes(
        state=state,
        degraded_passes=degraded_passes,
        reason=f"modeled mapping protocol was inconclusive for {instr.opname}",
    )

    if isinstance(real_container, SymbolicDict) and update_arg is not None:
        new_container, constraint = real_container.update(update_arg)
        if container_addr != -1:
            state = state.store_heap(container_addr, new_container)
        else:
            new_stack = list(state.stack)
            new_stack[-dict_idx] = new_container
            state = state.replace(stack=new_stack)
        state = state.add_constraint(constraint)
        state = record_item_write(state, write_location, instr)

    state = state.advance_pc()
    return OpcodeResult.continue_with(
        state,
        degraded_passes=degraded_passes,
        fallback_events=fallback_events,
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
            modeled_type_name = _definite_non_mapping_symbolic_type(raw_value)
            if modeled_type_name is not None:
                return _dict_merge_update_type_error_message(
                    instr,
                    state,
                    dict_idx,
                    modeled_type_name,
                )
            return None
        if _is_mapping_payload(raw_value):
            return None
        modeled_type_name = _dict_merge_update_type_name(raw_value)

    return _dict_merge_update_type_error_message(instr, state, dict_idx, modeled_type_name)


def _dict_merge_update_type_error_message(
    instr: dis.Instruction,
    state: VMState,
    dict_idx: int,
    modeled_type_name: str,
) -> str:
    """Return the opcode-specific CPython mapping-unpack TypeError message."""
    if instr.opname == "DICT_MERGE":
        return (
            f"{_dict_merge_callable_name(state, dict_idx)}() argument after ** "
            f"must be a mapping, not {modeled_type_name}"
        )
    return f"'{modeled_type_name}' object is not a mapping"


def _definite_non_mapping_symbolic_type(value: SymbolicValue) -> str | None:
    """Return a type name when a symbolic value is definitely invalid as a mapping."""
    type_name = definite_symbolic_type_name(value)
    if type_name in {"NoneType", "bool", "bytes", "float", "int", "list", "str", "tuple"}:
        return type_name
    return None


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
        mapping_value = cast("Mapping[object, object]", value)
        return any(not isinstance(key, str) for key in mapping_value)
    return False


def _dict_merge_update_exception_result(
    instr: dis.Instruction,
    state: VMState,
    ctx: OpcodeDispatcher,
    kind: IssueKind,
    exc: Exception,
) -> OpcodeResult:
    """Route a concrete mapping-unpack exception or emit a deterministic issue."""
    modeled_exc = from_native_exception(exc, state=state, instr=instr)
    handler_state = ExceptionFlow.jump_to_handler(state, ctx, instr.offset, modeled_exc)
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
    if value is None or isinstance(value, SymbolicNoneType):
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
