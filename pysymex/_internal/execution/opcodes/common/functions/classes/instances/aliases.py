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

"""Alias propagation for copied modeled instances and updated containers."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.opcodes.common.functions.classes.instances.sources import (
    replace_container_source_references,
)
from pysymex._internal.execution.opcodes.common.functions.classes.instances.values import (
    copy_symbolic_value_with_modeled_object,
)

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def replace_identity_references(state: VMState, old: object, new: StackValue) -> None:
    """Rewrite ``is``-aliased slots across stack, locals, globals, and call frames."""
    with state.memory.mutate() as mem_mut:
        for address, value in tuple(state.memory.items()):
            replacement, replaced = _replace_nested_stack_identity(value, old, new)
            if replaced:
                mem_mut[address] = replacement
                state.invalidate_cached_hash()
    state.stack = [
        replacement
        for item in state.stack
        for replacement, _replaced in [_replace_nested_stack_identity(item, old, new)]
    ]
    with state.local_vars.mutate() as loc_mut:
        for name, value in list(state.local_vars.items()):
            replacement, replaced = _replace_nested_stack_identity(value, old, new)
            if replaced:
                loc_mut[name] = replacement
    with state.global_vars.mutate() as glob_mut:
        for name, value in list(state.global_vars.items()):
            replacement, replaced = _replace_nested_stack_identity(value, old, new)
            if replaced:
                glob_mut[name] = replacement
    from pysymex._internal.core.state.types import CallFrame, ProtocolCallCandidate

    new_call_stack: list[CallFrame] = []
    for frame in state.call_stack:
        modified = False
        new_locals = frame.local_vars
        new_locals_mut = None
        for name, value in list(frame.local_vars.items()):
            replacement, replaced = _replace_nested_stack_identity(value, old, new)
            if replaced:
                if not modified:
                    new_locals = frame.local_vars.cow_fork()
                    new_locals_mut = new_locals.mutate()
                    modified = True
                if new_locals_mut is not None:
                    new_locals_mut[name] = replacement
        if new_locals_mut is not None:
            new_locals_mut.finish()
        new_init_instance = frame.init_instance
        if frame.init_instance is old:
            new_init_instance = new
            modified = True
        new_retained_operand = frame.protocol_retained_operand
        if frame.protocol_retained_operand is old:
            new_retained_operand = new
            modified = True
        new_caller_stack = frame.caller_stack
        if new_caller_stack is not None:
            updated_caller_stack: list[StackValue] | None = None
            for index, value in enumerate(new_caller_stack):
                replacement, replaced = _replace_nested_stack_identity(value, old, new)
                if not replaced:
                    continue
                if updated_caller_stack is None:
                    updated_caller_stack = list(new_caller_stack)
                updated_caller_stack[index] = replacement
            if updated_caller_stack is not None:
                new_caller_stack = tuple(updated_caller_stack)
                modified = True
        new_fallbacks: list[ProtocolCallCandidate] = []
        fallbacks_modified = False
        for candidate in frame.protocol_fallbacks:
            owner = new if candidate.owner is old else candidate.owner
            argument = new if candidate.argument is old else candidate.argument
            fallbacks_modified = fallbacks_modified or (
                owner is not candidate.owner or argument is not candidate.argument
            )
            new_fallbacks.append(
                ProtocolCallCandidate(
                    owner=owner,
                    method_name=candidate.method_name,
                    argument=argument,
                ),
            )
        if fallbacks_modified:
            modified = True

        if modified:
            new_frame = CallFrame(
                function_name=frame.function_name,
                return_pc=frame.return_pc,
                local_vars=new_locals,
                stack_depth=frame.stack_depth,
                caller_stack=new_caller_stack,
                caller_instructions=frame.caller_instructions,
                summary_builder=frame.summary_builder,
                is_init_call=frame.is_init_call,
                init_instance=new_init_instance,
                protocol_method=frame.protocol_method,
                protocol_retained_operand=new_retained_operand,
                protocol_fallbacks=tuple(new_fallbacks),
                has_contract_frame=frame.has_contract_frame,
                argument_aliases=frame.argument_aliases,
                caller_offset=frame.caller_offset,
                write_event_start_index=frame.write_event_start_index,
            )
            new_call_stack.append(new_frame)
        else:
            new_call_stack.append(frame)
    state.call_stack = new_call_stack


def _replace_nested_stack_identity(
    value: StackValue,
    old: object,
    new: StackValue,
) -> tuple[StackValue, bool]:
    """Return *value* with nested stack-value identity references replaced."""
    if value is old:
        return new, True
    if isinstance(value, SymbolicList) and value.concrete_items is not None:
        concrete_items = value.concrete_items
        updated_items: list[object] | None = None
        for index, item in enumerate(concrete_items):
            replacement, replaced = _replace_nested_stack_identity(
                cast("StackValue", item),
                old,
                new,
            )
            if not replaced:
                continue
            if updated_items is None:
                updated_items = list(concrete_items)
            updated_items[index] = replacement
        if updated_items is not None:
            updated_symbolic_list = dataclasses.replace(value, _concrete_items=updated_items)
            return updated_symbolic_list, True
    if isinstance(value, tuple):
        tuple_items = cast("tuple[StackValue, ...]", value)
        updated: list[StackValue] | None = None
        for index, item in enumerate(tuple_items):
            replacement, replaced = _replace_nested_stack_identity(item, old, new)
            if not replaced:
                continue
            if updated is None:
                updated = list(tuple_items)
            updated[index] = replacement
        if updated is not None:
            return cast("StackValue", tuple(updated)), True
    if isinstance(value, list):
        list_items = cast("list[StackValue]", value)
        updated_list: list[StackValue] | None = None
        for index, item in enumerate(list_items):
            replacement, replaced = _replace_nested_stack_identity(item, old, new)
            if not replaced:
                continue
            if updated_list is None:
                updated_list = list(list_items)
            updated_list[index] = replacement
        if updated_list is not None:
            return cast("StackValue", updated_list), True
    if isinstance(value, dict):
        dict_items = cast("dict[str, StackValue]", value)
        updated_dict: dict[str, StackValue] | None = None
        for key, item in dict_items.items():
            replacement, replaced = _replace_nested_stack_identity(item, old, new)
            if not replaced:
                continue
            if updated_dict is None:
                updated_dict = dict(dict_items)
            updated_dict[key] = replacement
        if updated_dict is not None:
            return cast("StackValue", updated_dict), True
    return cast("StackValue", value), False


def retarget_nested_modeled_instance(
    state: VMState,
    old: object,
    new: StackValue,
) -> bool:
    """Replace a mutated value retained in a modeled instance attribute."""
    candidates: list[object] = [
        *state.stack,
        *state.local_vars.values(),
        *state.global_vars.values(),
    ]
    for frame in state.call_stack:
        candidates.extend(frame.local_vars.values())

    replaced = False
    seen: set[int] = set()
    for candidate in candidates:
        if not isinstance(candidate, SymbolicValue) or id(candidate) in seen:
            continue
        seen.add(id(candidate))
        modeled = getattr(candidate, "_modeled_object", None)
        raw_attrs = getattr(modeled, "attrs", None)
        if not isinstance(raw_attrs, dict):
            continue
        attrs = cast("dict[str, object]", raw_attrs)
        attribute_names = [name for name, value in attrs.items() if value is old]
        if not attribute_names:
            continue
        cloned = copy_symbolic_value_with_modeled_object(candidate)
        if cloned is None:
            continue
        cloned_modeled = getattr(cloned, "_modeled_object", None)
        raw_cloned_attrs = getattr(cloned_modeled, "attrs", None)
        if not isinstance(raw_cloned_attrs, dict):
            continue
        cloned_attrs = cast("dict[str, object]", raw_cloned_attrs)
        for name in attribute_names:
            cloned_attrs[name] = new
        replace_identity_references(state, candidate, cloned)
        replaced = True
    return replaced


def propagate_container_mutation_reference(state: VMState, old: object, new: StackValue) -> VMState:
    """Propagate a modeled container update through all identity aliases."""
    replaced = False
    with state.memory.mutate() as mem_mut:
        for addr, obj in state.memory.items():
            if obj is old:
                mem_mut[addr] = new
                replaced = True
    if retarget_nested_modeled_instance(state, old, new):
        replaced = True
    if any(item is old for item in state.stack):
        state.stack = [new if item is old else item for item in state.stack]
        replaced = True
    with state.local_vars.mutate() as loc_mut:
        for name, value in list(state.local_vars.items()):
            if value is old:
                loc_mut[name] = new
                replaced = True
    with state.global_vars.mutate() as glob_mut:
        for name, value in list(state.global_vars.items()):
            if value is old:
                glob_mut[name] = new
                replaced = True
    for frame in state.call_stack:
        frame_mut = None
        for name, value in list(frame.local_vars.items()):
            if value is old:
                if frame_mut is None:
                    frame_mut = frame.local_vars.mutate()
                frame_mut[name] = new
                replaced = True
        if frame_mut is not None:
            frame_mut.finish()
    state, source_references_replaced = replace_container_source_references(state, old, new)
    if source_references_replaced:
        replaced = True
    if replaced:
        state.invalidate_cached_hash()
    return state


def propagate_list_mutation_reference(state: VMState, old: object, new: StackValue) -> VMState:
    """Propagate a modeled list update through heap, object, or direct aliases."""
    return propagate_container_mutation_reference(state, old, new)
