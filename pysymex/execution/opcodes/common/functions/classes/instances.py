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

"""Modeled instance-copy helpers for common function opcodes."""

from __future__ import annotations

import copy
from dataclasses import replace
from typing import TYPE_CHECKING, cast

from pysymex.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex.core.types.containers.dict_views import SymbolicDictView
from pysymex.core.types.containers.dicts import SymbolicDict
from pysymex.core.types.containers.iterator_sources import (
    EnumerateIteratorSource,
    FilterIteratorSource,
    MapIteratorSource,
    ZipIteratorSource,
)
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


def _clone_modeled_object(value: object) -> object | None:
    """Return a copy of a modeled instance when the object layer supports it."""
    try:
        from pysymex.models.objects import SymbolicInstance
    except ImportError:
        return None
    if not isinstance(value, SymbolicInstance):
        return None
    return value.copy()


def copy_symbolic_value_with_modeled_object(obj: SymbolicValue) -> SymbolicValue | None:
    """Clone a symbolic value and its attached modeled object together."""
    cloned_model = _clone_modeled_object(getattr(obj, "_modeled_object", None))
    if cloned_model is None:
        return None
    cloned_obj = copy.copy(obj)
    cloned_obj.attach_modeled_object(cloned_model)
    return cloned_obj


def modeled_instance_value(class_name: str, instance: object, pc: int) -> SymbolicValue:
    """Wrap a modeled instance in the value representation used by the VM."""
    result_val = SymbolicValue(
        _name=f"instance_{class_name}_{pc}",
        z3_int=Z3_ZERO,
        is_int=Z3_FALSE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_obj=Z3_TRUE,
        is_none=Z3_FALSE,
        is_path=Z3_FALSE,
        affinity_type=class_name,
    )
    result_val.attach_modeled_object(instance)
    return result_val


def replace_identity_references(state: VMState, old: object, new: StackValue) -> None:
    """Rewrite ``is``-aliased slots across stack, locals, globals, and call frames."""
    for address, value in tuple(state.memory.items()):
        if value is old:
            state.store_heap(address, new)
    state.stack = [new if item is old else item for item in state.stack]
    for name, value in list(state.local_vars.items()):
        if value is old:
            state.local_vars[name] = new
    for name, value in list(state.global_vars.items()):
        if value is old:
            state.global_vars[name] = new
    from pysymex.core.state.types import CallFrame
    from pysymex.core.state.types import ProtocolCallCandidate

    new_call_stack: list[CallFrame] = []
    for frame in state.call_stack:
        modified = False
        new_locals = frame.local_vars
        for name, value in list(frame.local_vars.items()):
            if value is old:
                if not modified:
                    new_locals = frame.local_vars.cow_fork()
                    modified = True
                new_locals[name] = new
        new_init_instance = frame.init_instance
        if frame.init_instance is old:
            new_init_instance = new
            modified = True
        new_retained_operand = frame.protocol_retained_operand
        if frame.protocol_retained_operand is old:
            new_retained_operand = new
            modified = True
        new_caller_stack = frame.caller_stack
        if new_caller_stack is not None and any(value is old for value in new_caller_stack):
            new_caller_stack = tuple(new if value is old else value for value in new_caller_stack)
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
                )
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
                argument_aliases=frame.argument_aliases,
                caller_offset=frame.caller_offset,
            )
            new_call_stack.append(new_frame)
        else:
            new_call_stack.append(frame)
    state.call_stack = new_call_stack


def replace_nested_modeled_instance_reference(
    state: VMState,
    old: object,
    new: StackValue,
) -> bool:
    """Replace a mutated value retained in a modeled instance attribute.

    Container methods return updated immutable symbolic container values. When
    such a container is an instance attribute, the enclosing modeled object
    must be copied and its aliases refreshed just as for direct attribute
    assignment. Mutating an attribute's contents remains permitted for frozen
    dataclasses, matching CPython.
    """
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
    for addr, obj in state.memory.items():
        if obj is old:
            state = state.store_heap(addr, new)
            replaced = True
    if replace_nested_modeled_instance_reference(state, old, new):
        replaced = True
    if any(item is old for item in state.stack):
        state.stack = [new if item is old else item for item in state.stack]
        replaced = True
    for name, value in list(state.local_vars.items()):
        if value is old:
            state = state.set_local(name, new)
            replaced = True
    for name, value in list(state.global_vars.items()):
        if value is old:
            state = state.set_global(name, new)
            replaced = True
    for frame in state.call_stack:
        for name, value in list(frame.local_vars.items()):
            if value is old:
                frame.local_vars[name] = new
                replaced = True
    state, source_references_replaced = _replace_container_source_references(state, old, new)
    if source_references_replaced:
        replaced = True
    if replaced:
        state.invalidate_cached_hash()
    return state


def propagate_list_mutation_reference(state: VMState, old: object, new: StackValue) -> VMState:
    """Propagate a modeled list update through heap, object, or direct aliases."""
    return propagate_container_mutation_reference(state, old, new)


def _replace_container_source_references(
    state: VMState,
    old: object,
    new: StackValue,
) -> tuple[VMState, bool]:
    """Retarget modeled views and iterators that source from a replaced container."""
    replaced = False
    for address, value in tuple(state.memory.items()):
        replacement = _retarget_container_source(value, old, new)
        if replacement is not None:
            state = state.store_heap(address, cast("StackValue", replacement))
            replaced = True
    new_stack = _retarget_container_sources(state.stack, old, new)
    if new_stack is not None:
        state.stack = new_stack
        replaced = True
    for name, value in list(state.local_vars.items()):
        replacement = _retarget_container_source(value, old, new)
        if replacement is not None:
            state = state.set_local(name, cast("StackValue", replacement))
            replaced = True
    for name, value in list(state.global_vars.items()):
        replacement = _retarget_container_source(value, old, new)
        if replacement is not None:
            state = state.set_global(name, cast("StackValue", replacement))
            replaced = True
    for frame in state.call_stack:
        for name, value in list(frame.local_vars.items()):
            replacement = _retarget_container_source(value, old, new)
            if replacement is not None:
                frame.local_vars[name] = cast("StackValue", replacement)
                replaced = True
    return state, replaced


def _retarget_container_sources(
    values: list[StackValue],
    old: object,
    new: StackValue,
) -> list[StackValue] | None:
    updated: list[StackValue] | None = None
    for index, value in enumerate(values):
        replacement = _retarget_container_source(value, old, new)
        if replacement is None:
            continue
        if updated is None:
            updated = list(values)
        updated[index] = cast("StackValue", replacement)
    return updated


def _retarget_container_source(value: object, old: object, new: StackValue) -> object | None:
    if isinstance(value, SymbolicIterator):
        if value.iterable is old:
            return replace(value, iterable=new)
        iterable_replacement = _retarget_iterator_source(value.iterable, old, new)
        if iterable_replacement is not None:
            return replace(value, iterable=iterable_replacement)
        if (
            isinstance(value.iterable, SymbolicDictView)
            and value.iterable.source is old
            and isinstance(new, SymbolicDict)
        ):
            return replace(value, iterable=value.iterable.with_source(new))
    if (
        isinstance(value, SymbolicDictView)
        and value.source is old
        and isinstance(new, SymbolicDict)
    ):
        return value.with_source(new)
    return None


def _retarget_iterator_source(source: object, old: object, new: StackValue) -> object | None:
    direct_replacement = _retarget_iterator_direct_source(source, old, new)
    if direct_replacement is not None:
        return direct_replacement
    if isinstance(source, EnumerateIteratorSource):
        iterable = _retarget_iterator_source(source.iterable, old, new)
        if iterable is not None:
            return source.with_iterable(iterable)
    if isinstance(source, ZipIteratorSource):
        updated_iterables: list[object] | None = None
        for index, iterable in enumerate(source.iterables):
            replacement = _retarget_iterator_source(iterable, old, new)
            if replacement is None:
                continue
            if updated_iterables is None:
                updated_iterables = list(source.iterables)
            updated_iterables[index] = replacement
        if updated_iterables is not None:
            return source.with_iterables(tuple(updated_iterables))
    if isinstance(source, MapIteratorSource):
        iterable = _retarget_iterator_source(source.iterable, old, new)
        if iterable is not None:
            return source.with_iterable(iterable)
    if isinstance(source, FilterIteratorSource):
        iterable = _retarget_iterator_source(source.iterable, old, new)
        if iterable is not None:
            return source.with_iterable(iterable)
    return None


def _retarget_iterator_direct_source(source: object, old: object, new: StackValue) -> object | None:
    if source is old:
        return new
    if isinstance(source, SymbolicIterator):
        if source.iterable is old:
            return replace(source, iterable=new)
        iterable_replacement = _retarget_iterator_source(source.iterable, old, new)
        if iterable_replacement is not None:
            return replace(source, iterable=iterable_replacement)
    if (
        isinstance(source, SymbolicDictView)
        and source.source is old
        and isinstance(new, SymbolicDict)
    ):
        return source.with_source(new)
    return None
