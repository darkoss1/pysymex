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

"""Retarget iterator and view sources after container replacement."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.dict_views import SymbolicDictView
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.iterator_sources import (
    EnumerateIteratorSource,
    FilterIteratorSource,
    MapIteratorSource,
    ZipIteratorSource,
)
from pysymex._internal.core.types.containers.iterators import SymbolicIterator

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def replace_container_source_references(
    state: VMState,
    old: object,
    new: StackValue,
) -> tuple[VMState, bool]:
    """Retarget modeled views and iterators that source from a replaced container."""
    replaced = False
    with state.memory.mutate() as mem_mut:
        for address, value in tuple(state.memory.items()):
            replacement = retarget_container_source(value, old, new)
            if replacement is not None:
                mem_mut[address] = cast("StackValue", replacement)
                state.invalidate_cached_hash()
                replaced = True
    new_stack = retarget_container_sources(state.stack, old, new)
    if new_stack is not None:
        state.stack = new_stack
        replaced = True
    with state.local_vars.mutate() as loc_mut:
        for name, value in list(state.local_vars.items()):
            replacement = retarget_container_source(value, old, new)
            if replacement is not None:
                loc_mut[name] = cast("StackValue", replacement)
                state.invalidate_cached_hash()
                replaced = True
    with state.global_vars.mutate() as glob_mut:
        for name, value in list(state.global_vars.items()):
            replacement = retarget_container_source(value, old, new)
            if replacement is not None:
                glob_mut[name] = cast("StackValue", replacement)
                state.invalidate_cached_hash()
                replaced = True
    for frame in state.call_stack:
        frame_mut = None
        for name, value in list(frame.local_vars.items()):
            replacement = retarget_container_source(value, old, new)
            if replacement is not None:
                if frame_mut is None:
                    frame_mut = frame.local_vars.mutate()
                frame_mut[name] = cast("StackValue", replacement)
                replaced = True
        if frame_mut is not None:
            frame_mut.finish()
    return state, replaced


def retarget_container_sources(
    values: list[StackValue],
    old: object,
    new: StackValue,
) -> list[StackValue] | None:
    """Retarget container sources in a stack-like value list."""
    updated: list[StackValue] | None = None
    for index, value in enumerate(values):
        replacement = retarget_container_source(value, old, new)
        if replacement is None:
            continue
        if updated is None:
            updated = list(values)
        updated[index] = cast("StackValue", replacement)
    return updated


def retarget_container_source(value: object, old: object, new: StackValue) -> object | None:
    """Return a value with a direct container source changed to ``new``."""
    if isinstance(value, SymbolicIterator):
        if value.iterable is old:
            return replace(value, iterable=new)
        iterable_replacement = retarget_iterator_source(value.iterable, old, new)
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


def retarget_iterator_source(source: object, old: object, new: StackValue) -> object | None:
    """Return an iterator source with nested container references changed to ``new``."""
    direct_replacement = retarget_iterator_direct_source(source, old, new)
    if direct_replacement is not None:
        return direct_replacement
    if isinstance(source, EnumerateIteratorSource):
        iterable = retarget_iterator_source(source.iterable, old, new)
        if iterable is not None:
            return source.with_iterable(iterable)
    if isinstance(source, ZipIteratorSource):
        updated_iterables: list[object] | None = None
        for index, iterable in enumerate(source.iterables):
            replacement = retarget_iterator_source(iterable, old, new)
            if replacement is None:
                continue
            if updated_iterables is None:
                updated_iterables = list(source.iterables)
            updated_iterables[index] = replacement
        if updated_iterables is not None:
            return source.with_iterables(tuple(updated_iterables))
    if isinstance(source, MapIteratorSource):
        iterable = retarget_iterator_source(source.iterable, old, new)
        if iterable is not None:
            return source.with_iterable(iterable)
    if isinstance(source, FilterIteratorSource):
        iterable = retarget_iterator_source(source.iterable, old, new)
        if iterable is not None:
            return source.with_iterable(iterable)
    return None


def retarget_iterator_direct_source(
    source: object,
    old: object,
    new: StackValue,
) -> object | None:
    """Return an iterator source when the top-level source directly matches ``old``."""
    if source is old:
        return new
    if isinstance(source, SymbolicIterator):
        if source.iterable is old:
            return replace(source, iterable=new)
        iterable_replacement = retarget_iterator_source(source.iterable, old, new)
        if iterable_replacement is not None:
            return replace(source, iterable=iterable_replacement)
    if (
        isinstance(source, SymbolicDictView)
        and source.source is old
        and isinstance(new, SymbolicDict)
    ):
        return source.with_source(new)
    return None
