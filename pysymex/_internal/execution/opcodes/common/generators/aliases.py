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

"""Alias replacement for modeled generator state transitions."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.generators import ModeledGenerator

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


def latest_generator_alias(state: VMState, generator: ModeledGenerator) -> ModeledGenerator:
    """Return the most progressed same-identity generator visible in *state*."""
    best = generator
    for value in _state_values(state):
        candidate = _find_generator_alias(value, generator)
        if candidate is not None and _generator_progress_key(candidate) > _generator_progress_key(
            best,
        ):
            best = candidate
    return best


def replace_generator_aliases(
    state: VMState,
    old: ModeledGenerator,
    new: ModeledGenerator,
) -> None:
    """Replace *old* generator references in locals, globals, and the stack."""
    for name, value in tuple(state.local_vars.items()):
        state = state.set_local(str(name), cast("StackValue", _replace_value(value, old, new)))
    for name, value in tuple(state.global_vars.items()):
        state = state.set_global(str(name), cast("StackValue", _replace_value(value, old, new)))
    state.stack = [cast("StackValue", _replace_value(value, old, new)) for value in state.stack]
    state.invalidate_cached_hash()


def _state_values(state: VMState) -> tuple[object, ...]:
    """Return root values that may retain generator aliases."""
    values: list[object] = [
        *state.local_vars.values(),
        *state.global_vars.values(),
        *state.stack,
        *state.memory.values(),
    ]
    for frame in state.call_stack:
        values.extend(frame.local_vars.values())
        if frame.caller_stack is not None:
            values.extend(frame.caller_stack)
        if frame.init_instance is not None:
            values.append(frame.init_instance)
        if frame.protocol_retained_operand is not None:
            values.append(frame.protocol_retained_operand)
        for fallback in frame.protocol_fallbacks:
            values.append(fallback.owner)
            values.append(fallback.argument)
    return tuple(values)


def _generator_progress_key(generator: ModeledGenerator) -> tuple[int, int, int]:
    """Rank generator aliases by progress so stale concrete handles lose."""
    return (
        int(generator.closed),
        int(generator.started),
        -1 if generator.resume_pc is None else generator.resume_pc,
    )


def _find_generator_alias(value: object, target: ModeledGenerator) -> ModeledGenerator | None:
    """Return a same-identity generator nested in *value*, if present."""
    if isinstance(value, ModeledGenerator):
        return value if value.identity == target.identity else None
    from pysymex._internal.core.types.containers.iterators import SymbolicIterator

    if isinstance(value, SymbolicIterator):
        return _find_generator_alias(value.iterable, target)
    from pysymex._internal.core.types.scalars.values import SymbolicValue

    if isinstance(value, SymbolicValue):
        modeled_object = getattr(value, "_modeled_object", None)
        raw_attrs = getattr(modeled_object, "attrs", None)
        if isinstance(raw_attrs, dict):
            for attr_value in cast("dict[str, object]", raw_attrs).values():
                candidate = _find_generator_alias(attr_value, target)
                if candidate is not None:
                    return candidate
    from pysymex._internal.core.classes.types import SymbolicMethod

    if isinstance(value, SymbolicMethod) and value.bound_to is not None:
        return _find_generator_alias(value.bound_to, target)
    if isinstance(value, list):
        for item in cast("list[object]", value):
            candidate = _find_generator_alias(item, target)
            if candidate is not None:
                return candidate
    if isinstance(value, tuple):
        for item in cast("tuple[object, ...]", value):
            candidate = _find_generator_alias(item, target)
            if candidate is not None:
                return candidate
    if isinstance(value, dict):
        for item in cast("dict[object, object]", value).values():
            candidate = _find_generator_alias(item, target)
            if candidate is not None:
                return candidate
    return None


def _replace_value(value: object, old: ModeledGenerator, new: ModeledGenerator) -> object:
    """Recursively substitute *new* for *old* inside nested container values."""
    _replace_context_manager_generator(value, old, new)
    if value is old:
        return new
    if isinstance(value, ModeledGenerator) and value.identity == old.identity:
        return new
    from pysymex._internal.core.types.scalars.values import SymbolicValue
    from pysymex._internal.execution.opcodes.common.functions.classes.instances.values import (
        copy_symbolic_value_with_modeled_object,
    )

    if isinstance(value, SymbolicValue):
        cloned = copy_symbolic_value_with_modeled_object(value)
        if cloned is not None:
            modeled_object = getattr(cloned, "_modeled_object", None)
            raw_attrs = getattr(modeled_object, "attrs", None)
            if isinstance(raw_attrs, dict):
                changed = False
                attrs = cast("dict[str, object]", raw_attrs)
                for attr_name, attr_value in tuple(attrs.items()):
                    replacement = _replace_value(attr_value, old, new)
                    if replacement is not attr_value:
                        attrs[attr_name] = replacement
                        changed = True
                if changed:
                    return cloned
    from pysymex._internal.core.classes.types import SymbolicMethod

    if isinstance(value, SymbolicMethod):
        bound_to = value.bound_to
        if bound_to is not None:
            replacement = _replace_value(bound_to, old, new)
            if replacement is not bound_to:
                return dataclasses.replace(value, bound_to=replacement)
    from pysymex._internal.core.types.containers.iterators import SymbolicIterator

    if isinstance(value, SymbolicIterator) and value.iterable is old:
        return dataclasses.replace(value, iterable=new)
    if isinstance(value, list):
        items = cast("list[object]", value)
        return [_replace_value(item, old, new) for item in items]
    if isinstance(value, tuple):
        items = cast("tuple[object, ...]", value)
        return tuple(_replace_value(item, old, new) for item in items)
    if isinstance(value, dict):
        items = cast("dict[object, object]", value)
        return {key: _replace_value(item, old, new) for key, item in items.items()}
    return value


def _replace_context_manager_generator(
    value: object,
    old: ModeledGenerator,
    new: ModeledGenerator,
) -> None:
    """Update modeled ``contextlib.contextmanager`` receivers retained by bound methods."""
    from pysymex._internal.models.stdlib.contextlib.managers import ContextManager

    candidates = (
        value,
        getattr(value, "__self__", None),
        getattr(value, "_modeled_object", None),
        getattr(value, "value", None),
    )
    for candidate in candidates:
        if isinstance(candidate, ContextManager):
            candidate.replace_modeled_generator(old, new)
