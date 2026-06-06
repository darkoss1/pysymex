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

"""Protocols and guards for mergeable symbolic stack values.

Detects values exposing ``conditional_merge`` or structural hash helpers used
when joining symbolic locals and globals.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable, Mapping
from typing import Protocol, TypeGuard, runtime_checkable

import z3

from pysymex.typing import StackValue


@runtime_checkable
class ConditionalMergeable(Protocol):
    """Values that can merge with a path condition guarding the join."""

    def conditional_merge(self, other: object, condition: z3.BoolRef) -> object: ...


@runtime_checkable
class HashableValue(Protocol):
    """Values exposing a structural hash used for pending-state bucketing."""

    def hash_value(self) -> int: ...


@runtime_checkable
class StringStackMappingLike(Protocol):
    """Protocol for string-keyed mappings containing stack values."""

    def keys(self) -> Iterable[str]:
        """Return iterable of string keys."""
        ...

    def __getitem__(self, key: str) -> StackValue:
        """Return the value associated with key."""
        ...


def is_any_symbolic(value: object) -> bool:
    """Return whether ``value`` is a known symbolic carrier type."""
    from pysymex.core.types.containers.dicts import SymbolicDict
    from pysymex.core.types.containers.lists import SymbolicList
    from pysymex.core.types.containers.objects import SymbolicObject
    from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
    from pysymex.core.types.scalars.strings import SymbolicString
    from pysymex.core.types.scalars.values import SymbolicValue

    return isinstance(
        value,
        (SymbolicValue, SymbolicNone, SymbolicString, SymbolicList, SymbolicDict, SymbolicObject),
    )


def is_conditional_mergeable(value: object) -> TypeGuard[ConditionalMergeable]:
    """Return whether value exposes a callable ``conditional_merge`` method."""
    merge_fn = getattr(value, "conditional_merge", None)
    return callable(merge_fn)


def is_stack_value(value: object) -> TypeGuard[StackValue]:
    """Validate values against the ``StackValue`` recursive union."""
    if value is None:
        return True
    if isinstance(value, (z3.ExprRef, int, bool, str, float, bytes, type)):
        return True
    if is_any_symbolic(value):
        return True
    if isinstance(value, list):
        return True
    if isinstance(value, tuple):
        return True
    if isinstance(value, dict):
        return True
    if isinstance(value, Callable):
        return True
    return False


def as_string_object_mapping(value: object | None) -> Mapping[str, StackValue] | None:
    """Normalize ``locals``/``globals`` views to a string-keyed mapping when possible."""
    if value is None:
        return {}
    if not isinstance(value, StringStackMappingLike):
        return None
    normalized: dict[str, StackValue] = {}
    for key_obj in value.keys():
        normalized[key_obj] = value[key_obj]
    return normalized
