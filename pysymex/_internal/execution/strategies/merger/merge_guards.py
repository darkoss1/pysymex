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
from typing import TYPE_CHECKING, Protocol, TypeGuard, runtime_checkable

import z3

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


@runtime_checkable
class ConditionalMergeable(Protocol):
    """Values that can merge with a path condition guarding the join."""

    def conditional_merge(self, other: object, condition: z3.BoolRef) -> object: ...


@runtime_checkable
class StringStackMappingLike(Protocol):
    """Protocol for string-keyed mappings containing stack values."""

    def keys(self) -> Iterable[str]:
        """Return iterable of string keys."""
        ...

    def __getitem__(self, key: str) -> StackValue:
        """Return the value associated with key."""
        ...


class MergeGuards:
    """Domain owner for merge-time symbolic carrier detection and mapping normalization."""

    @staticmethod
    def is_symbolic(value: object) -> bool:
        """Return whether ``value`` is a known symbolic carrier type."""
        from pysymex._internal.core.types.base import SymbolicNoneType
        from pysymex._internal.core.types.containers.dicts import SymbolicDict
        from pysymex._internal.core.types.containers.generators import ModeledGenerator
        from pysymex._internal.core.types.containers.lists import SymbolicList
        from pysymex._internal.core.types.containers.objects import SymbolicObject
        from pysymex._internal.core.types.scalars.strings import SymbolicString
        from pysymex._internal.core.types.scalars.values import SymbolicValue

        return isinstance(
            value,
            (
                SymbolicValue,
                SymbolicNoneType,
                SymbolicString,
                SymbolicList,
                SymbolicDict,
                SymbolicObject,
                ModeledGenerator,
            ),
        )

    @staticmethod
    def is_mergeable(value: object) -> TypeGuard[ConditionalMergeable]:
        """Return whether value exposes a callable ``conditional_merge`` method."""
        merge_fn = getattr(value, "conditional_merge", None)
        return callable(merge_fn)

    @staticmethod
    def is_stack_value(value: object) -> TypeGuard[StackValue]:
        """Validate values against the ``StackValue`` recursive union."""
        if value is None:
            return True
        if isinstance(value, (z3.ExprRef, int, bool, str, float, bytes, type)):
            return True
        if MergeGuards.is_symbolic(value):
            return True
        if isinstance(value, list):
            return True
        if isinstance(value, tuple):
            return True
        if isinstance(value, dict):
            return True
        return bool(isinstance(value, Callable))

    @staticmethod
    def as_mapping(value: object | None) -> Mapping[str, StackValue] | None:
        """Normalize ``locals``/``globals`` views to a string-keyed mapping when possible."""
        if value is None:
            return {}
        if not isinstance(value, StringStackMappingLike):
            return None
        normalized: dict[str, StackValue] = {}
        for key_obj in value.keys():
            normalized[key_obj] = value[key_obj]
        return normalized
