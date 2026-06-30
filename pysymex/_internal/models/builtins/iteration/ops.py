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

"""Shared helpers for builtin iterator models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.core.types.containers.dict_views import SymbolicDictView
from pysymex._internal.core.types.containers.dicts import SymbolicDict
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.sets import SymbolicSet
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class BuiltinIteratorOps:
    """Namespace for operations and utilities related to builtin iterators."""

    @staticmethod
    def arity_type_error(name: str, args: list[StackValue], state: VMState) -> ModelResult:
        """Return the common symbolic result for invalid builtin iterator arity."""
        result, constraint = SymbolicValue.symbolic(f"{name}_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint],
            side_effects=SideEffects.type_error(
                f"builtins.{name}",
                f"{name}() received invalid positional argument count: {len(args)}",
            ),
        )

    @staticmethod
    def definite_non_callable(value: object) -> bool:
        """Return whether *value* is definitely not callable for ``iter(callable, sentinel)``."""
        return value is None or isinstance(
            value,
            (
                int,
                float,
                bool,
                str,
                bytes,
                bytearray,
                list,
                tuple,
                dict,
                set,
                frozenset,
                SymbolicDictView,
                SymbolicSet,
                SymbolicList,
                SymbolicString,
            ),
        )

    @staticmethod
    def iterator_source_size(value: object, state: VMState) -> int | None:
        """Return a concrete source size for iterator mutation checks when known."""
        items = IterationSources.iterable_items(value, state)
        if items is None:
            return None
        return len(items)

    @staticmethod
    def iterator_size_change_raises(value: object) -> bool:
        """Return whether CPython raises when this iterator source changes size."""
        if isinstance(value, SymbolicValue) and isinstance(value.value, set):
            return True
        return isinstance(value, (dict, set, SymbolicDict, SymbolicDictView, SymbolicSet))

    @staticmethod
    def iterator_size_change_message(iterator: SymbolicIterator) -> str:
        """Return CPython's size-change message for dictionary and set iterators."""
        source = iterator.iterable
        if isinstance(source, (set, SymbolicSet)) or (
            isinstance(source, SymbolicValue) and isinstance(source.value, set)
        ):
            return "Set changed size during iteration"
        return "dictionary changed size during iteration"

    @staticmethod
    def symbolic_iterator(name: str, source: object, state: VMState) -> SymbolicIterator:
        """Create a SymbolicIterator with source-size mutation metadata."""
        return SymbolicIterator(
            name,
            source,
            source_size=BuiltinIteratorOps.iterator_source_size(source, state),
            size_change_raises=BuiltinIteratorOps.iterator_size_change_raises(source),
        )
