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

"""Lazy transformation builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.types.containers.iterator_sources import (
    FilterIteratorSource,
    MapIteratorSource,
)
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.models.builtins.common.builtin_policies import BuiltinInputPolicy
from pysymex._internal.models.builtins.iteration.predicates.evaluator import (
    supports_exact_filter_predicate,
    supports_exact_single_iterable_map,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult


def _type_error_result(name: str, message: str, state: VMState) -> ModelResult:
    result, constraint = SymbolicList.symbolic(f"{name}_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects=SideEffects.type_error(f"builtins.{name}", message),
    )


class MapModel(FunctionModel):
    """Model for map()."""

    name = "map"
    qualname = "builtins.map"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) < 2 or kwargs:
            return _type_error_result("map", "map() received invalid arguments", state)
        if any(
            BuiltinInputPolicy.iter_type_error(iterable)
            and _concrete_iterable_items(iterable, state) is None
            for iterable in args[1:]
        ):
            return _type_error_result("map", "map() argument is not iterable", state)
        if len(args) == 2 and supports_exact_single_iterable_map(args[0]):
            source = MapIteratorSource(function=args[0], iterable=args[1])
            return ModelResult(value=SymbolicIterator(f"map_{state.pc}", source))
        return ModelResult(value=SymbolicIterator(f"map_{state.pc}", object()))


class FilterModel(FunctionModel):
    """Model for filter()."""

    name = "filter"
    qualname = "builtins.filter"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return _type_error_result("filter", "filter() received invalid arguments", state)
        if (
            BuiltinInputPolicy.iter_type_error(args[1])
            and _concrete_iterable_items(args[1], state) is None
        ):
            return _type_error_result("filter", "filter() argument is not iterable", state)
        if supports_exact_filter_predicate(args[0]):
            source = FilterIteratorSource(predicate=args[0], iterable=args[1])
            return ModelResult(value=SymbolicIterator(f"filter_{state.pc}", source))
        return ModelResult(value=SymbolicIterator(f"filter_{state.pc}", object()))


def _concrete_iterable_items(value: object, state: VMState) -> list[object] | None:
    concrete_items = IterationSources.iterable_items(value, state)
    return list(concrete_items) if concrete_items is not None else None
