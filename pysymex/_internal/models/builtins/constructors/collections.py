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

"""list() and None builtin models."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.models.contracts.results import SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.iterators import SymbolicIterator
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.guards import RuntimeObjectGuards
from pysymex._internal.models.builtins.iteration.consumption import (
    exhausted_iterator,
    iterator_mutation_side_effect,
)
from pysymex._internal.models.builtins.iteration.sources import IterationSources
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult


class ListModel(FunctionModel):
    """Model for list()."""

    name = "list"
    qualname = "builtins.list"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) > 1 or kwargs:
            result, constraint = SymbolicValue.symbolic(f"list_invalid_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.list",
                    "list() accepts at most one argument",
                ),
            )
        if not args:
            return ModelResult(value=SymbolicList.from_const([]))
        val = SymbolicObject.resolve(args[0], state)
        if val is None or isinstance(val, (int, float, bool)):
            result, constraint = SymbolicList.symbolic(f"list_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=SideEffects.type_error(
                    "builtins.list",
                    "list() argument is not iterable",
                ),
            )
        if isinstance(val, SymbolicList):
            return ModelResult(value=dataclasses.replace(val.copy(), _type=None))
        if isinstance(val, SymbolicIterator) and not val.is_generator:
            symbolic_filter_result = IterationSources.truth_filter_list(
                val,
                state,
                f"list_{state.pc}",
            )
            if symbolic_filter_result is not None:
                filtered_list, updated_iterator = symbolic_filter_result
                return ModelResult(
                    value=filtered_list,
                    side_effects=iterator_mutation_side_effect(val, updated_iterator),
                )
            iterator_values = IterationSources.remaining_iterator_items(val, state)
            updated_iterator = exhausted_iterator(val, state)
            if (
                iterator_values is not None
                and updated_iterator is not None
                and all(_can_retain_list_constructor_item(item) for item in iterator_values)
            ):
                return ModelResult(
                    value=SymbolicList.from_const(iterator_values),
                    side_effects=iterator_mutation_side_effect(val, updated_iterator),
                )
        direct_values = IterationSources.iterable_items(val, state)
        if direct_values is not None and all(
            _can_retain_list_constructor_item(item) for item in direct_values
        ):
            return ModelResult(value=SymbolicList.from_const(direct_values))
        concrete_values: list[object] = []
        all_supported = True
        if RuntimeObjectGuards.list(val):
            for item in val:  # item is object from list[object]
                if _can_retain_list_constructor_item(item):
                    concrete_values.append(item)
                else:
                    all_supported = False
                    break
        elif RuntimeObjectGuards.tuple(val):
            for item in val:  # item is object from tuple[object, ...]
                if _can_retain_list_constructor_item(item):
                    concrete_values.append(item)
                else:
                    all_supported = False
                    break
        else:
            all_supported = False
        if all_supported:
            return ModelResult(value=SymbolicList.from_const(concrete_values))
        result, constraint = SymbolicList.symbolic(f"list_{state.pc}")
        return ModelResult(value=result, constraints=[constraint])


class NoneModel(FunctionModel):
    """Model for NoneType/None."""

    name = "NoneType"
    qualname = "builtins.NoneType"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if args or kwargs:
            return ModelResult(
                value=SymbolicNoneType("none"),
                side_effects=SideEffects.type_error(
                    "builtins.NoneType",
                    "NoneType takes no arguments",
                ),
            )
        return ModelResult(value=SymbolicNoneType("none"))


def _can_retain_list_constructor_item(value: object) -> bool:
    if isinstance(value, tuple):
        tuple_items = cast("tuple[object, ...]", value)
        return all(_can_retain_list_constructor_item(item) for item in tuple_items)
    return isinstance(value, (SymbolicValue, int, bool, str))
