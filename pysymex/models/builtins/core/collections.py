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

"""list(), tuple(), and None builtin models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast


if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

from pysymex.typing import (
    is_list_of_objects,
    is_tuple_of_objects,
)
from pysymex.core.types.containers.sequences import SymbolicIterator
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue

from ..base import FunctionModel, ModelResult
from .helpers import resolve_heap_object, type_error_side_effect
from .iterator_items import (
    concrete_iterable_items,
    exhausted_iterator,
    iterator_mutation_side_effect,
    remaining_concrete_iterator_items,
    symbolic_truth_filter_list_from_iterator,
)


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
                side_effects=type_error_side_effect(
                    "builtins.list", "list() accepts at most one argument"
                ),
            )
        if not args:
            return ModelResult(value=SymbolicList.from_const([]))
        val = resolve_heap_object(args[0], state)
        if val is None or isinstance(val, (int, float, bool)):
            result, constraint = SymbolicList.symbolic(f"list_{state.pc}")
            return ModelResult(
                value=result,
                constraints=[constraint],
                side_effects=type_error_side_effect(
                    "builtins.list", "list() argument is not iterable"
                ),
            )
        if isinstance(val, SymbolicList):
            return ModelResult(value=val.copy())
        if isinstance(val, SymbolicIterator) and not val.is_generator:
            symbolic_filter_result = symbolic_truth_filter_list_from_iterator(
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
            iterator_values = remaining_concrete_iterator_items(val, state)
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
        direct_values = concrete_iterable_items(val, state)
        if direct_values is not None and all(
            _can_retain_list_constructor_item(item) for item in direct_values
        ):
            return ModelResult(value=SymbolicList.from_const(direct_values))
        concrete_values: list[object] = []
        all_supported = True
        if is_list_of_objects(val):
            for item in val:  # item is object from list[object]
                if _can_retain_list_constructor_item(item):
                    concrete_values.append(item)
                else:
                    all_supported = False
                    break
        elif is_tuple_of_objects(val):
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


class TupleModel(FunctionModel):
    """Model for tuple()."""

    name = "tuple"
    qualname = "builtins.tuple"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if not args:
            return ModelResult(value=())
        val = args[0]
        if isinstance(val, tuple):
            return ModelResult(value=cast("tuple[StackValue, ...]", val))
        if isinstance(val, (list, SymbolicList)):
            if isinstance(val, list):
                return ModelResult(value=tuple(cast("list[StackValue]", val)))
            result, constraint = SymbolicList.symbolic(f"tuple_{state.pc}")
            return ModelResult(value=result, constraints=[constraint])
        result, constraint = SymbolicList.symbolic(f"tuple_{state.pc}")
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
                value=SymbolicNone("none"),
                side_effects=type_error_side_effect(
                    "builtins.NoneType", "NoneType takes no arguments"
                ),
            )
        return ModelResult(value=SymbolicNone("none"))


def _can_retain_list_constructor_item(value: object) -> bool:
    if isinstance(value, tuple):
        tuple_items = cast("tuple[object, ...]", value)
        return all(_can_retain_list_constructor_item(item) for item in tuple_items)
    return isinstance(value, (SymbolicValue, int, bool, str))
