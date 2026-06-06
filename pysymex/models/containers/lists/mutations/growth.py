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

from __future__ import annotations

from typing import TYPE_CHECKING

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicList,
    SymbolicNone,
    SymbolicValue,
    get_symbolic_list,
    list_type_error_result,
    z3,
)
from pysymex.models.builtins.core.helpers import resolve_heap_object
from pysymex.models.builtins.core.iterator_items import (
    concrete_iterable_items,
    iterator_exhaustion_side_effect,
)
from pysymex.models.containers.sequence_precision import (
    concatenate_concrete_backed_sequences,
    exact_concrete_items,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Length-increasing symbolic list method models."""


class ListAppendModel(FunctionModel):
    """Model for list.append(x) - increases list length by 1.
    Relationship: After append, len(list) == old_len + 1
    Side effect: Updates the list's symbolic length constraint.
    """

    name = "append"
    qualname = "list.append"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return list_type_error_result("append", state)
        lst = get_symbolic_list(args[0], state) if args else None
        element = args[1] if len(args) > 1 else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = lst.append(
                element if isinstance(element, SymbolicValue) else SymbolicValue.from_const(element)
            )
            side_effects["list_mutation"] = {
                "operation": "append",
                "original_list": lst,
                "updated_list": new_list,
            }
        else:
            from pysymex.logger import get_logger

            get_logger("pysymex").debug(
                "ListAppendModel failed to find list in %s", args[0] if args else "None"
            )
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class ListExtendModel(FunctionModel):
    """Model for list.extend(iterable) - increases length by len(iterable).
    Relationship: len(list) >= old_len (extends by >= 0 elements)
    """

    name = "extend"
    qualname = "list.extend"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return list_type_error_result("extend", state)
        lst = get_symbolic_list(args[0], state) if args else None
        extension = get_symbolic_list(args[1], state) if len(args) > 1 else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if lst is not None:
            if extension is not None:
                new_list = concatenate_concrete_backed_sequences(lst, extension)
                if new_list is None:
                    new_len = z3.Int(f"extend_len_{state.pc}_{state.path_id}")
                    constraints.append(new_len == lst.z3_len + extension.z3_len)
                    new_list = lst.copy()
                    new_list.z3_len = new_len
            else:
                source = resolve_heap_object(args[1], state)
                direct_items = concrete_iterable_items(source, state)
                if direct_items is not None:
                    extension_items: list[object] = list(direct_items)
                    new_list = lst.extend(extension_items)
                    iterator_side_effect = iterator_exhaustion_side_effect(source, state)
                    if iterator_side_effect:
                        side_effects.update(iterator_side_effect)
                else:
                    new_list = lst.copy()

            side_effects["list_mutation"] = {
                "operation": "extend",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class ListInsertModel(FunctionModel):
    """Model for list.insert(i, x) - increases list length by 1.
    Relationship: After insert, len(list) == old_len + 1
    Note: Index i can be any value (negative, > len are valid)
    """

    name = "insert"
    qualname = "list.insert"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 3 or kwargs:
            return list_type_error_result("insert", state)
        lst = get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = _insert_concrete_item(lst, args[1], args[2])
            if new_list is None:
                new_list = lst.copy()
                new_list.z3_len = lst.z3_len + 1

            side_effects["list_mutation"] = {
                "operation": "insert",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


def _insert_concrete_item(lst: SymbolicList, index: object, item: object) -> SymbolicList | None:
    """Return an exact list after insert when retained items and index are concrete."""
    items = exact_concrete_items(lst)
    insert_index = _concrete_insert_index(index, len(items)) if items is not None else None
    if items is None or insert_index is None:
        return None
    updated_items = list(items)
    updated_items.insert(insert_index, item)
    return SymbolicList.from_const(updated_items)


def _concrete_insert_index(value: object, length: int) -> int | None:
    """Normalize a concrete list.insert index with CPython bounds behavior."""
    raw_index = _concrete_int(value)
    if raw_index is None:
        return None
    if raw_index < 0:
        return max(0, raw_index + length)
    return min(raw_index, length)


def _concrete_int(value: object) -> int | None:
    """Return a concrete integer or boolean stack value when available."""
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, SymbolicValue):
        concrete = value.value
        if isinstance(concrete, bool):
            return int(concrete)
        if isinstance(concrete, int):
            return concrete
        expr = z3.simplify(value.z3_int)
        if z3.is_int_value(expr):
            return expr.as_long()
    return None


__all__ = ["ListAppendModel", "ListExtendModel", "ListInsertModel"]
