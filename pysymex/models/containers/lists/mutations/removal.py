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

from pysymex.models.containers.sequence_precision import exact_concrete_items

from ..shared import (
    FunctionModel,
    ModelResult,
    SymbolicList,
    SymbolicNone,
    SymbolicValue,
    absence_condition,
    get_symbolic_list,
    get_symbolic_value,
    list_type_error_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Length-reducing symbolic list method models."""


class ListRemoveModel(FunctionModel):
    """Model for list.remove(x) - decreases length by 1 if element exists.
    Raises: ValueError if x not in list.
    Relationship: After remove (if successful), len(list) == old_len - 1
    Bug detection: Can find cases where element might not exist.
    """

    name = "remove"
    qualname = "list.remove"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return list_type_error_result("remove", state)
        lst = get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if lst is not None:
            missing_condition = absence_condition(
                lst.concrete_items, args[1] if len(args) > 1 else None
            )
            if missing_condition is not None:
                side_effects["potential_exception"] = {
                    "type": "ValueError",
                    "message": "list.remove(x): x not in list",
                    "condition": missing_condition,
                }
            new_list = _remove_concrete_item(lst, args[1])
            if new_list is None:
                new_list = lst.copy()
                new_list.z3_len = lst.z3_len - 1
            constraints.append(lst.z3_len >= 1)
            side_effects["list_mutation"] = {
                "operation": "remove",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


def _remove_concrete_item(lst: SymbolicList, item: object) -> SymbolicList | None:
    """Return an exact list after removing the first definitely matching item."""
    items = exact_concrete_items(lst)
    if items is None:
        return None
    for index, current in enumerate(items):
        if _definitely_same_item(current, item):
            updated = list(items)
            del updated[index]
            return SymbolicList.from_const(updated)
    return None


def _definitely_same_item(left: object, right: object) -> bool:
    """Return whether two retained items are definitely the same concrete value."""
    if left is right:
        return True
    left_value = _primitive_constant(left)
    right_value = _primitive_constant(right)
    return left_value is not _UNKNOWN_ITEM and left_value == right_value


_UNKNOWN_ITEM = object()


def _primitive_constant(value: object) -> object:
    """Return primitive retained constants that Python equality can compare exactly."""
    if isinstance(value, SymbolicValue):
        concrete = value.value
        if isinstance(concrete, (bool, int, str, bytes)) or concrete is None:
            return concrete
        return _UNKNOWN_ITEM
    if isinstance(value, (bool, int, str, bytes)) or value is None:
        return value
    return _UNKNOWN_ITEM


class ListPopModel(FunctionModel):
    """Model for list.pop([i]) - removes and returns element.
    Raises: IndexError if list is empty or index out of range.
    Relationship:
    - After pop, len(list) == old_len - 1
    - Returned element was in the list
    Bug detection: Can find cases where list might be empty.
    """

    name = "pop"
    qualname = "list.pop"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {1, 2} or kwargs:
            return list_type_error_result("pop", state)
        lst = get_symbolic_list(args[0], state) if args else None
        index = get_symbolic_value(args[1]) if len(args) > 1 else None
        result, result_constraint = SymbolicValue.symbolic(f"pop_{state.pc}_{state.path_id}")
        constraints: list[z3.BoolRef | z3.ExprRef] = [result_constraint]
        side_effects: dict[str, object] = {}
        if lst is not None:
            side_effects["potential_exception"] = {
                "type": "IndexError",
                "message": "pop from empty list",
                "condition": lst.z3_len == 0,
            }
            constraints.append(lst.z3_len >= 1)
            deletion_index: StackValue = -1
            if index is not None:
                constraints.append(lst.in_bounds(index))
                deletion_index = index
            result = lst[deletion_index]

            new_list = lst.__delitem__(deletion_index)

            side_effects["list_mutation"] = {
                "operation": "pop",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class ListClearModel(FunctionModel):
    """Model for list.clear() - removes all elements.
    Relationship: After clear, len(list) == 0
    """

    name = "clear"
    qualname = "list.clear"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return list_type_error_result("clear", state)
        lst = get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            new_list = SymbolicList.from_const([])
            side_effects["list_mutation"] = {
                "operation": "clear",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


__all__ = ["ListClearModel", "ListPopModel", "ListRemoveModel"]
