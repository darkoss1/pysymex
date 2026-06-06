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

from typing import TYPE_CHECKING, Any, cast

from pysymex.models.containers.sequence_precision import exact_concrete_items

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

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""In-place symbolic list reordering method models."""


class ListSortModel(FunctionModel):
    """Model for list.sort() - sorts in place.
    Relationship:
    - Length unchanged
    - Same elements (permutation)
    """

    name = "sort"
    qualname = "list.sort"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or set(kwargs).difference({"key", "reverse"}):
            return list_type_error_result("sort", state)
        lst = get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            exact_items = exact_concrete_items(lst)
            reverse = _concrete_reverse(kwargs.get("reverse", False))
            key = kwargs.get("key")
            if exact_items is not None and key is None and reverse is not None:
                sorted_items = _sort_concrete_items(exact_items, reverse=reverse)
                if sorted_items is not None:
                    side_effects["list_mutation"] = {
                        "operation": "sort",
                        "original_list": lst,
                        "updated_list": SymbolicList.from_const(sorted_items),
                    }
                else:
                    side_effects["list_mutation"] = _permutation_side_effect(lst)
            else:
                side_effects["list_mutation"] = _permutation_side_effect(lst)
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class ListReverseModel(FunctionModel):
    """Model for list.reverse() - reverses in place.
    Relationship:
    - Length unchanged
    - Elements are reversed (permutation)
    """

    name = "reverse"
    qualname = "list.reverse"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return list_type_error_result("reverse", state)
        lst = get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            exact_items = exact_concrete_items(lst)
            if exact_items is not None:
                side_effects["list_mutation"] = {
                    "operation": "reverse",
                    "original_list": lst,
                    "updated_list": SymbolicList.from_const(list(reversed(exact_items))),
                }
            else:
                side_effects["list_mutation"] = {
                    "operation": "reverse",
                    "list_name": lst.name,
                    "old_length": lst.z3_len,
                    "new_length": lst.z3_len,
                    "is_permutation": True,
                }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


def _concrete_reverse(value: object) -> bool | None:
    """Return a concrete list.sort reverse flag when known."""
    if isinstance(value, bool):
        return value
    if isinstance(value, SymbolicValue):
        concrete = value.value
        if isinstance(concrete, bool):
            return concrete
        expr = z3.simplify(value.z3_bool)
        if z3.is_true(expr):
            return True
        if z3.is_false(expr):
            return False
    return None


def _sort_concrete_items(items: list[object], *, reverse: bool) -> list[object] | None:
    """Return CPython-sorted retained items, or ``None`` for unsupported ordering."""
    sortable_items = cast("list[Any]", list(items))
    try:
        sortable_items.sort(reverse=reverse)
    except TypeError:
        return None
    return list(sortable_items)


def _permutation_side_effect(lst: SymbolicList) -> dict[str, object]:
    """Return the imprecise length-preserving sort/reverse mutation metadata."""
    return {
        "operation": "sort",
        "list_name": lst.name,
        "old_length": lst.z3_len,
        "new_length": lst.z3_len,
        "is_permutation": True,
    }


__all__ = ["ListReverseModel", "ListSortModel"]
