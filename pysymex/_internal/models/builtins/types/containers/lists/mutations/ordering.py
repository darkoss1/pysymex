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

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.sequence_precision import (
    reverse_retained_sequence,
    sort_retained_sequence,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""In-place symbolic list reordering method models."""


class ListSortModel(FunctionModel):
    """Model for list.sort() - sorts in place.
    Relationship:
    - Length unchanged
    - Same elements (permutation).
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
            return ModelResult.method_type_error("list.sort", state)
        lst = SymbolicList.resolve(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            key = kwargs.get("key")
            if key is None:
                sorted_list = sort_retained_sequence(
                    lst,
                    kwargs.get("reverse", False),
                    state.path_constraints.to_list(),
                )
                if sorted_list is not None:
                    side_effects["list_mutation"] = {
                        "operation": "sort",
                        "original_list": lst,
                        "updated_list": sorted_list,
                    }
                else:
                    side_effects["list_mutation"] = _permutation_side_effect(lst)
            else:
                side_effects["list_mutation"] = _permutation_side_effect(lst)
        return ModelResult(
            value=SymbolicNoneType(),
            side_effects=side_effects,
        )


class ListReverseModel(FunctionModel):
    """Model for list.reverse() - reverses in place.
    Relationship:
    - Length unchanged
    - Elements are reversed (permutation).
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
            return ModelResult.method_type_error("list.reverse", state)
        lst = SymbolicList.resolve(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        if lst is not None:
            reversed_list = reverse_retained_sequence(
                lst,
                state.path_constraints.to_list(),
            )
            if reversed_list is not None:
                side_effects["list_mutation"] = {
                    "operation": "reverse",
                    "original_list": lst,
                    "updated_list": reversed_list,
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
            value=SymbolicNoneType(),
            side_effects=side_effects,
        )


def _permutation_side_effect(lst: SymbolicList) -> dict[str, object]:
    """Return the imprecise length-preserving sort/reverse mutation metadata."""
    return {
        "operation": "sort",
        "list_name": lst.name,
        "old_length": lst.z3_len,
        "new_length": lst.z3_len,
        "is_permutation": True,
    }
