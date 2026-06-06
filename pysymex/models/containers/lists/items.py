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

from .shared import (
    FunctionModel,
    ModelResult,
    SymbolicList,
    SymbolicNone,
    get_symbolic_list,
    list_type_error_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Copy, slicing, and item access symbolic list models."""


class ListCopyModel(FunctionModel):
    """Model for list.copy() - returns shallow copy.
    Relationship:
    - New list has same length
    - New list has same elements
    """

    name = "copy"
    qualname = "list.copy"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 1 or kwargs:
            return list_type_error_result("copy", state)
        lst = get_symbolic_list(args[0], state) if args else None
        result, base_constraint = SymbolicList.symbolic(f"list_copy_{state.pc}")
        constraints = [base_constraint]
        if lst is not None:
            return ModelResult(value=lst.copy())
        return ModelResult(value=result, constraints=constraints)


class ListSliceModel(FunctionModel):
    """Model for list[start:end] slicing.
    Relationship:
    - Result length = min(end, len) - max(start, 0)
    - Result length >= 0
    - Result elements are from original list
    """

    name = "__getitem__"
    qualname = "list.__getitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = get_symbolic_list(args[0], state) if args else None
        result, base_constraint = SymbolicList.symbolic(f"list_slice_{state.pc}")
        constraints = [base_constraint]
        if lst is not None:
            constraints.append(result.z3_len <= lst.z3_len)
            constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class ListSetitemModel(FunctionModel):
    """Model for list.__setitem__(index, value)."""

    name = "__setitem__"
    qualname = "list.__setitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__setitem__ method."""
        lst = get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if lst is not None and len(args) > 1:
            idx = args[1]
            idx_val = getattr(idx, "z3_int", None)
            if idx_val is not None:
                side_effects["potential_exception"] = {
                    "type": "IndexError",
                    "condition": z3.Or(idx_val >= lst.z3_len, idx_val < -lst.z3_len),
                    "message": "list assignment index out of range",
                }

            new_list = lst.copy()

            side_effects["list_mutation"] = {
                "operation": "setitem",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class ListDelitemModel(FunctionModel):
    """Model for list.__delitem__(index)."""

    name = "__delitem__"
    qualname = "list.__delitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__delitem__ method."""
        lst = get_symbolic_list(args[0], state) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if lst is not None:
            if len(args) > 1:
                idx = args[1]
                idx_val = getattr(idx, "z3_int", None)
                if idx_val is not None:
                    side_effects["potential_exception"] = {
                        "type": "IndexError",
                        "condition": z3.Or(idx_val >= lst.z3_len, idx_val < -lst.z3_len),
                        "message": "list assignment index out of range",
                    }

            new_list = lst.copy()
            new_len = z3.Int(f"list_len_{state.pc}_{state.path_id}")
            constraints.append(new_len == lst.z3_len - 1)
            constraints.append(new_len >= 0)
            new_list.z3_len = new_len

            side_effects["list_mutation"] = {
                "operation": "delitem",
                "original_list": lst,
                "updated_list": new_list,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )
