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
    SymbolicValue,
    get_symbolic_list,
    list_type_error_result,
    symbolic_bool_result,
    symbolic_int_result,
    z3,
)

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState

"""Query symbolic list method models."""


class ListIndexModel(FunctionModel):
    """Model for list.index(x) - returns index of first occurrence.
    Raises: ValueError if x not in list.
    Relationship:
    - Result >= 0
    - Result < len(list)
    Bug detection: Can find cases where element might not exist.
    """

    name = "index"
    qualname = "list.index"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) not in {2, 3, 4} or kwargs:
            return list_type_error_result("index", state)
        lst = get_symbolic_list(args[0], state) if args else None
        result, result_constraint = SymbolicValue.symbolic(f"list_index_{state.pc}")
        constraints = [result_constraint, result.is_int, result.z3_int >= 0]
        side_effects: dict[str, object] = {}
        if lst is not None:
            constraints.append(result.z3_int < lst.z3_len)
            side_effects["potential_exception"] = {
                "type": "ValueError",
                "message": "x not in list",
                "condition": z3.Bool(f"list_index_missing_{state.pc}"),
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class ListCountModel(FunctionModel):
    """Model for list.count(x) - returns number of occurrences.
    Relationship:
    - Result >= 0
    - Result <= len(list)
    """

    name = "count"
    qualname = "list.count"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return list_type_error_result("count", state)
        lst = get_symbolic_list(args[0], state) if args else None
        result, result_constraint = SymbolicValue.symbolic(f"list_count_{state.pc}")
        constraints = [result_constraint, result.is_int, result.z3_int >= 0]
        if lst is not None:
            constraints.append(result.z3_int <= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class ListContainsModel(FunctionModel):
    """Model for 'x in list' operation.
    Relationship:
    - If list is empty, result is False
    - Otherwise, result is symbolic boolean
    """

    name = "__contains__"
    qualname = "list.__contains__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = get_symbolic_list(args[0], state) if args else None
        result, constraints = symbolic_bool_result(f"list_contains_{state.pc}")
        if lst is not None:
            constraints.append(z3.Implies(lst.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class ListLenModel(FunctionModel):
    """Model for len(list).
    Relationship: Returns the symbolic length of the list.
    """

    name = "__len__"
    qualname = "list.__len__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = get_symbolic_list(args[0], state) if args else None
        if lst is not None:
            result = lst.length()
            return ModelResult(value=result, constraints=[])
        result, constraints = symbolic_int_result(f"list_len_{state.pc}")
        constraints.append(result.z3_int >= 0)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class ListEqModel(FunctionModel):
    """Model for list.__eq__(other)."""

    name = "__eq__"
    qualname = "list.__eq__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply list.__eq__ method."""
        lst = get_symbolic_list(args[0], state) if args else None
        other = get_symbolic_list(args[1], state) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"list_eq_{state.pc}")
        constraints = [constraint, result.is_bool]
        if lst is not None and other is not None:
            constraints.append(z3.Implies(result.z3_bool, lst.z3_len == other.z3_len))
            constraints.append(z3.Implies(lst.z3_len != other.z3_len, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)
