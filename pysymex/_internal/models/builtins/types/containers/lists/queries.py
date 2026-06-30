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

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.objects import SymbolicObject
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.core.types.containers.sequence_precision import (
    RetainedSequenceIndexResult,
    derived_concrete_items,
    retained_sequence_contains_value,
    retained_sequence_count_value,
    retained_sequence_index_result,
)
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

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
            return ModelResult.method_type_error("list.index", state)
        lst = _resolve_list_receiver(args[0], state) if args else None
        if lst is not None:
            retained_index = _retained_index_result(lst, args, state)
            if retained_index is not None:
                missing_condition = z3.Not(retained_index.found_condition)
                return ModelResult(
                    value=retained_index.value,
                    constraints=[retained_index.found_condition],
                    side_effects={
                        "potential_exception": {
                            "type": "ValueError",
                            "message": "x not in list",
                            "condition": missing_condition,
                        },
                    },
                )
        result, result_constraint = SymbolicValue.symbolic_int(f"list_index_{state.pc}")
        constraints = [result_constraint, result.z3_int >= 0]
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


def _retained_index_result(
    lst: SymbolicList,
    args: list[StackValue],
    state: VMState,
) -> RetainedSequenceIndexResult | None:
    constraints = state.path_constraints.to_list()
    if len(args) == 2:
        return retained_sequence_index_result(lst, args[1], constraints)
    if len(args) == 3:
        return retained_sequence_index_result(lst, args[1], constraints, args[2])
    return retained_sequence_index_result(lst, args[1], constraints, args[2], args[3])


class ListCountModel(FunctionModel):
    """Model for list.count(x) - returns number of occurrences.
    Relationship:
    - Result >= 0
    - Result <= len(list).
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
            return ModelResult.method_type_error("list.count", state)
        lst = _resolve_list_receiver(args[0], state) if args else None
        if lst is not None:
            retained_count = retained_sequence_count_value(
                lst,
                args[1] if len(args) > 1 else None,
                state.path_constraints.to_list(),
            )
            if retained_count is not None:
                return ModelResult(value=retained_count)
        result, result_constraint = SymbolicValue.symbolic_int(f"list_count_{state.pc}")
        constraints = [result_constraint, result.z3_int >= 0]
        if lst is not None:
            constraints.append(result.z3_int <= lst.z3_len)
        return ModelResult(value=result, constraints=constraints)


class ListContainsModel(FunctionModel):
    """Model for 'x in list' operation.
    Relationship:
    - If list is empty, result is False
    - Otherwise, result is symbolic boolean.
    """

    name = "__contains__"
    qualname = "list.__contains__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        lst = _resolve_list_receiver(args[0], state) if args else None
        if lst is not None:
            retained_contains = retained_sequence_contains_value(
                lst,
                args[1] if len(args) > 1 else None,
                state.path_constraints.to_list(),
            )
            if retained_contains is not None:
                return ModelResult(value=retained_contains)
        result, constraints = ModelResult.symbolic_bool(f"list_contains_{state.pc}")
        if lst is not None:
            constraints.append(z3.Implies(lst.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


def _resolve_list_receiver(arg: object, state: VMState) -> SymbolicList | None:
    resolved = SymbolicList.resolve(arg, state)
    if resolved is not None:
        return resolved
    if isinstance(arg, SymbolicObject):
        value = state.memory.get(arg.address)
        if isinstance(value, list):
            return SymbolicList.from_const(cast("list[StackValue]", value))
    if isinstance(arg, list):
        return SymbolicList.from_const(cast("list[StackValue]", arg))
    return None


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
        lst = SymbolicList.resolve(args[0], state) if args else None
        if lst is not None:
            derived_items = derived_concrete_items(lst, state.path_constraints.to_list())
            if derived_items is not None:
                return ModelResult(value=len(derived_items))
            result = lst.length()
            return ModelResult(value=result, constraints=[])
        result, constraints = ModelResult.symbolic_int(f"list_len_{state.pc}")
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
        lst = SymbolicList.resolve(args[0], state) if args else None
        other = SymbolicList.resolve(args[1], state) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic_bool(f"list_eq_{state.pc}")
        constraints = [constraint]
        if lst is not None and other is not None:
            constraints.append(z3.Implies(result.z3_bool, lst.z3_len == other.z3_len))
            constraints.append(z3.Implies(lst.z3_len != other.z3_len, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)
