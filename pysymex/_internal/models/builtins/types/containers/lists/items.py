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

from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.sequence_precision import (
    retained_sequence_item_for_index,
    sequence_index_error_condition,
    sequence_index_value,
    slice_concrete_backed_sequence,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult, SideEffects

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Copy, slicing, and item access symbolic list models."""


class ListCopyModel(FunctionModel):
    """Model for list.copy() - returns shallow copy.
    Relationship:
    - New list has same length
    - New list has same elements.
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
            return ModelResult.method_type_error("list.copy", state)
        lst = SymbolicList.resolve(args[0], state) if args else None
        result, base_constraint = SymbolicList.symbolic(f"list_copy_{state.pc}")
        constraints = [base_constraint]
        if lst is not None:
            return ModelResult(value=lst.copy())
        return ModelResult(value=result, constraints=constraints)


class ListGetitemModel(FunctionModel):
    """Model for ``list.__getitem__`` item and slice access."""

    name = "__getitem__"
    qualname = "list.__getitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error("list.__getitem__", state)
        lst = SymbolicList.resolve(args[0], state) if args else None
        key = args[1]
        slice_key = _slice_key(key)
        if slice_key is not None:
            retained = (
                slice_concrete_backed_sequence(
                    lst,
                    slice_key,
                    state.path_constraints.to_list(),
                )
                if lst is not None
                else None
            )
            if retained is not None:
                return ModelResult(value=retained)
            result, base_constraint = SymbolicList.symbolic(f"list_slice_{state.pc}")
            constraints = [base_constraint]
            if lst is not None:
                constraints.append(result.z3_len <= lst.z3_len)
                constraints.append(result.z3_len >= 0)
            return ModelResult(value=result, constraints=constraints)

        result, constraint = SymbolicValue.symbolic(f"list_item_{state.pc}")
        constraints = [constraint]
        side_effects: dict[str, object] = {}
        if lst is None:
            return ModelResult(value=result, constraints=constraints)

        retained_item = retained_sequence_item_for_index(
            lst,
            key,
            state,
            name=f"{lst.name}[{getattr(key, 'name', key)!s}]",
        )
        if retained_item is not None:
            return ModelResult(value=retained_item.value)

        index_value = sequence_index_value(key)
        if index_value is None:
            return ModelResult.method_type_error(
                "list.__getitem__",
                state,
                message=f"list indices must be integers or slices, not {type(key).__name__}",
            )

        side_effects["potential_exception"] = {
            "type": "IndexError",
            "condition": sequence_index_error_condition(lst, index_value),
            "message": "list index out of range",
        }
        return ModelResult(value=lst[index_value], side_effects=side_effects)


def _slice_key(value: object) -> slice[object, object, object] | None:
    if not isinstance(value, slice):
        return None
    return cast("slice[object, object, object]", value)


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
        if len(args) != 3 or kwargs:
            return ModelResult.method_type_error("list.__setitem__", state)
        lst = SymbolicList.resolve(args[0], state) if args else None
        if lst is None:
            return ModelResult.none()
        if _slice_key(args[1]) is not None:
            return _imprecise_slice_mutation_result("setitem", lst)
        index = sequence_index_value(args[1])
        if index is None:
            return ModelResult.method_type_error(
                "list.__setitem__",
                state,
                message=f"list indices must be integers or slices, not {type(args[1]).__name__}",
            )

        exception_condition = sequence_index_error_condition(lst, index)
        if _path_implies(state, exception_condition):
            return _definite_index_error_result("list.__setitem__")

        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects = _potential_index_error_side_effects(
            "setitem",
            lst,
            lst.__setitem__(index, args[2]),
            exception_condition,
            state,
            constraints,
        )
        return ModelResult(
            value=SymbolicNoneType(),
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
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error("list.__delitem__", state)
        lst = SymbolicList.resolve(args[0], state) if args else None
        if lst is None:
            return ModelResult.none()
        if _slice_key(args[1]) is not None:
            return _imprecise_slice_mutation_result("delitem", lst)
        index = sequence_index_value(args[1])
        if index is None:
            return ModelResult.method_type_error(
                "list.__delitem__",
                state,
                message=f"list indices must be integers or slices, not {type(args[1]).__name__}",
            )

        exception_condition = sequence_index_error_condition(lst, index)
        if _path_implies(state, exception_condition):
            return _definite_index_error_result("list.__delitem__")

        constraints: list[z3.BoolRef | z3.ExprRef] = []
        side_effects = _potential_index_error_side_effects(
            "delitem",
            lst,
            lst.__delitem__(index),
            exception_condition,
            state,
            constraints,
        )
        return ModelResult(
            value=SymbolicNoneType(),
            constraints=constraints,
            side_effects=side_effects,
        )


def _potential_index_error_side_effects(
    operation: str,
    original: SymbolicList,
    updated: SymbolicList,
    exception_condition: z3.BoolRef,
    state: VMState,
    constraints: list[z3.BoolRef | z3.ExprRef],
) -> dict[str, object]:
    side_effects: dict[str, object] = {
        "list_mutation": {
            "operation": operation,
            "original_list": original,
            "updated_list": updated,
        },
    }
    if not _path_refutes(state, exception_condition):
        side_effects["potential_exception"] = {
            "type": "IndexError",
            "condition": exception_condition,
            "message": "list assignment index out of range",
        }
        constraints.append(z3.Not(exception_condition))
    return side_effects


def _path_refutes(state: VMState, condition: z3.BoolRef) -> bool:
    simplified = z3.simplify(condition)
    if z3.is_false(simplified):
        return True
    if z3.is_true(simplified):
        return False
    solver = z3.Solver()
    solver.add(*state.path_constraints.to_list(), simplified)
    return solver.check() == z3.unsat


def _path_implies(state: VMState, condition: z3.BoolRef) -> bool:
    simplified = z3.simplify(condition)
    if z3.is_true(simplified):
        return True
    if z3.is_false(simplified):
        return False
    solver = z3.Solver()
    solver.add(*state.path_constraints.to_list(), z3.Not(simplified))
    return solver.check() == z3.unsat


def _definite_index_error_result(source: str) -> ModelResult:
    return ModelResult.none(
        side_effects=SideEffects.from_native_exception(
            source,
            IndexError("list assignment index out of range"),
        ),
    )


def _imprecise_slice_mutation_result(operation: str, lst: SymbolicList) -> ModelResult:
    return ModelResult.none(
        side_effects={
            "list_mutation": {
                "operation": operation,
                "original_list": lst,
                "updated_list": lst.copy(),
            },
        },
    )
