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

"""Tuple query symbolic models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.containers.sequence_precision import (
    RetainedSequenceIndexResult,
    retained_sequence_item_for_index,
    retained_sequence_contains_value,
    retained_sequence_count_value,
    retained_sequence_index_result,
    sequence_index_error_condition,
    sequence_index_value,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.builtins.types.containers.tuples.tuple_ops import TupleContainerOps
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue


class TupleGetitemModel(FunctionModel):
    """Model for tuple.__getitem__(index)."""

    name = "__getitem__"
    qualname = "tuple.__getitem__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple.__getitem__ method."""
        t = TupleContainerOps.get_symbolic_tuple(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"tuple_item_{state.pc}")
        constraints = [constraint]
        side_effects: dict[str, object] = {}
        if t is not None and len(args) > 1:
            idx = args[1]
            retained_item = retained_sequence_item_for_index(
                t,
                idx,
                state,
                name=f"{t.name}[{getattr(idx, 'name', idx)!s}]",
            )
            if retained_item is not None:
                return ModelResult(value=retained_item.value)
            idx_value = sequence_index_value(idx)
            if idx_value is not None:
                side_effects["potential_exception"] = {
                    "type": "IndexError",
                    "condition": sequence_index_error_condition(t, idx_value),
                    "message": "tuple index out of range",
                }
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


class TupleContainsModel(FunctionModel):
    """Model for tuple.__contains__(elem)."""

    name = "__contains__"
    qualname = "tuple.__contains__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple.__contains__ method."""
        t = TupleContainerOps.get_symbolic_tuple(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic_bool(f"tuple_contains_{state.pc}")
        constraints = [constraint]
        if t is not None:
            retained_contains = retained_sequence_contains_value(
                t,
                args[1] if len(args) > 1 else None,
                state.path_constraints.to_list(),
            )
            if retained_contains is not None:
                return ModelResult(value=retained_contains)
            constraints.append(z3.Implies(t.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class TupleLenModel(FunctionModel):
    """Model for tuple.__len__()."""

    name = "__len__"
    qualname = "tuple.__len__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple.__len__ method."""
        t = TupleContainerOps.get_symbolic_tuple(args[0]) if args else None
        if t is not None:
            result, constraint = SymbolicValue.symbolic(f"len_{getattr(t, '_name', 'tuple')}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_int == t.z3_len],
            )
        result, constraint = SymbolicValue.symbolic_int(f"tuple_len_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.z3_int >= 0],
        )


class TupleCountModel(FunctionModel):
    """Model for tuple.count(value)."""

    name = "count"
    qualname = "tuple.count"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple.count method."""
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"tuple.{self.name}", state)
        t = TupleContainerOps.get_symbolic_tuple(args[0]) if args else None
        if t is not None:
            retained_count = retained_sequence_count_value(
                t,
                args[1] if len(args) > 1 else None,
                state.path_constraints.to_list(),
            )
            if retained_count is not None:
                return ModelResult(value=retained_count)
        result, constraint = SymbolicValue.symbolic_int(f"tuple_count_{state.pc}")
        constraints = [constraint, result.z3_int >= 0]
        if t is not None:
            constraints.append(result.z3_int <= t.z3_len)
        return ModelResult(value=result, constraints=constraints)


class TupleIndexModel(FunctionModel):
    """Model for tuple.index(value)."""

    name = "index"
    qualname = "tuple.index"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple.index method."""
        if len(args) not in {2, 3, 4} or kwargs:
            return ModelResult.method_type_error(f"tuple.{self.name}", state)
        t = TupleContainerOps.get_symbolic_tuple(args[0]) if args else None
        if t is not None:
            retained_index = _retained_index_result(t, args, state)
            if retained_index is not None:
                missing_condition = z3.Not(retained_index.found_condition)
                return ModelResult(
                    value=retained_index.value,
                    constraints=[retained_index.found_condition],
                    side_effects={
                        "potential_exception": {
                            "type": "ValueError",
                            "condition": missing_condition,
                            "message": "tuple.index(x): x not in tuple",
                        },
                    },
                )
        result, constraint = SymbolicValue.symbolic_int(f"tuple_index_{state.pc}")
        constraints = [constraint, result.z3_int >= 0]
        side_effects: dict[str, object] = {}
        if t is not None:
            constraints.append(result.z3_int < t.z3_len)
            side_effects["potential_exception"] = {
                "type": "ValueError",
                "condition": t.z3_len == 0,
                "message": "tuple.index(x): x not in tuple",
            }
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)


def _retained_index_result(
    value: SymbolicList,
    args: list[StackValue],
    state: VMState,
) -> RetainedSequenceIndexResult | None:
    constraints = state.path_constraints.to_list()
    if len(args) == 2:
        return retained_sequence_index_result(value, args[1], constraints)
    if len(args) == 3:
        return retained_sequence_index_result(value, args[1], constraints, args[2])
    return retained_sequence_index_result(value, args[1], constraints, args[2], args[3])
