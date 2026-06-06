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

from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.containers.tuples.helpers import get_symbolic_tuple, tuple_type_error_result

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


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
        t = get_symbolic_tuple(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"tuple_item_{state.pc}")
        constraints = [constraint]
        side_effects: dict[str, object] = {}
        if t is not None and len(args) > 1:
            idx = args[1]
            idx_val = getattr(idx, "z3_int", None)
            if idx_val is not None:
                side_effects["potential_exception"] = {
                    "type": "IndexError",
                    "condition": z3.Or(idx_val >= t.z3_len, idx_val < -t.z3_len),
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
        t = get_symbolic_tuple(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"tuple_contains_{state.pc}")
        constraints = [constraint, result.is_bool]
        if t is not None:
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
        t = get_symbolic_tuple(args[0]) if args else None
        if t is not None:
            result, constraint = SymbolicValue.symbolic(f"len_{getattr(t, '_name', 'tuple')}")
            return ModelResult(
                value=result,
                constraints=[constraint, result.z3_int == t.z3_len],
            )
        result, constraint = SymbolicValue.symbolic(f"tuple_len_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
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
            return tuple_type_error_result(self.name, state)
        t = get_symbolic_tuple(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"tuple_count_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
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
            return tuple_type_error_result(self.name, state)
        t = get_symbolic_tuple(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"tuple_index_{state.pc}")
        constraints = [constraint, result.is_int, result.z3_int >= 0]
        side_effects: dict[str, object] = {}
        if t is not None:
            constraints.append(result.z3_int < t.z3_len)
            side_effects["potential_exception"] = {
                "type": "ValueError",
                "condition": t.z3_len == 0,
                "message": "tuple.index(x): x not in tuple",
            }
        return ModelResult(value=result, constraints=constraints, side_effects=side_effects)
