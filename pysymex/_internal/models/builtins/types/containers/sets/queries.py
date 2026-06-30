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

import z3

from pysymex._internal.core.types.containers.set_retention import (
    set_length_expr,
    set_presence_condition,
)
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.models.contracts.function import FunctionModel
from pysymex._internal.models.contracts.results import ModelResult

from .shared import get_symbolic_set

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.typing.protocols import StackValue

"""Query and predicate symbolic set models."""


class SetContainsModel(FunctionModel):
    """Model for set.__contains__(elem)."""

    name = "__contains__"
    qualname = "set.__contains__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.__contains__ method."""
        s = get_symbolic_set(args[0]) if args else None
        result, constraints = ModelResult.symbolic_bool(f"set_contains_{state.pc}")
        if s is not None:
            presence_condition = set_presence_condition(s, args[1] if len(args) > 1 else None)
            if presence_condition is not None:
                constraints.append(result.z3_bool == presence_condition)
            z3_len = set_length_expr(s)
            if z3_len is not None:
                constraints.append(z3.Implies(z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class SetLenModel(FunctionModel):
    """Model for set.__len__()."""

    name = "__len__"
    qualname = "set.__len__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.__len__ method."""
        s = get_symbolic_set(args[0]) if args else None
        z3_len = set_length_expr(s) if s else None
        if s is not None and z3_len is not None:
            result_val, result_constraints = ModelResult.symbolic_int(
                f"len_{getattr(s, '_name', 'set')}",
            )
            result_constraints.append(result_val.z3_int == z3_len)
            return ModelResult(
                value=result_val,
                constraints=result_constraints,
            )
        result, constraints = ModelResult.symbolic_int(f"set_len_{state.pc}")
        constraints.append(result.z3_int >= 0)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class SetIssubsetModel(FunctionModel):
    """Model for set.issubset(other)."""

    name = "issubset"
    qualname = "set.issubset"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.issubset method."""
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        other = get_symbolic_set(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic_bool(f"set_issubset_{state.pc}")
        constraints = [constraint]
        if s is not None and other is not None:
            z3_len = set_length_expr(s)
            other_len = getattr(other, "z3_len", getattr(other, "z3_int", None))
            if z3_len is not None and other_len is not None:
                constraints.append(z3.Implies(result.z3_bool, z3_len <= other_len))
        if s is not None:
            z3_len = set_length_expr(s)
            if z3_len is not None:
                constraints.append(z3.Implies(z3_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)


class SetIssupersetModel(FunctionModel):
    """Model for set.issuperset(other)."""

    name = "issuperset"
    qualname = "set.issuperset"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.issuperset method."""
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        other = get_symbolic_set(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic_bool(f"set_issuperset_{state.pc}")
        constraints = [constraint]
        if s is not None and other is not None:
            z3_len = set_length_expr(s)
            other_len = getattr(other, "z3_len", getattr(other, "z3_int", None))
            if z3_len is not None and other_len is not None:
                constraints.append(z3.Implies(result.z3_bool, z3_len >= other_len))
        if other is not None:
            other_len = getattr(other, "z3_len", getattr(other, "z3_int", None))
            if other_len is not None:
                constraints.append(z3.Implies(other_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)


class SetIsdisjointModel(FunctionModel):
    """Model for set.isdisjoint(other)."""

    name = "isdisjoint"
    qualname = "set.isdisjoint"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.isdisjoint method."""
        if len(args) != 2 or kwargs:
            return ModelResult.method_type_error(f"set.{self.name}", state)
        s = get_symbolic_set(args[0]) if args else None
        other = get_symbolic_set(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic_bool(f"set_isdisjoint_{state.pc}")
        constraints = [constraint]
        if s is not None:
            z3_len = set_length_expr(s)
            if z3_len is not None:
                constraints.append(z3.Implies(z3_len == 0, result.z3_bool))
        if other is not None:
            other_len = getattr(other, "z3_len", getattr(other, "z3_int", None))
            if other_len is not None:
                constraints.append(z3.Implies(other_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)
