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

"""Symbolic tuple operation models."""

from __future__ import annotations

import dataclasses
from typing import TYPE_CHECKING

import z3

from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins.base import FunctionModel, ModelResult
from pysymex.models.containers.sequence_precision import (
    concatenate_concrete_backed_sequences,
    concrete_repeat_count,
    repeat_concrete_backed_sequence,
    repeat_count_expr,
)
from pysymex.models.containers.tuples.helpers import get_symbolic_tuple

if TYPE_CHECKING:
    from pysymex.typing import StackValue
    from pysymex.core.state.record import VMState


class TupleAddModel(FunctionModel):
    """Model for tuple.__add__(other) - concatenation."""

    name = "__add__"
    qualname = "tuple.__add__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple.__add__ method."""
        t = get_symbolic_tuple(args[0]) if args else None
        other = get_symbolic_tuple(args[1]) if len(args) > 1 else None
        if t is not None and other is not None:
            concatenated = concatenate_concrete_backed_sequences(t, other)
            if concatenated is not None:
                return ModelResult(value=_tuple_result(concatenated))
        result, constraint = SymbolicList.symbolic(f"tuple_add_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if t is not None and other is not None:
            constraints.append(result.z3_len == t.z3_len + other.z3_len)
        elif t is not None:
            constraints.append(result.z3_len >= t.z3_len)
        return ModelResult(value=result, constraints=constraints)


class TupleMulModel(FunctionModel):
    """Model for tuple.__mul__(n) - repetition."""

    name = "__mul__"
    qualname = "tuple.__mul__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple.__mul__ method."""
        t = get_symbolic_tuple(args[0]) if args else None
        n = args[1] if len(args) > 1 else None
        if t is not None and n is not None:
            count = concrete_repeat_count(n)
            if count is not None:
                repeated = repeat_concrete_backed_sequence(t, count)
                if repeated is not None:
                    return ModelResult(value=_tuple_result(repeated))
        result, constraint = SymbolicList.symbolic(f"tuple_mul_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if t is not None and n is not None:
            n_val = repeat_count_expr(n)
            if n_val is not None:
                constraints.append(
                    z3.If(
                        n_val > 0,
                        result.z3_len == t.z3_len * n_val,
                        result.z3_len == 0,
                    )
                )
        return ModelResult(value=result, constraints=constraints)


class TupleSliceModel(FunctionModel):
    """Model for tuple slicing."""

    name = "__getitem__"
    qualname = "tuple.__getslice__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple slice operation."""
        t = get_symbolic_tuple(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"tuple_slice_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if t is not None:
            constraints.append(result.z3_len <= t.z3_len)
        return ModelResult(value=result, constraints=constraints)


def _tuple_result(value: SymbolicList) -> SymbolicList:
    return dataclasses.replace(value, _type="tuple")


class TupleEqModel(FunctionModel):
    """Model for tuple.__eq__(other)."""

    name = "__eq__"
    qualname = "tuple.__eq__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple.__eq__ method."""
        t = get_symbolic_tuple(args[0]) if args else None
        other = get_symbolic_tuple(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"tuple_eq_{state.pc}")
        constraints = [constraint, result.is_bool]
        if t is not None and other is not None:
            constraints.append(z3.Implies(result.z3_bool, t.z3_len == other.z3_len))
            constraints.append(z3.Implies(t.z3_len != other.z3_len, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class TupleHashModel(FunctionModel):
    """Model for tuple.__hash__()."""

    name = "__hash__"
    qualname = "tuple.__hash__"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple.__hash__ method."""
        result, constraint = SymbolicValue.symbolic(f"tuple_hash_{state.pc}")
        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int],
        )
