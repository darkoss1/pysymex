# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
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

"""Symbolic models for Python tuple operations.

This module provides relationship-preserving symbolic models for tuple methods.
Tuples are immutable, so all operations return new values without side effects.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.types import SymbolicList, SymbolicValue
from pysymex.models.builtins_base import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


def _get_symbolic_tuple(arg: object) -> SymbolicList | None:
    """Extract SymbolicList (used for tuples) from argument."""
    if isinstance(arg, SymbolicList):
        return arg
    return getattr(arg, "_symbolic_list", None) if arg is not None else None


class TupleModel(FunctionModel):
    """Model for tuple() constructor."""

    name = "tuple"
    qualname = "tuple"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply tuple() constructor."""
        result, constraint = SymbolicList.symbolic(f"tuple_{state.pc}")
        constraints = [constraint]
        if not args:
            constraints.append(result.z3_len == 0)
        return ModelResult(value=result, constraints=constraints)


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
        t = _get_symbolic_tuple(args[0]) if args else None
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
        t = _get_symbolic_tuple(args[0]) if args else None
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
        t = _get_symbolic_tuple(args[0]) if args else None
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
        t = _get_symbolic_tuple(args[0]) if args else None
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
        t = _get_symbolic_tuple(args[0]) if args else None
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
        t = _get_symbolic_tuple(args[0]) if args else None
        other = _get_symbolic_tuple(args[1]) if len(args) > 1 else None
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
        t = _get_symbolic_tuple(args[0]) if args else None
        n = args[1] if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"tuple_mul_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if t is not None and n is not None:
            n_val = getattr(n, "z3_int", None)
            if n_val is not None:
                constraints.append(
                    cast(
                        "z3.BoolRef",
                        z3.If(n_val > 0, result.z3_len == t.z3_len * n_val, result.z3_len == 0),
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
        t = _get_symbolic_tuple(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"tuple_slice_{state.pc}")
        constraints = [constraint, result.z3_len >= 0]
        if t is not None:
            constraints.append(result.z3_len <= t.z3_len)
        return ModelResult(value=result, constraints=constraints)


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
        t = _get_symbolic_tuple(args[0]) if args else None
        other = _get_symbolic_tuple(args[1]) if len(args) > 1 else None
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


TUPLE_MODELS = [
    TupleModel(),
    TupleGetitemModel(),
    TupleContainsModel(),
    TupleLenModel(),
    TupleCountModel(),
    TupleIndexModel(),
    TupleAddModel(),
    TupleMulModel(),
    TupleSliceModel(),
    TupleEqModel(),
    TupleHashModel(),
]
