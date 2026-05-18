# pysymex: Python Symbolic Execution & Formal Verification
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

"""Symbolic models for Python set operations.

This module provides relationship-preserving symbolic models for set methods.
It tracks set size, membership constraints, and length mutations.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.types import (
    SymbolicList,
    SymbolicNone,
    SymbolicValue,
)
from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.typed_results import (
    symbolic_bool_result,
    symbolic_int_result,
)

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


def _get_symbolic_set(arg: object) -> SymbolicValue | None:
    """Extract symbolic value treated as set."""
    if isinstance(arg, SymbolicValue):
        return arg
    return None


def _set_length_expr(value: SymbolicValue) -> z3.ArithRef | None:
    """Return the Int expression that represents symbolic set cardinality."""
    for attr_name in ("z3_len", "z3_int"):
        candidate = getattr(value, attr_name, None)
        if isinstance(candidate, z3.ArithRef) and z3.is_int(candidate):
            return candidate
    return None


def _set_absence_condition(set_value: SymbolicValue, needle: object) -> z3.BoolRef | None:
    concrete = set_value.value
    if not isinstance(concrete, set):
        return None
    concrete_set = cast("set[object]", concrete)
    if not concrete_set:
        return z3.BoolVal(True)
    if isinstance(needle, SymbolicValue):
        clauses: list[z3.BoolRef] = []
        for value in concrete_set:
            if isinstance(value, SymbolicValue):
                value = value.value
            if isinstance(value, bool):
                clauses.append(needle.z3_int != int(value))
            elif isinstance(value, int):
                clauses.append(needle.z3_int != value)
            elif isinstance(value, str):
                clauses.append(needle.z3_str != z3.StringVal(value))
        if clauses:
            return z3.And(*clauses)
        return None
    try:
        return z3.BoolVal(needle not in concrete)
    except TypeError:
        return None


class SetModel(FunctionModel):
    """Model for set constructor."""

    name = "set"
    qualname = "builtins.set"

    def apply(
        self, args: list[StackValue], kwargs: dict[str, StackValue], state: VMState
    ) -> ModelResult:
        """Apply the set constructor model."""
        result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")
        setattr(result, "_type", "set")
        if not args:
            return ModelResult(value=result, constraints=[constraint, result.z3_int == 0])
        return ModelResult(value=result, constraints=[constraint, result.z3_int >= 0])


class SetAddModel(FunctionModel):
    """Model for set.add(elem).
    Relationship:
    - len(set) >= old_len (increases if new)
    - len(set) <= old_len + 1
    """

    name = "add"
    qualname = "set.add"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.add method."""
        s = _get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(z3.And(new_len >= z3_len, new_len <= z3_len + 1))
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "add",
                "set_name": getattr(s, "_name", "set"),
                "old_length": z3_len,
                "length_may_increase": True,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetRemoveModel(FunctionModel):
    """Model for set.remove(elem).
    Raises: KeyError if elem not in set.
    Relationship: len(set) == old_len - 1
    """

    name = "remove"
    qualname = "set.remove"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.remove method."""
        s = _get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                constraints.append(z3_len >= 1)
                missing_condition = _set_absence_condition(s, args[1] if len(args) > 1 else None)
                if missing_condition is not None:
                    side_effects["potential_exception"] = {
                        "type": "KeyError",
                        "message": "set.remove(x): x not in set",
                        "condition": missing_condition,
                    }
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(new_len == z3_len - 1)
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "remove",
                "set_name": getattr(s, "_name", "set"),
                "old_length": z3_len,
                "length_decrease": 1,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetDiscardModel(FunctionModel):
    """Model for set.discard(elem).
    Like remove but no error if missing.
    Relationship: new_len in [old_len - 1, old_len]
    """

    name = "discard"
    qualname = "set.discard"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.discard method."""
        s = _get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(z3.And(new_len >= z3_len - 1, new_len <= z3_len))
                constraints.append(new_len >= 0)
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "discard",
                "set_name": getattr(s, "_name", "set"),
                "old_length": z3_len,
                "length_may_decrease": True,
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetPopModel(FunctionModel):
    """Model for set.pop()."""

    name = "pop"
    qualname = "set.pop"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.pop method."""
        s = _get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"set_pop_{state.pc}")
        constraints: list[z3.BoolRef | z3.ExprRef] = [constraint]
        side_effects: dict[str, object] = {}
        z3_len = _set_length_expr(s) if s else None
        if s is not None and z3_len is not None:
            constraints.append(z3_len >= 1)
            side_effects["potential_exception"] = {
                "type": "KeyError",
                "message": "pop from an empty set",
                "condition": z3_len == 0,
            }
            new_len = z3.Int(f"set_len_{state.pc}")
            constraints.append(new_len == z3_len - 1)
            s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "pop",
                "set_name": getattr(s, "_name", "set"),
                "old_length": z3_len,
                "length_decrease": 1,
            }
        return ModelResult(
            value=result,
            constraints=constraints,
            side_effects=side_effects,
        )


class SetClearModel(FunctionModel):
    """Model for set.clear()."""

    name = "clear"
    qualname = "set.clear"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.clear method."""
        s = _get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        if s is not None:
            s.z3_int = z3.IntVal(0)
            side_effects["set_mutation"] = {
                "operation": "clear",
                "set_name": getattr(s, "_name", "set"),
                "old_length": _set_length_expr(s),
                "new_length": 0,
            }
        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class SetCopyModel(FunctionModel):
    """Model for set.copy()."""

    name = "copy"
    qualname = "set.copy"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.copy method."""
        s = _get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"set_copy_{state.pc}")
        setattr(result, "_type", "set")
        constraints = [constraint]
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                constraints.append(result.z3_len == z3_len)
        return ModelResult(value=result, constraints=constraints)


class SetUnionModel(FunctionModel):
    """Model for set.union(*others)."""

    name = "union"
    qualname = "set.union"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.union method."""
        s = _get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"set_union_{state.pc}")
        setattr(result, "_type", "set")
        constraints = [constraint]
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                constraints.append(result.z3_len >= z3_len)
        return ModelResult(value=result, constraints=constraints)


class SetIntersectionModel(FunctionModel):
    """Model for set.intersection(*others)."""

    name = "intersection"
    qualname = "set.intersection"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.intersection method."""
        s = _get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"set_inter_{state.pc}")
        setattr(result, "_type", "set")
        constraints = [constraint]
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                constraints.append(result.z3_len <= z3_len)
                constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


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
        s = _get_symbolic_set(args[0]) if args else None
        result, constraints = symbolic_bool_result(f"set_contains_{state.pc}")
        if s is not None:
            z3_len = _set_length_expr(s)
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
        s = _get_symbolic_set(args[0]) if args else None
        z3_len = _set_length_expr(s) if s else None
        if s is not None and z3_len is not None:
            result_val, result_constraints = symbolic_int_result(
                f"len_{getattr(s, '_name', 'set')}"
            )
            result_constraints.append(result_val.z3_int == z3_len)
            return ModelResult(
                value=result_val,
                constraints=result_constraints,
            )
        result, constraints = symbolic_int_result(f"set_len_{state.pc}")
        constraints.append(result.z3_int >= 0)
        return ModelResult(
            value=result,
            constraints=constraints,
        )


class SetDifferenceModel(FunctionModel):
    """Model for set.difference(*others)."""

    name = "difference"
    qualname = "set.difference"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.difference method."""
        s = _get_symbolic_set(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"set_diff_{state.pc}")
        setattr(result, "_type", "set")
        constraints = [constraint]
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                constraints.append(result.z3_len <= z3_len)
                constraints.append(result.z3_len >= 0)
        return ModelResult(value=result, constraints=constraints)


class SetSymmetricDifferenceModel(FunctionModel):
    """Model for set.symmetric_difference(other)."""

    name = "symmetric_difference"
    qualname = "set.symmetric_difference"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.symmetric_difference method."""
        s = _get_symbolic_set(args[0]) if args else None
        other = _get_symbolic_set(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicList.symbolic(f"set_symdiff_{state.pc}")
        setattr(result, "_type", "set")
        constraints = [constraint, result.z3_len >= 0]
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None and other is not None:
                other_len = getattr(other, "z3_len", getattr(other, "z3_int", None))
                if other_len is not None:
                    constraints.append(result.z3_len <= z3_len + other_len)
        return ModelResult(value=result, constraints=constraints)


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
        s = _get_symbolic_set(args[0]) if args else None
        other = _get_symbolic_set(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"set_issubset_{state.pc}")
        constraints = [constraint, result.is_bool]
        if s is not None and other is not None:
            z3_len = _set_length_expr(s)
            other_len = getattr(other, "z3_len", getattr(other, "z3_int", None))
            if z3_len is not None and other_len is not None:
                constraints.append(z3.Implies(result.z3_bool, z3_len <= other_len))
        if s is not None:
            z3_len = _set_length_expr(s)
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
        s = _get_symbolic_set(args[0]) if args else None
        other = _get_symbolic_set(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"set_issuperset_{state.pc}")
        constraints = [constraint, result.is_bool]
        if s is not None and other is not None:
            z3_len = _set_length_expr(s)
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
        s = _get_symbolic_set(args[0]) if args else None
        other = _get_symbolic_set(args[1]) if len(args) > 1 else None
        result, constraint = SymbolicValue.symbolic(f"set_isdisjoint_{state.pc}")
        constraints = [constraint, result.is_bool]
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                constraints.append(z3.Implies(z3_len == 0, result.z3_bool))
        if other is not None:
            other_len = getattr(other, "z3_len", getattr(other, "z3_int", None))
            if other_len is not None:
                constraints.append(z3.Implies(other_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)


class SetUpdateModel(FunctionModel):
    """Model for set.update(*others)."""

    name = "update"
    qualname = "set.update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.update method."""
        s = _get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(new_len >= z3_len)
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "update",
                "set_name": getattr(s, "_name", "set"),
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetIntersectionUpdateModel(FunctionModel):
    """Model for set.intersection_update(*others)."""

    name = "intersection_update"
    qualname = "set.intersection_update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.intersection_update method."""
        s = _get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(new_len <= z3_len)
                constraints.append(new_len >= 0)
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "intersection_update",
                "set_name": getattr(s, "_name", "set"),
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetDifferenceUpdateModel(FunctionModel):
    """Model for set.difference_update(*others)."""

    name = "difference_update"
    qualname = "set.difference_update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.difference_update method."""
        s = _get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(new_len <= z3_len)
                constraints.append(new_len >= 0)
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "difference_update",
                "set_name": getattr(s, "_name", "set"),
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


class SetSymmetricDifferenceUpdateModel(FunctionModel):
    """Model for set.symmetric_difference_update(other)."""

    name = "symmetric_difference_update"
    qualname = "set.symmetric_difference_update"

    def apply(
        self,
        args: list[StackValue],
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        """Apply set.symmetric_difference_update method."""
        s = _get_symbolic_set(args[0]) if args else None
        side_effects: dict[str, object] = {}
        constraints: list[z3.BoolRef | z3.ExprRef] = []
        if s is not None:
            z3_len = _set_length_expr(s)
            if z3_len is not None:
                new_len = z3.Int(f"set_len_{state.pc}")
                constraints.append(new_len >= 0)
                s.z3_int = new_len
            side_effects["set_mutation"] = {
                "operation": "symmetric_difference_update",
                "set_name": getattr(s, "_name", "set"),
            }
        return ModelResult(
            value=SymbolicNone(),
            constraints=constraints,
            side_effects=side_effects,
        )


SET_MODELS = [
    SetModel(),
    SetAddModel(),
    SetRemoveModel(),
    SetDiscardModel(),
    SetPopModel(),
    SetClearModel(),
    SetCopyModel(),
    SetUnionModel(),
    SetIntersectionModel(),
    SetDifferenceModel(),
    SetSymmetricDifferenceModel(),
    SetIssubsetModel(),
    SetIssupersetModel(),
    SetIsdisjointModel(),
    SetUpdateModel(),
    SetIntersectionUpdateModel(),
    SetDifferenceUpdateModel(),
    SetSymmetricDifferenceUpdateModel(),
    SetContainsModel(),
    SetLenModel(),
]
