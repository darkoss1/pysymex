"""Symbolic models for Python set operations.

This module provides relationship-preserving symbolic models for set methods.
It tracks set size, membership constraints, and length mutations.
"""

from __future__ import annotations


from typing import TYPE_CHECKING, Any, cast


import z3


from pysymex.core.types import (
    SymbolicList,
    SymbolicNone,
    SymbolicValue,
)

from pysymex.models.builtins import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex.core.state import VMState


def _get_symbolic_set(arg: Any) -> SymbolicValue | None:
    """Extract symbolic value treated as set."""

    if isinstance(arg, SymbolicValue):
        return arg

    return None


class SetModel(FunctionModel):
    """Model for set constructor."""

    name = "set"

    qualname = "builtins.set"

    def apply(self, args: list[Any], kwargs: dict[str, Any], state: VMState) -> ModelResult:
        """Apply the set constructor model."""

        result, constraint = SymbolicValue.symbolic(f"set_{state.pc}")

        result._type = "set"

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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.add method."""

        s = _get_symbolic_set(args[0]) if args else None

        side_effects: dict[str, Any] = {}

        constraints: list[z3.BoolRef | z3.ExprRef] = []

        if s is not None:
            z3_len = getattr(s, "z3_len", getattr(s, "z3_int", None))

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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.remove method."""

        s = _get_symbolic_set(args[0]) if args else None

        side_effects: dict[str, Any] = {}

        constraints: list[z3.BoolRef | z3.ExprRef] = []

        if s is not None:
            z3_len = getattr(s, "z3_len", getattr(s, "z3_int", None))

            if z3_len is not None:
                constraints.append(z3_len >= 1)

                side_effects["potential_exception"] = {
                    "type": "KeyError",
                    "message": "set.remove(x): x not in set",
                    "condition": z3_len == 0,
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
    """Model for set.discard(elem)."""

    name = "discard"

    qualname = "set.discard"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.discard method."""

        s = _get_symbolic_set(args[0]) if args else None

        side_effects: dict[str, Any] = {}

        if s is not None:
            z3_len = getattr(s, "z3_len", getattr(s, "z3_int", None))

            side_effects["set_mutation"] = {
                "operation": "discard",
                "set_name": getattr(s, "_name", "set"),
                "old_length": z3_len,
                "length_may_decrease": True,
            }

        return ModelResult(
            value=SymbolicNone(),
            side_effects=side_effects,
        )


class SetPopModel(FunctionModel):
    """Model for set.pop()."""

    name = "pop"

    qualname = "set.pop"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.pop method."""

        s = _get_symbolic_set(args[0]) if args else None

        result, constraint = SymbolicValue.symbolic(f"set_pop_{state.pc}")

        constraints: list[z3.BoolRef | z3.ExprRef] = [constraint]

        side_effects: dict[str, Any] = {}

        z3_len = getattr(s, "z3_len", getattr(s, "z3_int", None)) if s else None

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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.clear method."""

        s = _get_symbolic_set(args[0]) if args else None

        side_effects: dict[str, Any] = {}

        if s is not None:
            s.z3_int = z3.IntVal(0)

            side_effects["set_mutation"] = {
                "operation": "clear",
                "set_name": getattr(s, "_name", "set"),
                "old_length": getattr(s, "z3_len", getattr(s, "z3_int", None)),
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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.copy method."""

        s = _get_symbolic_set(args[0]) if args else None

        result, constraint = SymbolicList.symbolic(f"set_copy_{state.pc}")

        cast(Any, result)._type = "set"

        constraints = [constraint]

        if s is not None:
            z3_len = getattr(s, "z3_len", getattr(s, "z3_int", None))

            if z3_len is not None:
                constraints.append(result.z3_len == z3_len)

        return ModelResult(value=result, constraints=constraints)


class SetUnionModel(FunctionModel):
    """Model for set.union(*others)."""

    name = "union"

    qualname = "set.union"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.union method."""

        s = _get_symbolic_set(args[0]) if args else None

        result, constraint = SymbolicList.symbolic(f"set_union_{state.pc}")

        cast(Any, result)._type = "set"

        constraints = [constraint]

        if s is not None:
            z3_len = getattr(s, "z3_len", getattr(s, "z3_int", None))

            if z3_len is not None:
                constraints.append(result.z3_len >= z3_len)

        return ModelResult(value=result, constraints=constraints)


class SetIntersectionModel(FunctionModel):
    """Model for set.intersection(*others)."""

    name = "intersection"

    qualname = "set.intersection"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.intersection method."""

        s = _get_symbolic_set(args[0]) if args else None

        result, constraint = SymbolicList.symbolic(f"set_inter_{state.pc}")

        cast(Any, result)._type = "set"

        constraints = [constraint]

        if s is not None:
            z3_len = getattr(s, "z3_len", getattr(s, "z3_int", None))

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
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.__contains__ method."""

        s = _get_symbolic_set(args[0]) if args else None

        result, constraint = SymbolicValue.symbolic(f"set_contains_{state.pc}")

        constraints = [constraint, result.is_bool]

        if s is not None:
            z3_len = getattr(s, "z3_len", getattr(s, "z3_int", None))

            if z3_len is not None:
                constraints.append(z3.Implies(z3_len == 0, z3.Not(result.z3_bool)))

        return ModelResult(value=result, constraints=constraints)


class SetLenModel(FunctionModel):
    """Model for set.__len__()."""

    name = "__len__"

    qualname = "set.__len__"

    def apply(
        self,
        args: list[Any],
        kwargs: dict[str, Any],
        state: VMState,
    ) -> ModelResult:
        """Apply set.__len__ method."""

        s = _get_symbolic_set(args[0]) if args else None

        z3_len = getattr(s, "z3_len", getattr(s, "z3_int", None)) if s else None

        if s is not None and z3_len is not None:
            result_val, result_const = SymbolicValue.symbolic(f"len_{getattr(s, '_name', 'set')}")

            return ModelResult(
                value=result_val, constraints=[result_const, result_val.z3_int == z3_len]
            )

        result, constraint = SymbolicValue.symbolic(f"set_len_{state.pc}")

        return ModelResult(
            value=result,
            constraints=[constraint, result.is_int, result.z3_int >= 0],
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
    SetContainsModel(),
    SetLenModel(),
]
