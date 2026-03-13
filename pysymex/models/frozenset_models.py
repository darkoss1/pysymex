"""Symbolic models for Python frozenset operations.

Frozenset is immutable, so all operations return new values.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, cast

import z3

from pysymex.core.types import SymbolicList, SymbolicValue
from pysymex.models.builtins_base import FunctionModel, ModelResult

if TYPE_CHECKING:
    from pysymex._typing import StackValue
    from pysymex.core.state import VMState


def _get_symbolic_frozenset(arg: object) -> SymbolicList | None:
    """Extract symbolic frozenset from argument."""
    if isinstance(arg, SymbolicList):
        return arg
    return getattr(arg, "_symbolic_list", None) if arg is not None else None


class FrozensetContainsModel(FunctionModel):
    """Model for frozenset.__contains__(elem)."""

    name = "__contains__"
    qualname = "frozenset.__contains__"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.__contains__(elem)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = _get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"frozenset_contains_{state .pc }")
        constraints = [constraint, result.is_bool]
        if s is not None:
            constraints.append(z3.Implies(s.z3_len == 0, z3.Not(result.z3_bool)))
        return ModelResult(value=result, constraints=constraints)


class FrozensetLenModel(FunctionModel):
    """Model for len(frozenset)."""

    name = "__len__"
    qualname = "frozenset.__len__"

    def apply(
        self,
        args: list[StackValue],
        """Apply the len(frozenset)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = _get_symbolic_frozenset(args[0]) if args else None
        if s is not None:
            result = SymbolicValue(
                _name=f"len_frozenset_{state .pc }",
                z3_int=s.z3_len,
                is_int=z3.BoolVal(True),
                z3_bool=z3.BoolVal(False),
                is_bool=z3.BoolVal(False),
            )
            return ModelResult(value=result, constraints=[])
        result, constraint = SymbolicValue.symbolic(f"frozenset_len_{state .pc }")
        return ModelResult(
            value=result, constraints=[constraint, result.is_int, result.z3_int >= 0]
        )


class FrozensetUnionModel(FunctionModel):
    """Model for frozenset.union(*others)."""

    name = "union"
    qualname = "frozenset.union"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.union(*others)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = _get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"frozenset_union_{state .pc }")
        cast("Any", result)._type = "frozenset"
        constraints = [constraint]
        if s is not None:
            constraints.append(result.z3_len >= s.z3_len)
        return ModelResult(value=result, constraints=constraints)


class FrozensetIntersectionModel(FunctionModel):
    """Model for frozenset.intersection(*others)."""

    name = "intersection"
    qualname = "frozenset.intersection"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.intersection(*others)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = _get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"frozenset_inter_{state .pc }")
        cast("Any", result)._type = "frozenset"
        constraints = [constraint, result.z3_len >= 0]
        if s is not None:
            constraints.append(result.z3_len <= s.z3_len)
        return ModelResult(value=result, constraints=constraints)


class FrozensetDifferenceModel(FunctionModel):
    """Model for frozenset.difference(*others)."""

    name = "difference"
    qualname = "frozenset.difference"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.difference(*others)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = _get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"frozenset_diff_{state .pc }")
        cast("Any", result)._type = "frozenset"
        constraints = [constraint, result.z3_len >= 0]
        if s is not None:
            constraints.append(result.z3_len <= s.z3_len)
        return ModelResult(value=result, constraints=constraints)


class FrozensetSymmetricDifferenceModel(FunctionModel):
    """Model for frozenset.symmetric_difference(other)."""

    name = "symmetric_difference"
    qualname = "frozenset.symmetric_difference"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.symmetric_difference(other)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicList.symbolic(f"frozenset_symdiff_{state .pc }")
        cast("Any", result)._type = "frozenset"
        constraints = [constraint, result.z3_len >= 0]
        return ModelResult(value=result, constraints=constraints)


class FrozensetIssubsetModel(FunctionModel):
    """Model for frozenset.issubset(other)."""

    name = "issubset"
    qualname = "frozenset.issubset"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.issubset(other)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = _get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"frozenset_issubset_{state .pc }")
        constraints = [constraint, result.is_bool]
        if s is not None:
            constraints.append(z3.Implies(s.z3_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)


class FrozensetIssupersetModel(FunctionModel):
    """Model for frozenset.issuperset(other)."""

    name = "issuperset"
    qualname = "frozenset.issuperset"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.issuperset(other)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"frozenset_issuperset_{state .pc }")
        constraints = [constraint, result.is_bool]
        return ModelResult(value=result, constraints=constraints)


class FrozensetIsdisjointModel(FunctionModel):
    """Model for frozenset.isdisjoint(other)."""

    name = "isdisjoint"
    qualname = "frozenset.isdisjoint"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.isdisjoint(other)."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = _get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicValue.symbolic(f"frozenset_isdisjoint_{state .pc }")
        constraints = [constraint, result.is_bool]
        if s is not None:
            constraints.append(z3.Implies(s.z3_len == 0, result.z3_bool))
        return ModelResult(value=result, constraints=constraints)


class FrozensetCopyModel(FunctionModel):
    """Model for frozenset.copy()."""

    name = "copy"
    qualname = "frozenset.copy"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.copy()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        s = _get_symbolic_frozenset(args[0]) if args else None
        result, constraint = SymbolicList.symbolic(f"frozenset_copy_{state .pc }")
        cast("Any", result)._type = "frozenset"
        constraints = [constraint]
        if s is not None:
            constraints.append(result.z3_len == s.z3_len)
        return ModelResult(value=result, constraints=constraints)


class FrozensetHashModel(FunctionModel):
    """Model for frozenset.__hash__()."""

    name = "__hash__"
    qualname = "frozenset.__hash__"

    def apply(
        self,
        args: list[StackValue],
        """Apply the frozenset.__hash__()."""
        kwargs: dict[str, StackValue],
        state: VMState,
    ) -> ModelResult:
        result, constraint = SymbolicValue.symbolic(f"frozenset_hash_{state .pc }")
        return ModelResult(value=result, constraints=[constraint, result.is_int])


FROZENSET_MODELS = [
    FrozensetContainsModel(),
    FrozensetLenModel(),
    FrozensetUnionModel(),
    FrozensetIntersectionModel(),
    FrozensetDifferenceModel(),
    FrozensetSymmetricDifferenceModel(),
    FrozensetIssubsetModel(),
    FrozensetIssupersetModel(),
    FrozensetIsdisjointModel(),
    FrozensetCopyModel(),
    FrozensetHashModel(),
]
