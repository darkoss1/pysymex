"""Helpers for model results with CPython-fixed symbolic return types."""

from __future__ import annotations

from collections.abc import Sequence

import z3

from pysymex.core.types import SymbolicValue
from pysymex.models.builtins.base import ModelResult, SideEffectValue

ModelConstraint = z3.ExprRef | z3.BoolRef


def symbolic_int_result(name: str) -> tuple[SymbolicValue, list[ModelConstraint]]:
    """Create a symbolic int value with its base model constraints."""
    value, constraint = SymbolicValue.symbolic_int(name)
    return value, [constraint]


def symbolic_bool_result(name: str) -> tuple[SymbolicValue, list[ModelConstraint]]:
    """Create a symbolic bool value with its base model constraints."""
    value, constraint = SymbolicValue.symbolic_bool(name)
    return value, [constraint]


def model_int_result(
    name: str,
    extra_constraints: Sequence[ModelConstraint] = (),
    side_effects: dict[str, SideEffectValue] | None = None,
) -> ModelResult:
    """Return a ModelResult for operations that are guaranteed to return int."""
    value, constraints = symbolic_int_result(name)
    constraints.extend(extra_constraints)
    return ModelResult(value=value, constraints=constraints, side_effects=side_effects or {})


def model_bool_result(
    name: str,
    extra_constraints: Sequence[ModelConstraint] = (),
    side_effects: dict[str, SideEffectValue] | None = None,
) -> ModelResult:
    """Return a ModelResult for operations that are guaranteed to return bool."""
    value, constraints = symbolic_bool_result(name)
    constraints.extend(extra_constraints)
    return ModelResult(value=value, constraints=constraints, side_effects=side_effects or {})
