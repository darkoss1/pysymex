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

"""Retain unevaluated ``BUILD_SLICE`` components for symbolic containers.

``SliceBounds`` is attached to a symbolic slice carrier so ``BINARY_SUBSCR`` /
``STORE_SUBSCR`` can retain start/stop/step evidence for execution collection
opcodes and runtime index-bounds detectors.

Limitations:
    This module does not query the solver. Concrete materialization with path
    constraints lives in :mod:`pysymex._internal.core.solver.slices`.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE, Z3_ZERO
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue

UNSUPPORTED_SLICE_ABSTRACTION = "unsupported_slice_abstraction"

if TYPE_CHECKING:
    from pysymex._internal.typing.protocols import StackValue


@dataclass(frozen=True, slots=True)
class SliceBounds:
    """Unevaluated slice components as CPython passes them to ``__getitem__``."""

    start: StackValue
    stop: StackValue
    step: StackValue | None = None


def build_slice_value(
    bounds: SliceBounds,
    pc: int,
) -> tuple[SymbolicValue, z3.BoolRef]:
    """Create a stack-compatible value retaining concrete slice components."""
    value, constraint = SymbolicValue.symbolic(f"slice_{pc}")
    value.attach_modeled_object(bounds)
    return value, constraint


def extract_slice_bounds(value: object) -> SliceBounds | None:
    """Return retained bounds when a value originated from ``BUILD_SLICE``."""
    if not isinstance(value, SymbolicValue):
        return None
    bounds = getattr(value, "_modeled_object", None)
    return bounds if isinstance(bounds, SliceBounds) else None


def replace_slice_bound(value: SymbolicValue, component: str, bound: StackValue) -> SymbolicValue:
    """Return a slice carrier with one converted component replaced."""
    bounds = extract_slice_bounds(value)
    if bounds is None:
        msg = "Slice carrier does not retain slice bounds"
        raise ValueError(msg)
    updated = copy.copy(value)
    updated.attach_modeled_object(replace(bounds, **{component: bound}))
    return updated


def possible_zero_step_condition(value: object) -> z3.BoolRef | None:
    """Return a precise zero-step predicate for a retained native integer step."""
    bounds = extract_slice_bounds(value)
    if bounds is None:
        return None
    step = bounds.step
    if step is None or isinstance(step, SymbolicNoneType):
        return Z3_FALSE
    if isinstance(step, bool):
        return Z3_FALSE if step else Z3_TRUE
    if isinstance(step, int):
        return Z3_TRUE if step == 0 else Z3_FALSE
    if isinstance(step, SymbolicValue):
        if z3.is_true(step.is_none):
            return Z3_FALSE
        if not z3.is_false(step.is_none) and z3.is_true(simplify_expr(step.is_none)):
            return Z3_FALSE
        return z3.And(step.is_int, step.z3_int == 0)
    return None


def unit_slice_step_is_supported(value: object) -> bool:
    """Return whether a slice step is encodable as CPython's unit-step case."""
    return value is None or (isinstance(value, int) and int(value) == 1)


def normalize_unit_slice_bound(
    value: object,
    length: z3.ArithRef,
    *,
    default_to_length: bool,
) -> z3.ArithRef | None:
    """Normalize a CPython unit-step slice bound against a symbolic sequence length."""
    if value is None:
        return length if default_to_length else Z3_ZERO
    if not isinstance(value, int):
        return None
    concrete = int(value)
    if concrete < 0:
        shifted = length + ConstraintValues.int(concrete)
        return simplify_expr(z3.If(shifted > 0, shifted, Z3_ZERO))
    raw = ConstraintValues.int(concrete)
    return simplify_expr(z3.If(raw < length, raw, length))


def unit_slice_extract_length(start: z3.ArithRef, stop: z3.ArithRef) -> z3.ArithRef:
    """Return the CPython unit-step slice length after normalized bounds."""
    return simplify_expr(z3.If(stop > start, stop - start, Z3_ZERO))
