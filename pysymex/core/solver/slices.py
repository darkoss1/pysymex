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

"""Solver-backed materialization for retained symbolic slice bounds."""

from __future__ import annotations

import z3

from pysymex.core.solver.engine.queries import check_sat_result, get_model

_UNRESOLVED_BOUND = object()
_MISSING = object()


def materialize_concrete_slice(
    value: object, constraints: list[z3.BoolRef] | None = None
) -> slice | None:
    """Return a nonzero concrete slice when retained bounds are fixed on this path."""
    bounds = _extract_slice_bounds(value)
    if bounds is None:
        return None
    start = _concrete_bound(bounds[0], constraints)
    stop = _concrete_bound(bounds[1], constraints)
    step = _concrete_bound(bounds[2], constraints)
    if _UNRESOLVED_BOUND in (start, stop, step) or step == 0:
        return None
    return slice(start, stop, step)


def _extract_slice_bounds(value: object) -> tuple[object, object, object | None] | None:
    """Return retained slice bounds without importing the core types package."""
    bounds = getattr(value, "_modeled_object", None)
    start = getattr(bounds, "start", _MISSING)
    stop = getattr(bounds, "stop", _MISSING)
    if start is _MISSING or stop is _MISSING:
        return None
    return start, stop, getattr(bounds, "step", None)


def _symbolic_value_parts(
    value: object,
) -> tuple[object, z3.BoolRef, z3.BoolRef, z3.ArithRef] | None:
    """Return the fields needed from a union-like symbolic value, if present."""
    concrete = getattr(value, "value", _MISSING)
    is_none = getattr(value, "is_none", None)
    is_int = getattr(value, "is_int", None)
    z3_int = getattr(value, "z3_int", None)
    if (
        concrete is _MISSING
        or not isinstance(is_none, z3.BoolRef)
        or not isinstance(is_int, z3.BoolRef)
        or not isinstance(z3_int, z3.ArithRef)
    ):
        return None
    return concrete, is_none, is_int, z3_int


def _concrete_bound(
    value: object | None, constraints: list[z3.BoolRef] | None = None
) -> int | None | object:
    """Resolve a retained slice bound to a concrete int, ``None``, or unresolved."""
    if value is None or type(value).__name__ == "SymbolicNoneType":
        return None
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    symbolic_parts = _symbolic_value_parts(value)
    if symbolic_parts is not None:
        concrete, is_none, is_int_expr, z3_int = symbolic_parts
        if z3.is_true(is_none):
            return None
        if not z3.is_false(is_none) and z3.is_true(z3.simplify(is_none)):
            return None
        if isinstance(concrete, bool):
            return int(concrete)
        if isinstance(concrete, int):
            return concrete
        is_int = z3.is_true(is_int_expr) or (
            not z3.is_false(is_int_expr) and z3.is_true(z3.simplify(is_int_expr))
        )
        if is_int and z3.is_int_value(z3_int):
            return z3_int.as_long()
        path = constraints or []
        if not check_sat_result([*path, z3.Not(is_int_expr)]).is_unsat:
            return _UNRESOLVED_BOUND
        model = get_model(path)
        if model is None:
            return _UNRESOLVED_BOUND
        candidate = model.eval(z3_int, model_completion=False)
        if not z3.is_int_value(candidate):
            return _UNRESOLVED_BOUND
        if check_sat_result([*path, z3_int != candidate]).is_unsat:
            return candidate.as_long()
    return _UNRESOLVED_BOUND


__all__ = ["materialize_concrete_slice"]
