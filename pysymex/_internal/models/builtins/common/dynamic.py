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

"""Shared helpers for extended builtin function models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.types.containers.lists import SymbolicList
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.guards import RuntimeObjectGuards
from pysymex._internal.core.solver.feasibility_context import path_may_be_feasible

if TYPE_CHECKING:
    from collections.abc import Callable


def _constructor_len(value: object) -> z3.ArithRef | None:
    """Return the length expression for sequence constructors that preserve input length."""
    if isinstance(value, SymbolicList):
        return value.z3_len
    if isinstance(value, SymbolicValue):
        if isinstance(value.value, int):
            return value.z3_int
        payload: object = value.value
        if RuntimeObjectGuards.list(payload) or RuntimeObjectGuards.tuple(payload):
            return ConstraintValues.int(len(payload))
        if isinstance(payload, (bytes, bytearray)):
            return ConstraintValues.int(len(payload))
    if isinstance(value, int):
        return ConstraintValues.int(value)
    if RuntimeObjectGuards.list(value) or RuntimeObjectGuards.tuple(value):
        return ConstraintValues.int(len(value))
    if isinstance(value, (bytes, bytearray)):
        return ConstraintValues.int(len(value))
    return None


def _must_be_none(
    value: SymbolicValue,
    constraints: list[z3.BoolRef],
    *,
    known_sat_prefix_len: int | None = None,
    inconclusive_path_prefix_len: int | None = None,
) -> bool:
    """Return whether current path constraints force a symbolic value to be None."""
    if inconclusive_path_prefix_len is not None and inconclusive_path_prefix_len > 0:
        return False
    return not path_may_be_feasible(
        [*constraints, z3.Not(value.is_none)],
        known_sat_prefix_len=known_sat_prefix_len,
    )


def _iter_type_error(value: object) -> bool:
    if isinstance(value, (int, float, bool)) or value is None:
        return True
    if isinstance(value, SymbolicValue):
        from pysymex._internal.core.calls.payload import function_payload

        if function_payload(getattr(value, "_modeled_object", value)) is not None:
            return False
        return value.affinity_type in {"int", "float", "bool", "none"}
    return False


def _has_symbolic_attr(value: SymbolicValue, attr_name: str) -> bool | None:
    """Return attribute presence for concretely-typed symbolic builtins, else None."""
    probes: tuple[tuple[z3.BoolRef, object], ...] = (
        (value.is_int, 0),
        (value.is_bool, False),
        (value.is_float, 0.0),
        (value.is_str, ""),
    )
    for type_flag, probe_value in probes:
        if z3.is_true(simplify_expr(type_flag)):
            return hasattr(probe_value, attr_name)
    return None


def _get_modeled_attr(obj: object, attr_name: str) -> tuple[object, bool] | None:
    get_attribute = getattr(obj, "get_attribute", None)
    if not callable(get_attribute):
        return None
    typed_get_attribute = cast("Callable[[str], tuple[object, bool]]", get_attribute)
    value, found = typed_get_attribute(attr_name)
    return value, bool(found)


def _has_dynamic_attr_hook(obj: object) -> bool:
    modeled_class = getattr(obj, "cls", None)
    if modeled_class is None:
        return False
    get_method = getattr(modeled_class, "get_method", None)
    if not callable(get_method):
        return False
    return get_method("__getattr__") is not None or get_method("__getattribute__") is not None


must_be_none = _must_be_none


class DynamicBuiltinOps:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    constructor_len = staticmethod(_constructor_len)
    must_be_none = staticmethod(_must_be_none)
    iter_type_error = staticmethod(_iter_type_error)
    has_symbolic_attr = staticmethod(_has_symbolic_attr)
    get_modeled_attr = staticmethod(_get_modeled_attr)
    has_dynamic_attr_hook = staticmethod(_has_dynamic_attr_hook)
