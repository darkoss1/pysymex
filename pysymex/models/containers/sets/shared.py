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

"""Shared helpers for symbolic set models."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_int_val, get_string_val
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.typed_results import symbolic_bool_result, symbolic_int_result

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


def get_symbolic_set(arg: object) -> SymbolicValue | None:
    """Extract symbolic value treated as set."""
    if isinstance(arg, SymbolicValue):
        return arg
    return None


def set_type_error_result(name: str, state: VMState) -> ModelResult:
    """Return a deterministic TypeError result for an invalid set method call."""
    result, constraint = SymbolicValue.symbolic(f"set_{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "raised_exception": {
                "issue_kind": "TYPE_ERROR",
                "exception_type": "TypeError",
                "message": f"set.{name}() received invalid arguments",
                "source": f"set.{name}",
            }
        },
    )


def set_length_expr(value: SymbolicValue) -> z3.ArithRef | None:
    """Return the Int expression that represents symbolic set cardinality."""
    for attr_name in ("z3_len", "z3_int"):
        candidate = getattr(value, attr_name, None)
        if isinstance(candidate, z3.ArithRef) and z3.is_int(candidate):
            return candidate
    return None


def set_absence_condition(set_value: SymbolicValue, needle: object) -> z3.BoolRef | None:
    concrete = set_value.value
    if not isinstance(concrete, set):
        return None
    concrete_set = cast("set[object]", concrete)
    if not concrete_set:
        return Z3_TRUE
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
                clauses.append(needle.z3_str != get_string_val(value))
        if clauses:
            return z3.And(*clauses)
        return None
    try:
        return Z3_TRUE if needle not in concrete else Z3_FALSE
    except TypeError:
        return None


def set_presence_condition(set_value: SymbolicValue, needle: object) -> z3.BoolRef | None:
    """Return an exact set-membership predicate when retained payload allows it."""
    absence = set_absence_condition(set_value, needle)
    if absence is None:
        return None
    return z3.Not(absence)


def replace_exact_set_value(set_value: SymbolicValue, values: set[object]) -> None:
    """Replace retained exact set payload and synchronized length metadata."""
    retained_values = set(values)
    setattr(set_value, "_constant_value", retained_values)
    setattr(set_value, "_modeled_object", retained_values)
    setattr(set_value, "_hash_cache", None)
    set_value.z3_int = get_int_val(len(retained_values))


__all__ = [
    "FunctionModel",
    "ModelResult",
    "replace_exact_set_value",
    "set_presence_condition",
    "SymbolicList",
    "SymbolicNone",
    "SymbolicValue",
    "get_symbolic_set",
    "set_absence_condition",
    "set_length_expr",
    "set_type_error_result",
    "symbolic_bool_result",
    "symbolic_int_result",
    "z3",
]
