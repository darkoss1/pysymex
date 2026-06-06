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

"""Shared helpers for symbolic list models."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex.core.constants import Z3_FALSE, Z3_TRUE
from pysymex.core.solver.constraints.hashing import get_string_val
from pysymex.core.types.containers.lists import SymbolicList
from pysymex.core.types.base import SymbolicNoneType as SymbolicNone
from pysymex.core.types.scalars.values import SymbolicValue
from pysymex.models.builtins import FunctionModel, ModelResult
from pysymex.models.typed_results import symbolic_bool_result, symbolic_int_result

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState


def get_symbolic_list(arg: object, state: VMState) -> SymbolicList | None:
    """Extract SymbolicList from argument, resolving SymbolicObject if needed."""
    if isinstance(arg, SymbolicList):
        return arg
    from pysymex.core.types.containers.objects import SymbolicObject

    if isinstance(arg, SymbolicObject):
        addr = arg.address
        if addr in state.memory:
            val = state.memory[addr]
            if isinstance(val, SymbolicList):
                return val
    return None


def get_symbolic_value(arg: object) -> SymbolicValue | None:
    """Extract SymbolicValue from argument."""
    if isinstance(arg, SymbolicValue):
        return arg
    return None


def absence_condition(values: list[object] | None, needle: object) -> z3.BoolRef | None:
    if values is None:
        return None
    if not values:
        return Z3_TRUE
    if isinstance(needle, SymbolicValue):
        clauses: list[z3.BoolRef] = []
        for value in values:
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
        return Z3_TRUE if needle not in values else Z3_FALSE
    except TypeError:
        return None


def list_type_error_result(name: str, state: VMState) -> ModelResult:
    """Return a deterministic TypeError result for an invalid list method call."""
    result, constraint = SymbolicValue.symbolic(f"list_{name}_invalid_{state.pc}")
    return ModelResult(
        value=result,
        constraints=[constraint],
        side_effects={
            "raised_exception": {
                "issue_kind": "TYPE_ERROR",
                "exception_type": "TypeError",
                "message": f"list.{name}() received invalid arguments",
                "source": f"list.{name}",
            }
        },
    )


__all__ = [
    "FunctionModel",
    "ModelResult",
    "SymbolicList",
    "SymbolicNone",
    "SymbolicValue",
    "absence_condition",
    "get_symbolic_list",
    "get_symbolic_value",
    "list_type_error_result",
    "symbolic_bool_result",
    "symbolic_int_result",
    "z3",
]
