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

"""Initial symbolic input constraints for function execution."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.initial.state.types import SymbolicCreatedValue


def supports_scalar_initial_constraint(value: object) -> bool:
    """Return whether ``constrain_initial_value`` can precisely constrain *value*."""
    return isinstance(value, (int, bool))


def assume_non_null_self(state: VMState, *, name: str, sym_val: SymbolicCreatedValue) -> VMState:
    """Apply the non-null ``self``/``cls`` heuristic when the carrier supports it."""
    lower_name = name.lower()
    if lower_name not in ("self", "cls") and not lower_name.startswith(("self_", "cls_")):
        return state
    maybe_none_expr = getattr(sym_val, "is_none", None)
    if isinstance(maybe_none_expr, z3.BoolRef):
        return state.add_constraint(z3.Not(maybe_none_expr))
    maybe_addr_expr = getattr(sym_val, "z3_addr", None)
    if isinstance(maybe_addr_expr, z3.ExprRef):
        return state.add_constraint(maybe_addr_expr != 0)
    return state


def constrain_initial_value(
    state: VMState,
    *,
    sym_val: SymbolicCreatedValue,
    value: object,
) -> VMState:
    """Constrain a symbolic scalar to a caller-provided concrete initial value."""
    if not isinstance(sym_val, SymbolicValue):
        return state
    if isinstance(value, int) and not isinstance(value, bool):
        return state.add_constraint(sym_val.z3_int == value)
    if isinstance(value, bool):
        return state.add_constraint(sym_val.z3_bool == value)
    return state
