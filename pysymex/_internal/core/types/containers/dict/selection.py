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

"""Finite retained-value selection helpers for symbolic dictionary semantics."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues
from pysymex._internal.core.solver.feasibility_context import path_may_be_feasible
from pysymex._internal.core.types.scalars.strings import SymbolicString
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.types.containers.dicts import SymbolicDict
    from pysymex._internal.typing.protocols import StackValue

NO_DEFAULT = object()


def conditional_retained_lookup_value(
    d: SymbolicDict,
    raw_key: object,
    default_value: StackValue | object = NO_DEFAULT,
    *,
    state: VMState,
    name: str,
) -> StackValue | None:
    """Return an exact finite-domain dict lookup value for retained items."""
    value_conditions = d.concrete_value_conditions_for_key(raw_key)
    if value_conditions is None:
        return None

    int_value = _conditional_int_value(value_conditions, default_value, state)
    if int_value is not None:
        int_value.rename(name)
        return int_value

    string_value = _conditional_string_value(value_conditions, default_value, state, name)
    if string_value is not None:
        return string_value
    return None


def _conditional_int_value(
    value_conditions: tuple[tuple[z3.BoolRef, object], ...],
    default_value: object,
    state: VMState,
) -> SymbolicValue | None:
    default_symbolic, iter_conditions = _default_or_present_retained_int(
        value_conditions,
        default_value,
        state,
    )
    if default_symbolic is None:
        return None

    result_expr = default_symbolic.z3_int
    for condition, value in reversed(iter_conditions):
        value_symbolic = _int_like_value(value)
        if value_symbolic is None:
            return None
        result_expr = z3.If(condition, value_symbolic.z3_int, result_expr)

    return SymbolicValue(
        _name="dict_lookup",
        z3_int=simplify_expr(result_expr),
        is_int=Z3_TRUE,
        z3_bool=Z3_FALSE,
        is_bool=Z3_FALSE,
        is_str=Z3_FALSE,
        is_none=Z3_FALSE,
        affinity_type="int",
    )


def _conditional_string_value(
    value_conditions: tuple[tuple[z3.BoolRef, object], ...],
    default_value: object,
    state: VMState,
    name: str,
) -> SymbolicString | None:
    default_str, default_len, iter_conditions = _default_or_present_retained_string(
        value_conditions,
        default_value,
        state,
    )
    if default_str is None or default_len is None:
        return None

    result_str = default_str
    result_len = default_len
    for condition, value in reversed(iter_conditions):
        value_str, value_len = _string_value_channels(value)
        if value_str is None or value_len is None:
            return None
        result_str = z3.If(condition, value_str, result_str)
        result_len = z3.If(condition, value_len, result_len)

    return SymbolicString(
        _z3_str=simplify_expr(result_str),
        _z3_len=simplify_expr(result_len),
        _name=name,
    )


def _default_or_present_retained_int(
    value_conditions: tuple[tuple[z3.BoolRef, object], ...],
    default_value: object,
    state: VMState,
) -> tuple[SymbolicValue | None, tuple[tuple[z3.BoolRef, object], ...]]:
    default_symbolic = None if default_value is NO_DEFAULT else _int_like_value(default_value)
    if default_symbolic is not None:
        return default_symbolic, value_conditions

    retained_value, iter_conditions = _present_retained_fallback(value_conditions, state)
    if retained_value is None:
        return None, ()
    retained_symbolic = _int_like_value(retained_value)
    if retained_symbolic is None:
        return None, ()
    return retained_symbolic, iter_conditions


def _default_or_present_retained_string(
    value_conditions: tuple[tuple[z3.BoolRef, object], ...],
    default_value: object,
    state: VMState,
) -> tuple[z3.SeqRef | None, z3.ArithRef | None, tuple[tuple[z3.BoolRef, object], ...]]:
    default_str, default_len = (
        (None, None) if default_value is NO_DEFAULT else _string_value_channels(default_value)
    )
    if default_str is not None and default_len is not None:
        return default_str, default_len, value_conditions

    retained_value, iter_conditions = _present_retained_fallback(value_conditions, state)
    if retained_value is None:
        return None, None, ()
    retained_str, retained_len = _string_value_channels(retained_value)
    if retained_str is None or retained_len is None:
        return None, None, ()
    return retained_str, retained_len, iter_conditions


def _present_retained_fallback(
    value_conditions: tuple[tuple[z3.BoolRef, object], ...],
    state: VMState,
) -> tuple[object | None, tuple[tuple[z3.BoolRef, object], ...]]:
    if not value_conditions:
        return None, ()
    presence = simplify_expr(z3.Or(*(condition for condition, _value in value_conditions)))
    if not _path_implies(state, presence):
        return None, ()
    return value_conditions[-1][1], value_conditions[:-1]


def _path_implies(state: VMState, condition: z3.BoolRef) -> bool:
    simplified = simplify_expr(condition)
    if z3.is_true(simplified):
        return True
    if z3.is_false(simplified):
        return False
    constraints = [*state.path_constraints.to_list(), z3.Not(simplified)]
    return not path_may_be_feasible(
        constraints,
        known_sat_prefix_len=_known_sat_prefix_len(state),
    )


def _known_sat_prefix_len(state: VMState) -> int:
    return max(0, len(state.path_constraints) - state.pending_constraint_count)


def _int_like_value(value: object) -> SymbolicValue | None:
    symbolic = SymbolicValue.from_const(value)
    if symbolic.affinity_type in {"int", "bool"}:
        return symbolic
    return None


def _string_value_channels(value: object) -> tuple[z3.SeqRef | None, z3.ArithRef | None]:
    if isinstance(value, str):
        return ConstraintValues.string(value), ConstraintValues.int(len(value))
    if isinstance(value, SymbolicString):
        return value.z3_str, value.z3_len
    if isinstance(value, SymbolicValue) and z3.is_true(simplify_expr(value.is_str)):
        return value.z3_str, z3.Length(value.z3_str)
    return None, None
