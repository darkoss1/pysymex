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

"""String/integer substitution construction for detector witness probes."""

from __future__ import annotations

import z3

from pysymex._internal.core.constants import Z3_FALSE, Z3_TRUE
from pysymex._internal.core.solver.constraints.values import ConstraintValues

BoolTypeSlot = tuple[z3.BoolRef, str, str]


def bool_constants(formula: z3.ExprRef) -> list[z3.BoolRef]:
    """Collect uninterpreted Boolean constants from *formula* in stable order."""
    pending: list[z3.ExprRef] = [formula]
    visited: set[int] = set()
    constants_by_name: dict[str, z3.BoolRef] = {}
    while pending:
        expression = pending.pop()
        expression_hash = expression.hash()
        if expression_hash in visited:
            continue
        visited.add(expression_hash)
        if (
            isinstance(expression, z3.BoolRef)
            and z3.is_const(expression)
            and expression.decl().kind() == z3.Z3_OP_UNINTERPRETED
        ):
            constants_by_name[expression.decl().name()] = expression
            continue
        pending.extend(expression.children())
    return [constants_by_name[name] for name in sorted(constants_by_name)]


def bool_type_slots(bool_variables: list[z3.BoolRef]) -> tuple[BoolTypeSlot, ...]:
    """Return ``prefix_is_type`` Boolean slots used by string/integer witnesses."""
    slots: list[BoolTypeSlot] = []
    for variable in bool_variables:
        prefix, separator, suffix = variable.decl().name().rpartition("_is_")
        if separator:
            slots.append((variable, prefix, suffix))
    return tuple(slots)


def string_integer_substitutions(
    *,
    string_variables: list[z3.SeqRef],
    integer_variables: list[z3.ArithRef],
    string_values: tuple[str, ...],
    active_string_prefixes: frozenset[str],
    integer_values: tuple[int, ...],
    integer_prefixes: frozenset[str],
    bool_type_slots: tuple[BoolTypeSlot, ...],
) -> list[tuple[z3.ExprRef, z3.ExprRef]]:
    """Return concrete substitutions for one string/integer witness candidate."""
    substitutions: list[tuple[z3.ExprRef, z3.ExprRef]] = [
        (variable, ConstraintValues.string(value))
        for variable, value in zip(string_variables, string_values, strict=True)
    ]
    substitutions.extend(
        (variable, ConstraintValues.int(value))
        for variable, value in zip(integer_variables, integer_values, strict=False)
    )
    for variable, prefix, suffix in bool_type_slots:
        if prefix in active_string_prefixes:
            substitutions.append((variable, Z3_TRUE if suffix == "str" else Z3_FALSE))
        elif prefix in integer_prefixes:
            substitutions.append((variable, Z3_TRUE if suffix == "int" else Z3_FALSE))
    return substitutions
