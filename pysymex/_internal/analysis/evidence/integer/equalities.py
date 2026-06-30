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

"""Integer equality extraction for detector witness probes."""

from __future__ import annotations

import z3

from pysymex._internal.analysis.evidence.formulas import iter_conjuncts
from pysymex._internal.core.solver.constraints.simplification import simplify_expr
from pysymex._internal.core.solver.constraints.values import ConstraintValues


def _assignment(
    formula: z3.BoolRef,
    variables: list[z3.ArithRef],
) -> tuple[int, ...] | None:
    """Return a complete assignment from direct ``x == literal`` constraints."""
    values_by_name: dict[str, int] = {}
    variables_by_name = {variable.decl().name(): variable for variable in variables}
    allowed_names = frozenset(variables_by_name)
    for constraint in iter_conjuncts(formula):
        simplified = simplify_expr(constraint)
        if not z3.is_eq(simplified):
            continue
        left, right = simplified.children()
        _assign_integer_value_from_equality(
            left=simplify_expr(left),
            right=simplify_expr(right),
            allowed_names=allowed_names,
            values_by_name=values_by_name,
        )
        _assign_integer_value_from_equality(
            left=simplify_expr(right),
            right=simplify_expr(left),
            allowed_names=allowed_names,
            values_by_name=values_by_name,
        )
    if any(variable.decl().name() not in values_by_name for variable in variables):
        return None
    return tuple(values_by_name[variable.decl().name()] for variable in variables)


def _infer_values(
    *,
    formula: z3.BoolRef,
    integer_variables: list[z3.ArithRef],
    values_by_name: dict[str, int],
) -> None:
    """Extend known integer assignments from direct equality constraints."""
    variables_by_name = {variable.decl().name(): variable for variable in integer_variables}
    allowed_names = frozenset(variables_by_name)
    for _ in range(len(integer_variables) + 1):
        substitutions = [
            (variable, ConstraintValues.int(values_by_name[name]))
            for name, variable in variables_by_name.items()
            if name in values_by_name
        ]
        changed = False
        for constraint in iter_conjuncts(formula):
            if substitutions:
                constraint = simplify_expr(z3.substitute(constraint, *substitutions))
            else:
                constraint = simplify_expr(constraint)
            if not z3.is_eq(constraint):
                continue
            left, right = constraint.children()
            left_simplified = simplify_expr(left)
            right_simplified = simplify_expr(right)
            changed |= _assign_integer_value_from_equality(
                left=left_simplified,
                right=right_simplified,
                allowed_names=allowed_names,
                values_by_name=values_by_name,
            )
            changed |= _assign_integer_value_from_equality(
                left=right_simplified,
                right=left_simplified,
                allowed_names=allowed_names,
                values_by_name=values_by_name,
            )
        if not changed:
            return


def _ordered_ord_variables(
    integer_variables: list[z3.ArithRef],
) -> list[z3.ArithRef]:
    """Return string-ordinal helper integers in source-index order."""
    return sorted(
        [
            variable
            for variable in integer_variables
            if variable.decl().name().startswith("ord_") and variable.decl().name().endswith("_int")
        ],
        key=_ord_integer_variable_key,
    )


def _slot_prefixes(integer_variables: list[z3.ArithRef]) -> frozenset[str]:
    """Return symbolic slot prefixes for ``*_int`` helper variables."""
    return frozenset(variable.decl().name().removesuffix("_int") for variable in integer_variables)


def _assign_integer_value_from_equality(
    *,
    left: z3.ExprRef,
    right: z3.ExprRef,
    allowed_names: frozenset[str],
    values_by_name: dict[str, int],
) -> bool:
    if (
        not isinstance(left, z3.ArithRef)
        or left.sort().kind() != z3.Z3_INT_SORT
        or left.decl().kind() != z3.Z3_OP_UNINTERPRETED
        or not z3.is_int_value(right)
    ):
        return False
    name = left.decl().name()
    if name not in allowed_names or name in values_by_name:
        return False
    values_by_name[name] = right.as_long()
    return True


def _ord_integer_variable_key(variable: z3.ArithRef) -> tuple[int, str]:
    name = variable.decl().name()
    stem = name.removesuffix("_int")
    address_text = stem.rsplit("_", 1)[-1]
    try:
        address = int(address_text)
    except ValueError:
        address = -1
    return (address, name)


class IntegerEqualities:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    assignment = staticmethod(_assignment)
    infer_values = staticmethod(_infer_values)
    ordered_ord_variables = staticmethod(_ordered_ord_variables)
    slot_prefixes = staticmethod(_slot_prefixes)
