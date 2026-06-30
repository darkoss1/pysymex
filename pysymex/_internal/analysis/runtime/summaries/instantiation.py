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

"""Instantiation of function summaries at call sites."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3

from pysymex._internal.core.constants import Z3_TRUE
from pysymex._internal.core.identity.addressing import next_address
from pysymex._internal.core.solver.constraints.values import ConstraintValues

if TYPE_CHECKING:
    from pysymex._internal.analysis.runtime.summaries.types import FunctionSummary


def instantiate_summary(
    summary: FunctionSummary,
    args: list[z3.ExprRef],
    kwargs: dict[str, z3.ExprRef],
    call_id: str = "",
) -> tuple[z3.BoolRef, z3.BoolRef, z3.ExprRef | None]:
    """Instantiate a summary with concrete/symbolic arguments.
    Returns (precondition, postcondition, return_value).
    """
    subst: dict[z3.ExprRef, z3.ExprRef] = {}
    for i, param in enumerate(summary.parameters):
        if i < len(args):
            old_var = param.to_z3()
            subst[old_var] = args[i]
        elif param.name in kwargs:
            old_var = param.to_z3()
            subst[old_var] = kwargs[param.name]
        elif param.default_value is not None:
            old_var = param.to_z3()
            if isinstance(param.default_value, bool):
                subst[old_var] = ConstraintValues.bool(param.default_value)
            elif isinstance(param.default_value, int):
                subst[old_var] = ConstraintValues.int(param.default_value)
            elif isinstance(param.default_value, float):
                subst[old_var] = ConstraintValues.real(param.default_value)
            elif isinstance(param.default_value, str):
                subst[old_var] = ConstraintValues.string(param.default_value)
        else:
            msg = f"Missing required argument: '{param.name}'"
            raise TypeError(msg)

    fresh_return_var = None
    if summary.return_var is not None:
        sort = summary.return_var.sort()
        uid = call_id or str(next_address())
        fresh_name = f"{summary.name}_ret_{uid}"
        fresh_return_var = z3.Const(fresh_name, sort)
        subst[summary.return_var] = fresh_return_var

    subst_items: list[tuple[z3.ExprRef, z3.ExprRef]] = list(subst.items())

    pre_conds: list[z3.BoolRef] = []
    for cond in summary.preconditions:
        instantiated = z3.substitute(cond, *subst_items) if subst_items else cond
        pre_conds.append(instantiated)
    precondition = z3.And(*pre_conds) if pre_conds else Z3_TRUE

    post_conds: list[z3.BoolRef] = []
    for cond in summary.postconditions:
        instantiated = z3.substitute(cond, *subst_items) if subst_items else cond
        post_conds.append(instantiated)

    if summary.return_constraint is not None:
        instantiated_rc = (
            z3.substitute(summary.return_constraint, *subst_items)
            if subst_items
            else summary.return_constraint
        )
        post_conds.append(instantiated_rc)

    postcondition = z3.And(*post_conds) if post_conds else Z3_TRUE
    return precondition, postcondition, fresh_return_var
