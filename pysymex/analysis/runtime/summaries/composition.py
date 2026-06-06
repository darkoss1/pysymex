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

"""Compose function summaries at call sites for interprocedural analysis."""

from __future__ import annotations

import z3

from pysymex.analysis.runtime.summaries.instantiation import instantiate_summary
from pysymex.analysis.runtime.summaries.types import CallSite, FunctionSummary
from pysymex.core.solver.constraints.hashing import (
    get_bool_val,
    get_int_val,
    get_real_val,
    get_string_val,
)
from pysymex.logger import get_logger

logger = get_logger(__name__)


def _stable_unknown_name(*parts: object) -> str:
    raw = "_".join(str(part) for part in parts)
    return "".join(char if char.isalnum() or char == "_" else "_" for char in raw)


def compose_summaries(
    outer: FunctionSummary,
    call_site: CallSite,
    inner: FunctionSummary,
) -> FunctionSummary:
    """
    Compose an outer summary with an inner call.
    Creates a new summary for outer that incorporates the effects
    of calling inner.
    """
    result = outer.clone()
    for mod in inner.modified:
        if mod.scope in ("global", "nonlocal"):
            result.add_modified(mod)
    for exc in inner.may_raise:
        result.add_exception(exc)
    if not inner.is_pure:
        result.is_pure = False
    if not inner.is_deterministic:
        result.is_deterministic = False

    def to_z3_expr(val: object) -> z3.ExprRef | None:
        if isinstance(val, z3.ExprRef):
            return val
        if isinstance(val, bool):
            return get_bool_val(val)
        if isinstance(val, int):
            return get_int_val(val)
        if isinstance(val, float):
            return get_real_val(val)
        if isinstance(val, str):
            return get_string_val(val)
        return None

    z3_args: list[z3.ExprRef] = []
    for i, arg in enumerate(call_site.args):
        z3_expr = to_z3_expr(arg)
        if z3_expr is not None:
            z3_args.append(z3_expr)
        else:
            z3_args.append(
                z3.Int(
                    _stable_unknown_name(
                        outer.name, call_site.callee, call_site.pc, "unknown_arg", i
                    )
                )
            )

    z3_kwargs: dict[str, z3.ExprRef] = {}
    for k, arg in call_site.kwargs.items():
        z3_expr = to_z3_expr(arg)
        if z3_expr is not None:
            z3_kwargs[k] = z3_expr
        else:
            z3_kwargs[k] = z3.Int(
                _stable_unknown_name(outer.name, call_site.callee, call_site.pc, "unknown_kwarg", k)
            )

    try:
        call_id = _stable_unknown_name(outer.name, call_site.callee, call_site.pc, "ret")
        pre, post, _ = instantiate_summary(inner, z3_args, z3_kwargs, call_id=call_id)
        if not z3.is_true(pre):
            result.add_precondition(pre)
        if not z3.is_true(post):
            result.add_postcondition(post)
    except TypeError:
        logger.debug("Failed to instantiate function summary during composition", exc_info=True)

    return result
