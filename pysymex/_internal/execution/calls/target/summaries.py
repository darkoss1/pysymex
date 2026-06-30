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

"""Function-summary cache application for resolved call targets."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.runtime.summaries.instantiation import instantiate_summary
from pysymex._internal.analysis.runtime.summaries.types import FunctionSummary
from pysymex._internal.core.types.base import SymbolicNoneType
from pysymex._internal.core.types.scalars.values import SymbolicValue
from pysymex._internal.execution.calls.model.dispatch import (
    MAX_SUMMARY_CACHE_ARGS,
    MAX_SUMMARY_CACHE_CONSTRAINTS,
)
from pysymex._internal.execution.calls.value.coercion import to_z3_expr
from pysymex._internal.execution.dispatch.result import OpcodeResult

if TYPE_CHECKING:
    import z3

    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.calls.summary.protocols import SummaryCacheProtocol
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher
    from pysymex._internal.typing.protocols import StackValue


def dispatch_summary_call_target(
    state: VMState,
    ctx: OpcodeDispatcher,
    call_name: str,
    args: list[StackValue],
    kwargs: dict[str, StackValue],
) -> OpcodeResult | None:
    """Reuse a cached function summary when arguments and constraints are encodable."""
    if not ctx.cross_function:
        return None

    cache_obj = getattr(ctx.cross_function, "function_summary_cache", None)
    if cache_obj is None:
        return None
    cache = cast("SummaryCacheProtocol", cache_obj)
    path_constraints_snapshot = list(state.path_constraints)
    summary = None
    if (
        len(path_constraints_snapshot) <= MAX_SUMMARY_CACHE_CONSTRAINTS
        and len(args) <= MAX_SUMMARY_CACHE_ARGS
    ):
        summary = cache.get(call_name, args, path_constraints_snapshot)
    if not isinstance(summary, FunctionSummary):
        return None

    z3_args: list[z3.ExprRef] = []
    for arg in args:
        expr = to_z3_expr(arg)
        if expr is None:
            z3_args = []
            break
        z3_args.append(expr)

    z3_kwargs: dict[str, z3.ExprRef] = {}
    if z3_args:
        for key, value in kwargs.items():
            expr = to_z3_expr(value)
            if expr is None:
                z3_kwargs = {}
                z3_args = []
                break
            z3_kwargs[key] = expr

    if not z3_args:
        return None

    pre, post, ret_val = instantiate_summary(summary, z3_args, z3_kwargs)
    state = state.add_constraint(pre)
    state = state.add_constraint(post)
    if ret_val is None:
        state = state.push(SymbolicNoneType())
    else:
        state = state.push(SymbolicValue.from_z3(ret_val))
    state = state.advance_pc()
    return OpcodeResult.continue_with(state)
