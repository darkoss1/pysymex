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

"""Build and cache interprocedural summaries from successful return paths.

Canonicalizes symbolic parameters in returned expressions and path constraints before
placing a bounded summary into the cross-function cache.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

import z3

from pysymex._internal.analysis.runtime.summaries.builder import SummaryBuilder
from pysymex._internal.core.types.scalars.values import SymbolicValue

if TYPE_CHECKING:
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.core.state.types import CallFrame
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher

_MAX_SUMMARY_CACHE_CONSTRAINTS = 24
_MAX_SUMMARY_CACHE_ARGS = 12


@runtime_checkable
class _SummaryCacheProtocol(Protocol):
    """Cross-function summary cache surface used on return paths."""

    def put(
        self,
        func_name: str,
        args: list[object],
        path_constraints: list[z3.BoolRef],
        summary: object,
    ) -> None:
        """Store a return summary keyed by function name, args, and path constraints."""
        ...


@runtime_checkable
class _CrossFunctionProtocol(Protocol):
    function_summary_cache: _SummaryCacheProtocol


def store_return_summary_if_supported(
    frame: CallFrame,
    return_value: object | None,
    state: VMState,
    ctx: OpcodeDispatcher,
) -> None:
    """Store a canonicalized return summary when the active frame supports summaries."""
    if not isinstance(frame.summary_builder, SummaryBuilder):
        return

    builder = frame.summary_builder
    initial_args = builder.initial_args
    cross_function = ctx.cross_function

    if not isinstance(cross_function, _CrossFunctionProtocol):
        return

    constraints = list(state.path_constraints)
    summary_constraints = constraints
    summary = builder.build()

    param_map: list[tuple[z3.ExprRef, z3.ExprRef]] = []
    for i, arg in enumerate(initial_args):
        if isinstance(arg, SymbolicValue):
            param_info = summary.parameters[i] if i < len(summary.parameters) else None
            if param_info:
                param_z3 = param_info.to_z3()
                param_map.append((arg.z3_int, param_z3))

    canonical_return = return_value

    if isinstance(return_value, SymbolicValue):
        new_z3_int = z3.substitute(return_value.z3_int, *param_map)
        new_z3_bool = z3.substitute(return_value.z3_bool, *param_map)

        canonical_return = SymbolicValue(
            _name=return_value.name,
            z3_int=new_z3_int,
            is_int=return_value.is_int,
            z3_bool=new_z3_bool,
            is_bool=return_value.is_bool,
        )

    summary.return_var = (
        canonical_return.z3_int if isinstance(canonical_return, SymbolicValue) else None
    )

    canonical_constraints: list[z3.BoolRef] = []
    for constraint in summary_constraints:
        canonical_constraints.append(z3.substitute(constraint, *param_map))

    summary.postconditions = canonical_constraints

    if (
        len(constraints) <= _MAX_SUMMARY_CACHE_CONSTRAINTS
        and len(initial_args) <= _MAX_SUMMARY_CACHE_ARGS
    ):
        cross_function.function_summary_cache.put(
            getattr(builder.summary, "name", "unknown"),
            initial_args,
            constraints,
            summary,
        )
