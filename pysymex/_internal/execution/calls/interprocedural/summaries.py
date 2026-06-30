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

"""Runtime summary-builder setup for interprocedural callees."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.analysis.runtime.summaries.builder import SummaryBuilder

if TYPE_CHECKING:
    from pysymex._internal.execution.calls.interprocedural.targets import InterproceduralTarget
    from pysymex._internal.execution.dispatch.dispatcher.core import OpcodeDispatcher


def build_interprocedural_summary(
    ctx: OpcodeDispatcher,
    target: InterproceduralTarget,
    pos_arg_names: tuple[str, ...],
    kwonly_arg_names: tuple[str, ...],
) -> SummaryBuilder | None:
    """Build a summary accumulator when cross-function caching is enabled."""
    if not (ctx.cross_function and hasattr(ctx.cross_function, "function_summary_cache")):
        return None

    builder = SummaryBuilder(target.func_name)
    builder.set_qualname(target.func_name)
    builder.set_initial_args(cast("list[object]", list(target.args)))
    for name in (*pos_arg_names, *kwonly_arg_names):
        builder.add_parameter(name)
    return builder
