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

"""Solver telemetry filters for trace analyzer pipelines."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.analyzer.predicates import TraceEventPredicates

if TYPE_CHECKING:
    from pysymex._internal.tracing.analyzer.pipeline.core import FilterPipeline
    from pysymex._internal.tracing.analyzer.pipeline.criteria import TraceFilterCriteria


def add_solve_filters(pipeline: FilterPipeline, config: TraceFilterCriteria) -> None:
    """Add solver telemetry filters to the trace analyzer pipeline.

    Allows filtering trace events by solve result (sat/unsat/unknown), cache hit
    status, solver latency range, constraint count range, presence of a model
    excerpt, or the presence of specific variable names in the model.

    Args:
        pipeline: The FilterPipeline instance to register filters on.
        config: Filter criteria for solver telemetry events.

    """
    if config.solve_result:
        sr: str = config.solve_result
        pipeline.add(lambda e, r=sr: e.get("result") == r)

    if config.cache_hit:
        pipeline.add(lambda e: e.get("cache_hit") is True)

    if config.cache_miss:
        pipeline.add(lambda e: e.get("cache_hit") is False)

    if config.solver_latency_min is not None:
        slmin: float = config.solver_latency_min
        pipeline.add(
            lambda e, ms=slmin: TraceEventPredicates.float_field_at_least(
                e,
                "solver_latency_ms",
                ms,
            ),
        )

    if config.solver_latency_max is not None:
        slmax: float = config.solver_latency_max
        pipeline.add(
            lambda e, ms=slmax: TraceEventPredicates.float_field_at_most(
                e,
                "solver_latency_ms",
                ms,
            ),
        )

    if config.num_constraints_min is not None:
        ncmin: int = config.num_constraints_min
        pipeline.add(
            lambda e, n=ncmin: TraceEventPredicates.int_field_at_least(e, "num_constraints", n),
        )

    if config.num_constraints_max is not None:
        ncmax: int = config.num_constraints_max
        pipeline.add(
            lambda e, n=ncmax: TraceEventPredicates.int_field_at_most(e, "num_constraints", n),
        )

    if config.has_model_excerpt:
        pipeline.add(lambda e: e.get("model_excerpt") is not None)

    if config.model_var_name:
        mvn: str = config.model_var_name
        pipeline.add(
            lambda e, k=mvn: k in (TraceEventPredicates.as_dict(e.get("model_excerpt")) or {}),
        )
