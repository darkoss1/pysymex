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

"""Composable filter pipeline for execution trace logs."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.analyzer.pipeline.core import FilterPipeline
from pysymex._internal.tracing.analyzer.pipeline.filters.context import add_system_context_filters
from pysymex._internal.tracing.analyzer.pipeline.filters.deep import add_deep_filters
from pysymex._internal.tracing.analyzer.pipeline.filters.issue import add_issue_filters
from pysymex._internal.tracing.analyzer.pipeline.filters.keyframe import add_keyframe_filters
from pysymex._internal.tracing.analyzer.pipeline.filters.routing import add_routing_filters
from pysymex._internal.tracing.analyzer.pipeline.filters.solve import add_solve_filters
from pysymex._internal.tracing.analyzer.pipeline.filters.step import add_step_filters

if TYPE_CHECKING:
    from pysymex._internal.tracing.analyzer.pipeline.criteria import TraceFilterCriteria


def build_pipeline(config: TraceFilterCriteria) -> FilterPipeline:
    """Derive a :class:`FilterPipeline` from a tracing filter config.

    Each ``if config.<flag>:`` block appends exactly one :data:`FilterFn`
    closure.  The closures capture their argument value at build time so
    they are stateless and safe to call repeatedly.

    Args:
        config: Filter criteria selected by the caller.

    Returns:
        A :class:`FilterPipeline` ready for streaming evaluation.

    """
    pipeline = FilterPipeline()
    add_routing_filters(pipeline, config)
    add_step_filters(pipeline, config)
    add_keyframe_filters(pipeline, config)
    add_solve_filters(pipeline, config)
    add_issue_filters(pipeline, config)
    add_system_context_filters(pipeline, config)
    add_deep_filters(pipeline, config)
    return pipeline
