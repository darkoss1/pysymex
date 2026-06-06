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

import argparse

from pysymex.tracing.analyzer.pipeline.filters.context import add_system_context_filters
from pysymex.tracing.analyzer.pipeline.core import FilterFn
from pysymex.tracing.analyzer.pipeline.core import FilterPipeline
from pysymex.tracing.analyzer.pipeline.filters.deep import add_deep_filters
from pysymex.tracing.analyzer.pipeline.filters.issue import add_issue_filters
from pysymex.tracing.analyzer.pipeline.filters.keyframe import add_keyframe_filters
from pysymex.tracing.analyzer.pipeline.filters.routing import add_routing_filters
from pysymex.tracing.analyzer.pipeline.filters.solve import add_solve_filters
from pysymex.tracing.analyzer.pipeline.filters.step import add_step_filters


def build_pipeline(args: argparse.Namespace) -> FilterPipeline:
    """Derive a :class:`FilterPipeline` from parsed CLI arguments.

    Each ``if args.<flag>:`` block appends exactly one :data:`FilterFn`
    closure.  The closures capture their argument value at build time so
    they are stateless and safe to call repeatedly.

    Args:
        args: The result of :func:`argparse.ArgumentParser.parse_args`.

    Returns:
        A :class:`FilterPipeline` ready for streaming evaluation.
    """
    pipeline = FilterPipeline()
    add_routing_filters(pipeline, args)
    add_step_filters(pipeline, args)
    add_keyframe_filters(pipeline, args)
    add_solve_filters(pipeline, args)
    add_issue_filters(pipeline, args)
    add_system_context_filters(pipeline, args)
    add_deep_filters(pipeline, args)
    return pipeline


__all__ = ["FilterFn", "FilterPipeline", "build_pipeline"]
