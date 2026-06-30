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

"""System context filters for trace analyzer pipelines."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.analyzer.predicates import TraceEventPredicates

if TYPE_CHECKING:
    from pysymex._internal.tracing.analyzer.pipeline.core import FilterPipeline
    from pysymex._internal.tracing.analyzer.pipeline.criteria import TraceFilterCriteria


def add_system_context_filters(pipeline: FilterPipeline, config: TraceFilterCriteria) -> None:
    """Add system context filters to a filter pipeline.

    Appends filters for function name substring, source file substring,
    pysymex version, and Z3 version.

    Args:
        pipeline: The FilterPipeline instance to add filters to.
        config: Filter criteria for system context events.

    """
    if config.function_name:
        fn_sub: str = config.function_name
        pipeline.add(
            lambda e, s=fn_sub: TraceEventPredicates.str_contains(
                TraceEventPredicates.as_str(e.get("function_name")),
                s,
            ),
        )

    if config.source_file:
        sf_sub: str = config.source_file
        pipeline.add(
            lambda e, s=sf_sub: TraceEventPredicates.str_contains(
                TraceEventPredicates.as_str(e.get("source_file")),
                s,
            ),
        )

    if config.pysymex_version:
        pv: str = config.pysymex_version
        pipeline.add(lambda e, v=pv: e.get("pysymex_version") == v)

    if config.z3_version:
        zv: str = config.z3_version
        pipeline.add(lambda e, v=zv: e.get("z3_version") == v)
