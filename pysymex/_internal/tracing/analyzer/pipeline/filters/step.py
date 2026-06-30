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

"""Step event filters for trace analyzer pipelines."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.analyzer.predicates import TraceEventPredicates

if TYPE_CHECKING:
    from pysymex._internal.tracing.analyzer.pipeline.core import FilterPipeline
    from pysymex._internal.tracing.analyzer.pipeline.criteria import TraceFilterCriteria


def add_step_filters(pipeline: FilterPipeline, config: TraceFilterCriteria) -> None:
    """Add execution step filters to the trace analyzer pipeline.

    Registers filters that restrict events to specific step attributes. Matches
    steps based on opcode name, source code line number, stack modifications (push/pop),
    variable additions/modifications/removals, memory writes, or constraint additions
    including causal opcodes matching a specific substring.

    Args:
        pipeline: The FilterPipeline instance to register filters on.
        config: Filter criteria for step event attributes.

    """
    if config.opcode:
        oc: str = config.opcode.upper()
        pipeline.add(
            lambda e, o=oc: (TraceEventPredicates.as_str(e.get("opcode")) or "").upper() == o,
        )

    if config.source_line is not None:
        sl: int = config.source_line
        pipeline.add(lambda e, s=sl: e.get("source_line") == s)

    if config.step_latency_min is not None:
        latency_min: float = config.step_latency_min
        pipeline.add(
            lambda e, ms=latency_min: TraceEventPredicates.float_field_at_least(
                e,
                "step_latency_ms",
                ms,
            ),
        )

    if config.step_latency_max is not None:
        latency_max: float = config.step_latency_max
        pipeline.add(
            lambda e, ms=latency_max: TraceEventPredicates.float_field_at_most(
                e,
                "step_latency_ms",
                ms,
            ),
        )

    if config.has_stack_push:
        pipeline.add(
            lambda e: bool((TraceEventPredicates.as_dict(e.get("stack_diff")) or {}).get("pushed")),
        )

    if config.has_stack_pop:
        pipeline.add(
            lambda e: bool((TraceEventPredicates.as_dict(e.get("stack_diff")) or {}).get("popped")),
        )

    if config.has_var_modified:
        pipeline.add(
            lambda e: bool((TraceEventPredicates.as_dict(e.get("var_diff")) or {}).get("modified")),
        )

    if config.var_modified_name:
        vmn: str = config.var_modified_name
        pipeline.add(
            lambda e, k=vmn: (
                k
                in (
                    TraceEventPredicates.as_dict(
                        (TraceEventPredicates.as_dict(e.get("var_diff")) or {}).get("modified"),
                    )
                    or {}
                )
            ),
        )

    if config.has_var_added:
        pipeline.add(
            lambda e: bool((TraceEventPredicates.as_dict(e.get("var_diff")) or {}).get("added")),
        )

    if config.var_added_name:
        van: str = config.var_added_name
        pipeline.add(
            lambda e, k=van: (
                k
                in (
                    TraceEventPredicates.as_dict(
                        (TraceEventPredicates.as_dict(e.get("var_diff")) or {}).get("added"),
                    )
                    or {}
                )
            ),
        )

    if config.has_var_removed:
        pipeline.add(
            lambda e: bool((TraceEventPredicates.as_dict(e.get("var_diff")) or {}).get("removed")),
        )

    if config.var_removed_name:
        vrn: str = config.var_removed_name
        pipeline.add(
            lambda e, k=vrn: (
                k
                in (
                    TraceEventPredicates.as_list(
                        (TraceEventPredicates.as_dict(e.get("var_diff")) or {}).get("removed"),
                    )
                    or []
                )
            ),
        )

    if config.has_mem_write:
        pipeline.add(lambda e: bool(e.get("mem_diff")))

    if config.has_constraint_added:
        pipeline.add(lambda e: e.get("constraint_added") is not None)

    if config.constraint_causality_contains:
        ccc: str = config.constraint_causality_contains
        pipeline.add(
            lambda e, s=ccc: TraceEventPredicates.str_contains(
                TraceEventPredicates.as_str(
                    (TraceEventPredicates.as_dict(e.get("constraint_added")) or {}).get(
                        "causality",
                    ),
                ),
                s,
            ),
        )
