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

"""Keyframe event filters for trace analyzer pipelines."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.analyzer.predicates import TraceEventPredicates

if TYPE_CHECKING:
    from pysymex._internal.tracing.analyzer.pipeline.core import FilterPipeline
    from pysymex._internal.tracing.analyzer.pipeline.criteria import TraceFilterCriteria


def add_keyframe_filters(pipeline: FilterPipeline, config: TraceFilterCriteria) -> None:
    """Add keyframe event filters to a filter pipeline.

    Appends filters for trigger type, execution depth boundaries, parent path,
    child forks, prune reasons, variables in scope, stack content, constraint
    text, and path constraint counts.

    Args:
        pipeline: The FilterPipeline instance to add filters to.
        config: Filter criteria for keyframe events.

    """
    if config.trigger:
        trg: str = config.trigger
        pipeline.add(lambda e, t=trg: e.get("trigger") == t)

    if config.depth is not None:
        d_exact: int = config.depth
        pipeline.add(lambda e, d=d_exact: e.get("depth") == d)

    if config.depth_min is not None:
        d_min: int = config.depth_min
        pipeline.add(lambda e, d=d_min: TraceEventPredicates.int_field_at_least(e, "depth", d))

    if config.depth_max is not None:
        d_max: int = config.depth_max
        pipeline.add(lambda e, d=d_max: TraceEventPredicates.int_field_at_most(e, "depth", d))

    if config.parent_path_id is not None:
        ppid: int = config.parent_path_id
        pipeline.add(lambda e, pp=ppid: e.get("parent_path_id") == pp)

    if config.has_child_fork:
        pipeline.add(lambda e: bool(e.get("child_path_ids")))

    if config.prune_reason:
        pr: str = config.prune_reason
        pipeline.add(
            lambda e, s=pr: TraceEventPredicates.str_contains(
                TraceEventPredicates.as_str(e.get("prune_reason")),
                s,
            ),
        )

    if config.stack_contains:
        sc: str = config.stack_contains
        pipeline.add(
            lambda e, s=sc: TraceEventPredicates.list_contains(
                TraceEventPredicates.as_list(e.get("stack")),
                s,
            ),
        )

    if config.local_var_name:
        lvn: str = config.local_var_name
        pipeline.add(
            lambda e, k=lvn: k in (TraceEventPredicates.as_dict(e.get("local_vars")) or {}),
        )

    if config.global_var_name:
        gvn: str = config.global_var_name
        pipeline.add(
            lambda e, k=gvn: k in (TraceEventPredicates.as_dict(e.get("global_vars")) or {}),
        )

    if config.constraint_smtlib_contains:
        csc: str = config.constraint_smtlib_contains
        pipeline.add(
            lambda e, s=csc: TraceEventPredicates.constraints_contain(
                TraceEventPredicates.as_list(e.get("path_constraints")),
                s,
            ),
        )

    if config.num_path_constraints_min is not None:
        npcmin: int = config.num_path_constraints_min
        pipeline.add(
            lambda e, n=npcmin: (
                len(TraceEventPredicates.as_list(e.get("path_constraints")) or []) >= n
            ),
        )

    if config.num_path_constraints_max is not None:
        npcmax: int = config.num_path_constraints_max
        pipeline.add(
            lambda e, n=npcmax: (
                len(TraceEventPredicates.as_list(e.get("path_constraints")) or []) <= n
            ),
        )
