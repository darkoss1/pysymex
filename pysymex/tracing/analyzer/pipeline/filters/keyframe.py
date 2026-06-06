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

import argparse

from pysymex.tracing.analyzer.helpers import (
    as_dict,
    as_list,
    as_str,
    constraints_contain,
    int_field_at_least,
    int_field_at_most,
    list_contains,
    str_contains,
)
from pysymex.tracing.analyzer.pipeline.core import FilterPipeline


def add_keyframe_filters(pipeline: FilterPipeline, args: argparse.Namespace) -> None:
    """Add keyframe event filters to a filter pipeline.

    Parses command-line arguments and appends filters to evaluate properties of
    keyframe events, such as trigger type, execution depth boundaries, parent path,
    presence of child forks, prune reasons, local/global variable names in scope,
    stack content, constraint text, and minimum/maximum path constraint count.

    Args:
        pipeline: The FilterPipeline instance to add filters to.
        args: Parsed command-line arguments containing filtering criteria.
    """
    if args.trigger:
        trg: str = args.trigger
        pipeline.add(lambda e, t=trg: e.get("trigger") == t)

    if args.depth is not None:
        d_exact: int = args.depth
        pipeline.add(lambda e, d=d_exact: e.get("depth") == d)

    if args.depth_min is not None:
        d_min: int = args.depth_min
        pipeline.add(lambda e, d=d_min: int_field_at_least(e, "depth", d))

    if args.depth_max is not None:
        d_max: int = args.depth_max
        pipeline.add(lambda e, d=d_max: int_field_at_most(e, "depth", d))

    if args.parent_path_id is not None:
        ppid: int = args.parent_path_id
        pipeline.add(lambda e, pp=ppid: e.get("parent_path_id") == pp)

    if args.has_child_fork:
        pipeline.add(lambda e: bool(e.get("child_path_ids")))

    if args.prune_reason:
        pr: str = args.prune_reason
        pipeline.add(lambda e, s=pr: str_contains(as_str(e.get("prune_reason")), s))

    if args.stack_contains:
        sc: str = args.stack_contains
        pipeline.add(lambda e, s=sc: list_contains(as_list(e.get("stack")), s))

    if args.local_var_name:
        lvn: str = args.local_var_name
        pipeline.add(lambda e, k=lvn: k in (as_dict(e.get("local_vars")) or {}))

    if args.global_var_name:
        gvn: str = args.global_var_name
        pipeline.add(lambda e, k=gvn: k in (as_dict(e.get("global_vars")) or {}))

    if args.constraint_smtlib_contains:
        csc: str = args.constraint_smtlib_contains
        pipeline.add(lambda e, s=csc: constraints_contain(as_list(e.get("path_constraints")), s))

    if args.num_path_constraints_min is not None:
        npcmin: int = args.num_path_constraints_min
        pipeline.add(lambda e, n=npcmin: len(as_list(e.get("path_constraints")) or []) >= n)

    if args.num_path_constraints_max is not None:
        npcmax: int = args.num_path_constraints_max
        pipeline.add(lambda e, n=npcmax: len(as_list(e.get("path_constraints")) or []) <= n)


__all__ = ["add_keyframe_filters"]
