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

import argparse

from pysymex.tracing.analyzer.helpers import (
    as_dict,
    as_list,
    as_str,
    float_field_at_least,
    float_field_at_most,
    has_stack_pop,
    str_contains,
)
from pysymex.tracing.analyzer.pipeline.core import FilterPipeline


def add_step_filters(pipeline: FilterPipeline, args: argparse.Namespace) -> None:
    """Add execution step filters to the trace analyzer pipeline based on CLI arguments.

    Registers filters that restrict events to specific step attributes. Matches
    steps based on opcode name, source code line number, stack modifications (push/pop),
    variable additions/modifications/removals, memory writes, or constraint additions
    including causal opcodes matching a specific substring.

    Args:
        pipeline: The FilterPipeline instance to register filters on.
        args: Command-line arguments containing step filtering criteria.
    """
    if args.opcode:
        oc: str = args.opcode.upper()
        pipeline.add(lambda e, o=oc: (as_str(e.get("opcode")) or "").upper() == o)

    if args.source_line is not None:
        sl: int = args.source_line
        pipeline.add(lambda e, s=sl: e.get("source_line") == s)

    if args.step_latency_min is not None:
        latency_min: float = args.step_latency_min
        pipeline.add(lambda e, ms=latency_min: float_field_at_least(e, "step_latency_ms", ms))

    if args.step_latency_max is not None:
        latency_max: float = args.step_latency_max
        pipeline.add(lambda e, ms=latency_max: float_field_at_most(e, "step_latency_ms", ms))

    if args.has_stack_push:
        pipeline.add(lambda e: bool((as_dict(e.get("stack_diff")) or {}).get("pushed")))

    if args.has_stack_pop:
        pipeline.add(has_stack_pop)

    if args.has_var_modified:
        pipeline.add(lambda e: bool((as_dict(e.get("var_diff")) or {}).get("modified")))

    if args.var_modified_name:
        vmn: str = args.var_modified_name
        pipeline.add(
            lambda e, k=vmn: (
                k in (as_dict((as_dict(e.get("var_diff")) or {}).get("modified")) or {})
            )
        )

    if args.has_var_added:
        pipeline.add(lambda e: bool((as_dict(e.get("var_diff")) or {}).get("added")))

    if args.var_added_name:
        van: str = args.var_added_name
        pipeline.add(
            lambda e, k=van: k in (as_dict((as_dict(e.get("var_diff")) or {}).get("added")) or {})
        )

    if args.has_var_removed:
        pipeline.add(lambda e: bool((as_dict(e.get("var_diff")) or {}).get("removed")))

    if args.var_removed_name:
        vrn: str = args.var_removed_name
        pipeline.add(
            lambda e, k=vrn: k in (as_list((as_dict(e.get("var_diff")) or {}).get("removed")) or [])
        )

    if args.has_mem_write:
        pipeline.add(lambda e: bool(e.get("mem_diff")))

    if args.has_constraint_added:
        pipeline.add(lambda e: e.get("constraint_added") is not None)

    if args.constraint_causality_contains:
        ccc: str = args.constraint_causality_contains
        pipeline.add(
            lambda e, s=ccc: str_contains(
                as_str((as_dict(e.get("constraint_added")) or {}).get("causality")),
                s,
            )
        )


__all__ = ["add_step_filters"]
