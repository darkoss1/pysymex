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

"""Common event routing filters for trace analyzer pipelines."""

from __future__ import annotations

import argparse

from pysymex.tracing.analyzer.helpers import int_field_in_range
from pysymex.tracing.analyzer.pipeline.core import FilterPipeline


def add_routing_filters(pipeline: FilterPipeline, args: argparse.Namespace) -> None:
    """Add routing-related filters to the trace analyzer pipeline based on CLI arguments.

    Inspects the provided command-line arguments and registers filters with the pipeline
    to restrict events by their event type, sequence number, path ID, or program counter (PC).

    Args:
        pipeline: The FilterPipeline instance to register filters on.
        args: Command-line arguments containing filtering criteria.
    """
    if args.event_type:
        allowed: frozenset[str] = frozenset(args.event_type)
        pipeline.add(lambda e, a=allowed: e.get("event_type") in a)

    if args.seq is not None:
        target_seq: int = args.seq
        pipeline.add(lambda e, s=target_seq: e.get("seq") == s)

    if args.seq_range:
        lo, hi = args.seq_range
        pipeline.add(lambda e, lo=lo, hi=hi: int_field_in_range(e, "seq", lo, hi))

    if args.path_id is not None:
        target_pid: int = args.path_id
        pipeline.add(lambda e, pid=target_pid: e.get("path_id") == pid)

    if args.path_id_list:
        allowed_pids: frozenset[int] = frozenset(args.path_id_list)
        pipeline.add(lambda e, ps=allowed_pids: e.get("path_id") in ps)

    if args.pc is not None:
        target_pc: int = args.pc
        pipeline.add(lambda e, pc=target_pc: e.get("pc") == pc)

    if args.pc_range:
        pc_lo, pc_hi = args.pc_range
        pipeline.add(lambda e, lo=pc_lo, hi=pc_hi: int_field_in_range(e, "pc", lo, hi))


__all__ = ["add_routing_filters"]
