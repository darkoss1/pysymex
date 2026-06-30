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

from typing import TYPE_CHECKING

from pysymex._internal.tracing.analyzer.predicates import TraceEventPredicates

if TYPE_CHECKING:
    from pysymex._internal.tracing.analyzer.pipeline.core import FilterPipeline
    from pysymex._internal.tracing.analyzer.pipeline.criteria import TraceFilterCriteria


def add_routing_filters(pipeline: FilterPipeline, config: TraceFilterCriteria) -> None:
    """Add routing-related filters to the trace analyzer pipeline.

    Args:
        pipeline: The FilterPipeline instance to register filters on.
        config: Filter criteria for event type, sequence, path ID, and program counter.

    """
    if config.event_type:
        allowed: frozenset[str] = frozenset(config.event_type)
        pipeline.add(lambda e, a=allowed: e.get("event_type") in a)

    if config.seq is not None:
        target_seq: int = config.seq
        pipeline.add(lambda e, s=target_seq: e.get("seq") == s)

    if config.seq_range:
        lo, hi = config.seq_range
        pipeline.add(
            lambda e, lo=lo, hi=hi: TraceEventPredicates.int_field_in_range(e, "seq", lo, hi),
        )

    if config.path_id is not None:
        target_pid: int = config.path_id
        pipeline.add(lambda e, pid=target_pid: e.get("path_id") == pid)

    if config.path_id_list:
        allowed_pids: frozenset[int] = frozenset(config.path_id_list)
        pipeline.add(lambda e, ps=allowed_pids: e.get("path_id") in ps)

    if config.pc is not None:
        target_pc: int = config.pc
        pipeline.add(lambda e, pc=target_pc: e.get("pc") == pc)

    if config.pc_range:
        pc_lo, pc_hi = config.pc_range
        pipeline.add(
            lambda e, lo=pc_lo, hi=pc_hi: TraceEventPredicates.int_field_in_range(e, "pc", lo, hi),
        )
