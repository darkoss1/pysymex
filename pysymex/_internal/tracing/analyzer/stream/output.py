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

"""Output formatting and summary accumulation for trace streams."""

from __future__ import annotations

import collections
import json

from pysymex._internal.tracing.analyzer.predicates import TraceEventPredicates
from pysymex._internal.tracing.analyzer.stream.summary import render_summary
from pysymex._internal.tracing.analyzer.stream.types import CountStats, LatencyStats

_LATENCY_FIELDS = {
    "step": "step_latency_ms",
    "solve": "solver_latency_ms",
    "path_feasibility": "policy_latency_ms",
}
_UNCERTAIN_DETECTOR_QUERY_SOURCES = frozenset(
    (
        "inconclusive_prefix_unknown",
        "solver_unknown",
    ),
)


def _pretty(event: dict[str, object]) -> str:
    """Two-space-indented JSON, suitable for human reading."""
    return json.dumps(event, indent=2, ensure_ascii=False)


def _fields(event: dict[str, object], fields: list[str]) -> str:
    """Emit only the requested top-level *fields* as a JSONL object."""
    subset = {f: event[f] for f in fields if f in event}
    return json.dumps(subset, ensure_ascii=False)


class SummaryAccumulator:
    """Accumulate lightweight statistics across matched events."""

    def __init__(self) -> None:
        """Initialize summary counters."""
        self.total: int = 0
        self.by_type: dict[str, int] = collections.defaultdict(int)
        self.first_seq: dict[str, int] = {}
        self.last_seq: dict[str, int] = {}
        self.latency_by_event_type: dict[str, LatencyStats] = collections.defaultdict(LatencyStats)
        self.latency_by_path_id: dict[int, LatencyStats] = collections.defaultdict(LatencyStats)
        self.step_latency_by_opcode: dict[str, LatencyStats] = collections.defaultdict(LatencyStats)
        self.solve_results: dict[str, int] = collections.defaultdict(int)
        self.solve_cache_hits: int = 0
        self.solve_cache_misses: int = 0
        self.detector_query_outcomes: dict[tuple[str, str], CountStats] = collections.defaultdict(
            CountStats,
        )
        self.path_feasibility_outcomes: dict[tuple[str, str], CountStats] = collections.defaultdict(
            CountStats,
        )
        self.fallback_labels: dict[tuple[str, str], CountStats] = collections.defaultdict(
            CountStats,
        )
        self.uncertain_detector_sites: dict[tuple[int, int, str, str, str], CountStats] = (
            collections.defaultdict(CountStats)
        )

    def record(self, event: dict[str, object]) -> None:
        """Record an event in the accumulator metrics."""
        event_type: str = TraceEventPredicates.as_str(event.get("event_type")) or "unknown"
        seq_raw = TraceEventPredicates.as_int(event.get("seq"))
        seq = seq_raw if seq_raw is not None else -1
        self.total += 1
        self.by_type[event_type] += 1
        if event_type not in self.first_seq:
            self.first_seq[event_type] = seq
        self.last_seq[event_type] = seq

        if event_type == "solve":
            solve_result = TraceEventPredicates.as_str(event.get("result")) or "unknown"
            self.solve_results[solve_result] += 1
            if event.get("cache_hit") is True:
                self.solve_cache_hits += 1
            elif event.get("cache_hit") is False:
                self.solve_cache_misses += 1
        elif event_type == "detector_query":
            self._record_detector_query(event, seq)
        elif event_type == "path_feasibility":
            self._record_path_feasibility(event, seq)
        elif event_type == "fallback":
            self._record_fallback(event, seq)

        latency_field = _LATENCY_FIELDS.get(event_type)
        if latency_field is None:
            return
        latency_ms = TraceEventPredicates.as_float(event.get(latency_field))
        if latency_ms is None:
            return

        self.latency_by_event_type[event_type].record(latency_ms, seq)
        path_id = TraceEventPredicates.as_int(event.get("path_id"))
        if path_id is not None:
            self.latency_by_path_id[path_id].record(latency_ms, seq)
        if event_type == "step":
            opcode = TraceEventPredicates.as_str(event.get("opcode")) or "UNKNOWN"
            self.step_latency_by_opcode[opcode].record(latency_ms, seq)

    def _record_detector_query(self, event: dict[str, object], seq: int) -> None:
        """Record detector-query outcomes and uncertain issue sites."""
        result_source = TraceEventPredicates.as_str(event.get("result_source")) or "unknown"
        result = "true" if event.get("result") is True else "false"
        self.detector_query_outcomes[(result_source, result)].record(seq)

        if result != "false" or result_source not in _UNCERTAIN_DETECTOR_QUERY_SOURCES:
            return
        line = TraceEventPredicates.as_int(event.get("source_line"))
        pc = TraceEventPredicates.as_int(event.get("pc"))
        detector = TraceEventPredicates.as_str(event.get("detector_name")) or "<unknown>"
        issue_kind = TraceEventPredicates.as_str(event.get("issue_kind")) or "<unknown>"
        site_key = (
            line if line is not None else -1,
            pc if pc is not None else -1,
            detector,
            issue_kind,
            result_source,
        )
        self.uncertain_detector_sites[site_key].record(seq)

    def _record_path_feasibility(self, event: dict[str, object], seq: int) -> None:
        """Record path-feasibility policy outcomes."""
        result = TraceEventPredicates.as_str(event.get("result")) or "unknown"
        result_source = TraceEventPredicates.as_str(event.get("result_source")) or "unknown"
        self.path_feasibility_outcomes[(result, result_source)].record(seq)

    def _record_fallback(self, event: dict[str, object], seq: int) -> None:
        """Record fallback labels and their kind."""
        label = TraceEventPredicates.as_str(event.get("label")) or "<unknown>"
        kind = TraceEventPredicates.as_str(event.get("kind")) or "<unknown>"
        self.fallback_labels[(label, kind)].record(seq)

    def render(self) -> str:
        """Render the accumulated statistics as a Markdown summary table."""
        return render_summary(self)


class TraceEventFormat:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    pretty = staticmethod(_pretty)
    fields = staticmethod(_fields)
