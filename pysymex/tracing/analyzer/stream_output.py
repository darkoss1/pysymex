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
from dataclasses import dataclass
from typing import TypeVar

from pysymex.tracing.analyzer.helpers import (
    as_float as _as_float,
    as_int as _as_int,
    as_str as _as_str,
)

_LATENCY_FIELDS = {
    "step": "step_latency_ms",
    "solve": "solver_latency_ms",
    "path_feasibility": "policy_latency_ms",
}
_UNCERTAIN_DETECTOR_QUERY_SOURCES = frozenset(
    {
        "inconclusive_prefix_unknown",
        "solver_unknown",
    }
)
_CountKeyT = TypeVar("_CountKeyT")


@dataclass
class _LatencyStats:
    """Aggregate latency samples for summary output."""

    count: int = 0
    total_ms: float = 0.0
    max_ms: float = 0.0
    max_seq: int | None = None

    def record(self, latency_ms: float, seq: int) -> None:
        """Record one latency sample."""
        self.count += 1
        self.total_ms += latency_ms
        if self.max_seq is None or latency_ms > self.max_ms:
            self.max_ms = latency_ms
            self.max_seq = seq

    @property
    def avg_ms(self) -> float:
        """Return the average latency in milliseconds."""
        if self.count == 0:
            return 0.0
        return self.total_ms / self.count


@dataclass
class _CountStats:
    """Count occurrences and sequence bounds for a diagnostic bucket."""

    count: int = 0
    first_seq: int | None = None
    last_seq: int | None = None

    def record(self, seq: int) -> None:
        """Record one occurrence."""
        self.count += 1
        if self.first_seq is None:
            self.first_seq = seq
        self.last_seq = seq


def format_pretty(event: dict[str, object]) -> str:
    """Two-space-indented JSON, suitable for human reading."""
    return json.dumps(event, indent=2, ensure_ascii=False)


def format_fields(event: dict[str, object], fields: list[str]) -> str:
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
        self.latency_by_event_type: dict[str, _LatencyStats] = collections.defaultdict(
            _LatencyStats
        )
        self.latency_by_path_id: dict[int, _LatencyStats] = collections.defaultdict(_LatencyStats)
        self.step_latency_by_opcode: dict[str, _LatencyStats] = collections.defaultdict(
            _LatencyStats
        )
        self.solve_results: dict[str, int] = collections.defaultdict(int)
        self.solve_cache_hits: int = 0
        self.solve_cache_misses: int = 0
        self.detector_query_outcomes: dict[tuple[str, str], _CountStats] = collections.defaultdict(
            _CountStats
        )
        self.path_feasibility_outcomes: dict[tuple[str, str], _CountStats] = (
            collections.defaultdict(_CountStats)
        )
        self.fallback_labels: dict[tuple[str, str], _CountStats] = collections.defaultdict(
            _CountStats
        )
        self.uncertain_detector_sites: dict[tuple[int, int, str, str, str], _CountStats] = (
            collections.defaultdict(_CountStats)
        )

    def record(self, event: dict[str, object]) -> None:
        """Record an event in the accumulator metrics."""
        et: str = _as_str(event.get("event_type")) or "unknown"
        seq_raw = _as_int(event.get("seq"))
        seq = seq_raw if seq_raw is not None else -1
        self.total += 1
        self.by_type[et] += 1
        if et not in self.first_seq:
            self.first_seq[et] = seq
        self.last_seq[et] = seq

        if et == "solve":
            solve_result = _as_str(event.get("result")) or "unknown"
            self.solve_results[solve_result] += 1
            if event.get("cache_hit") is True:
                self.solve_cache_hits += 1
            elif event.get("cache_hit") is False:
                self.solve_cache_misses += 1
        elif et == "detector_query":
            self._record_detector_query(event, seq)
        elif et == "path_feasibility":
            self._record_path_feasibility(event, seq)
        elif et == "fallback":
            self._record_fallback(event, seq)

        latency_field = _LATENCY_FIELDS.get(et)
        if latency_field is None:
            return
        latency_ms = _as_float(event.get(latency_field))
        if latency_ms is None:
            return

        self.latency_by_event_type[et].record(latency_ms, seq)
        path_id = _as_int(event.get("path_id"))
        if path_id is not None:
            self.latency_by_path_id[path_id].record(latency_ms, seq)
        if et == "step":
            opcode = _as_str(event.get("opcode")) or "UNKNOWN"
            self.step_latency_by_opcode[opcode].record(latency_ms, seq)

    def _record_detector_query(self, event: dict[str, object], seq: int) -> None:
        """Record detector-query outcomes and uncertain issue sites."""
        result_source = _as_str(event.get("result_source")) or "unknown"
        result = "true" if event.get("result") is True else "false"
        self.detector_query_outcomes[(result_source, result)].record(seq)

        if result != "false" or result_source not in _UNCERTAIN_DETECTOR_QUERY_SOURCES:
            return
        line = _as_int(event.get("source_line"))
        pc = _as_int(event.get("pc"))
        detector = _as_str(event.get("detector_name")) or "<unknown>"
        issue_kind = _as_str(event.get("issue_kind")) or "<unknown>"
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
        result = _as_str(event.get("result")) or "unknown"
        result_source = _as_str(event.get("result_source")) or "unknown"
        self.path_feasibility_outcomes[(result, result_source)].record(seq)

    def _record_fallback(self, event: dict[str, object], seq: int) -> None:
        """Record fallback labels and their kind."""
        label = _as_str(event.get("label")) or "<unknown>"
        kind = _as_str(event.get("kind")) or "<unknown>"
        self.fallback_labels[(label, kind)].record(seq)

    def render(self) -> str:
        """Render the accumulated statistics as a Markdown summary table."""
        lines = [
            "# pysymex Trace Summary",
            f"Total matched events: {self.total}",
            "",
            "| event_type      | count | first_seq | last_seq |",
            "|-----------------|-------|-----------|----------|",
        ]
        for et in sorted(self.by_type):
            cnt = self.by_type[et]
            fs = self.first_seq.get(et, -1)
            ls = self.last_seq.get(et, -1)
            lines.append(f"| {et:<15} | {cnt:>5} | {fs:>9} | {ls:>8} |")
        if self.latency_by_event_type:
            lines.extend(
                [
                    "",
                    "## Latency Summary",
                    "| event_type      | samples | total_ms | avg_ms | max_ms | max_seq |",
                    "|-----------------|---------|----------|--------|--------|---------|",
                ]
            )
            for et in sorted(self.latency_by_event_type):
                stats = self.latency_by_event_type[et]
                lines.append(
                    f"| {et:<15} | {stats.count:>7} | {stats.total_ms:>8.3f} | "
                    f"{stats.avg_ms:>6.3f} | {stats.max_ms:>6.3f} | "
                    f"{stats.max_seq if stats.max_seq is not None else -1:>7} |"
                )
        if self.solve_results:
            total_solves = sum(self.solve_results.values())
            lines.extend(
                [
                    "",
                    "## Solver Outcomes",
                    f"Cache hits: {self.solve_cache_hits}",
                    f"Cache misses: {self.solve_cache_misses}",
                    f"Cache hit rate: {self._cache_hit_rate(total_solves)}",
                    "",
                    "| result          | count |",
                    "|-----------------|-------|",
                ]
            )
            for result in sorted(self.solve_results):
                lines.append(f"| {result:<15} | {self.solve_results[result]:>5} |")
        if self.detector_query_outcomes:
            lines.extend(
                [
                    "",
                    "## Detector Query Outcomes",
                    "| result_source                  | result | count | first_seq | last_seq |",
                    "|--------------------------------|--------|-------|-----------|----------|",
                ]
            )
            for (result_source, result), stats in self._rank_counts(self.detector_query_outcomes):
                lines.append(
                    f"| {result_source:<30} | {result:<6} | {stats.count:>5} | "
                    f"{self._seq(stats.first_seq):>9} | {self._seq(stats.last_seq):>8} |"
                )
        if self.path_feasibility_outcomes:
            lines.extend(
                [
                    "",
                    "## Path Feasibility Outcomes",
                    "| result       | result_source             | count | first_seq | last_seq |",
                    "|--------------|---------------------------|-------|-----------|----------|",
                ]
            )
            for (result, result_source), stats in self._rank_counts(self.path_feasibility_outcomes):
                lines.append(
                    f"| {result:<12} | {result_source:<25} | {stats.count:>5} | "
                    f"{self._seq(stats.first_seq):>9} | {self._seq(stats.last_seq):>8} |"
                )
        if self.uncertain_detector_sites:
            lines.extend(
                [
                    "",
                    "## Uncertain Detector Sites",
                    "| line | pc | detector | kind | result_source | count | first_seq | last_seq |",
                    "|------|----|----------|------|---------------|-------|-----------|----------|",
                ]
            )
            ranked_sites = sorted(
                self.uncertain_detector_sites.items(),
                key=lambda item: (-item[1].count, item[0]),
            )
            for (line, pc, detector, issue_kind, result_source), stats in ranked_sites[:10]:
                lines.append(
                    f"| {line:>4} | {pc:>2} | {detector} | {issue_kind} | "
                    f"{result_source} | {stats.count:>5} | "
                    f"{self._seq(stats.first_seq):>9} | {self._seq(stats.last_seq):>8} |"
                )
        if self.fallback_labels:
            lines.extend(
                [
                    "",
                    "## Fallback Labels",
                    "| label | kind | count | first_seq | last_seq |",
                    "|-------|------|-------|-----------|----------|",
                ]
            )
            for (label, kind), stats in self._rank_counts(self.fallback_labels):
                lines.append(
                    f"| {label} | {kind} | {stats.count:>5} | "
                    f"{self._seq(stats.first_seq):>9} | {self._seq(stats.last_seq):>8} |"
                )
        if self.latency_by_path_id:
            lines.extend(
                [
                    "",
                    "## Slowest Paths",
                    "| path_id | samples | total_ms | avg_ms | max_ms | max_seq |",
                    "|---------|---------|----------|--------|--------|---------|",
                ]
            )
            ranked_paths = sorted(
                self.latency_by_path_id.items(),
                key=lambda item: (-item[1].total_ms, item[0]),
            )
            for path_id, stats in ranked_paths[:10]:
                lines.append(
                    f"| {path_id:>7} | {stats.count:>7} | {stats.total_ms:>8.3f} | "
                    f"{stats.avg_ms:>6.3f} | {stats.max_ms:>6.3f} | "
                    f"{stats.max_seq if stats.max_seq is not None else -1:>7} |"
                )
        if self.step_latency_by_opcode:
            lines.extend(
                [
                    "",
                    "## Slowest Step Opcodes",
                    "| opcode          | samples | total_ms | avg_ms | max_ms | max_seq |",
                    "|-----------------|---------|----------|--------|--------|---------|",
                ]
            )
            ranked_opcodes = sorted(
                self.step_latency_by_opcode.items(),
                key=lambda item: (-item[1].total_ms, item[0]),
            )
            for opcode, stats in ranked_opcodes[:10]:
                lines.append(
                    f"| {opcode:<15} | {stats.count:>7} | {stats.total_ms:>8.3f} | "
                    f"{stats.avg_ms:>6.3f} | {stats.max_ms:>6.3f} | "
                    f"{stats.max_seq if stats.max_seq is not None else -1:>7} |"
                )
        return "\n".join(lines)

    def _cache_hit_rate(self, total_solves: int) -> str:
        """Return a stable percentage string for the solver cache hit rate."""
        if total_solves == 0:
            return "0.0%"
        return f"{(self.solve_cache_hits / total_solves) * 100.0:.1f}%"

    def _seq(self, seq: int | None) -> int:
        """Return a printable sequence number sentinel."""
        return seq if seq is not None else -1

    def _rank_counts(
        self,
        counts: dict[_CountKeyT, _CountStats],
    ) -> list[tuple[_CountKeyT, _CountStats]]:
        """Rank diagnostic buckets by count, then key for deterministic summaries."""
        return sorted(counts.items(), key=lambda item: (-item[1].count, str(item[0])))
