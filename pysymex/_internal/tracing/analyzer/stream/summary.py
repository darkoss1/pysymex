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

"""Markdown rendering for accumulated trace stream summaries."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from pysymex._internal.tracing.analyzer.stream.types import (
        CountKeyT,
        CountStats,
        LatencyStats,
    )


class SummaryRenderSource(Protocol):
    """Read-only accumulator view consumed by summary rendering."""

    @property
    def total(self) -> int: ...

    @property
    def by_type(self) -> Mapping[str, int]: ...

    @property
    def first_seq(self) -> Mapping[str, int]: ...

    @property
    def last_seq(self) -> Mapping[str, int]: ...

    @property
    def latency_by_event_type(self) -> Mapping[str, LatencyStats]: ...

    @property
    def latency_by_path_id(self) -> Mapping[int, LatencyStats]: ...

    @property
    def step_latency_by_opcode(self) -> Mapping[str, LatencyStats]: ...

    @property
    def solve_results(self) -> Mapping[str, int]: ...

    @property
    def solve_cache_hits(self) -> int: ...

    @property
    def solve_cache_misses(self) -> int: ...

    @property
    def detector_query_outcomes(self) -> Mapping[tuple[str, str], CountStats]: ...

    @property
    def path_feasibility_outcomes(self) -> Mapping[tuple[str, str], CountStats]: ...

    @property
    def fallback_labels(self) -> Mapping[tuple[str, str], CountStats]: ...

    @property
    def uncertain_detector_sites(self) -> Mapping[tuple[int, int, str, str, str], CountStats]: ...


def render_summary(summary: SummaryRenderSource) -> str:
    """Render accumulated trace statistics as a Markdown summary table."""
    lines = [
        "# pysymex Trace Summary",
        f"Total matched events: {summary.total}",
        "",
        "| event_type      | count | first_seq | last_seq |",
        "|-----------------|-------|-----------|----------|",
    ]
    for event_type in sorted(summary.by_type):
        count = summary.by_type[event_type]
        first_seq = summary.first_seq.get(event_type, -1)
        last_seq = summary.last_seq.get(event_type, -1)
        lines.append(f"| {event_type:<15} | {count:>5} | {first_seq:>9} | {last_seq:>8} |")
    if summary.latency_by_event_type:
        lines.extend(
            [
                "",
                "## Latency Summary",
                "| event_type      | samples | total_ms | avg_ms | max_ms | max_seq |",
                "|-----------------|---------|----------|--------|--------|---------|",
            ],
        )
        for event_type in sorted(summary.latency_by_event_type):
            stats = summary.latency_by_event_type[event_type]
            lines.append(
                f"| {event_type:<15} | {stats.count:>7} | {stats.total_ms:>8.3f} | "
                f"{stats.avg_ms:>6.3f} | {stats.max_ms:>6.3f} | "
                f"{stats.max_seq if stats.max_seq is not None else -1:>7} |",
            )
    if summary.solve_results:
        total_solves = sum(summary.solve_results.values())
        lines.extend(
            [
                "",
                "## Solver Outcomes",
                f"Cache hits: {summary.solve_cache_hits}",
                f"Cache misses: {summary.solve_cache_misses}",
                f"Cache hit rate: {_cache_hit_rate(summary.solve_cache_hits, total_solves)}",
                "",
                "| result          | count |",
                "|-----------------|-------|",
            ],
        )
        for result in sorted(summary.solve_results):
            lines.append(f"| {result:<15} | {summary.solve_results[result]:>5} |")
    if summary.detector_query_outcomes:
        lines.extend(
            [
                "",
                "## Detector Query Outcomes",
                "| result_source                  | result | count | first_seq | last_seq |",
                "|--------------------------------|--------|-------|-----------|----------|",
            ],
        )
        for (result_source, result), stats in _rank_counts(summary.detector_query_outcomes):
            lines.append(
                f"| {result_source:<30} | {result:<6} | {stats.count:>5} | "
                f"{_seq(stats.first_seq):>9} | {_seq(stats.last_seq):>8} |",
            )
    if summary.path_feasibility_outcomes:
        lines.extend(
            [
                "",
                "## Path Feasibility Outcomes",
                "| result       | result_source             | count | first_seq | last_seq |",
                "|--------------|---------------------------|-------|-----------|----------|",
            ],
        )
        for (result, result_source), stats in _rank_counts(summary.path_feasibility_outcomes):
            lines.append(
                f"| {result:<12} | {result_source:<25} | {stats.count:>5} | "
                f"{_seq(stats.first_seq):>9} | {_seq(stats.last_seq):>8} |",
            )
    if summary.uncertain_detector_sites:
        lines.extend(
            [
                "",
                "## Uncertain Detector Sites",
                "| line | pc | detector | kind | result_source | count | first_seq | last_seq |",
                "|------|----|----------|------|---------------|-------|-----------|----------|",
            ],
        )
        ranked_sites = sorted(
            summary.uncertain_detector_sites.items(),
            key=lambda item: (-item[1].count, item[0]),
        )
        for (line, pc, detector, issue_kind, result_source), stats in ranked_sites[:10]:
            lines.append(
                f"| {line:>4} | {pc:>2} | {detector} | {issue_kind} | "
                f"{result_source} | {stats.count:>5} | "
                f"{_seq(stats.first_seq):>9} | {_seq(stats.last_seq):>8} |",
            )
    if summary.fallback_labels:
        lines.extend(
            [
                "",
                "## Fallback Labels",
                "| label | kind | count | first_seq | last_seq |",
                "|-------|------|-------|-----------|----------|",
            ],
        )
        for (label, kind), stats in _rank_counts(summary.fallback_labels):
            lines.append(
                f"| {label} | {kind} | {stats.count:>5} | "
                f"{_seq(stats.first_seq):>9} | {_seq(stats.last_seq):>8} |",
            )
    if summary.latency_by_path_id:
        lines.extend(
            [
                "",
                "## Slowest Paths",
                "| path_id | samples | total_ms | avg_ms | max_ms | max_seq |",
                "|---------|---------|----------|--------|--------|---------|",
            ],
        )
        ranked_paths = sorted(
            summary.latency_by_path_id.items(),
            key=lambda item: (-item[1].total_ms, item[0]),
        )
        for path_id, stats in ranked_paths[:10]:
            lines.append(
                f"| {path_id:>7} | {stats.count:>7} | {stats.total_ms:>8.3f} | "
                f"{stats.avg_ms:>6.3f} | {stats.max_ms:>6.3f} | "
                f"{stats.max_seq if stats.max_seq is not None else -1:>7} |",
            )
    if summary.step_latency_by_opcode:
        lines.extend(
            [
                "",
                "## Slowest Step Opcodes",
                "| opcode          | samples | total_ms | avg_ms | max_ms | max_seq |",
                "|-----------------|---------|----------|--------|--------|---------|",
            ],
        )
        ranked_opcodes = sorted(
            summary.step_latency_by_opcode.items(),
            key=lambda item: (-item[1].total_ms, item[0]),
        )
        for opcode, stats in ranked_opcodes[:10]:
            lines.append(
                f"| {opcode:<15} | {stats.count:>7} | {stats.total_ms:>8.3f} | "
                f"{stats.avg_ms:>6.3f} | {stats.max_ms:>6.3f} | "
                f"{stats.max_seq if stats.max_seq is not None else -1:>7} |",
            )
    return "\n".join(lines)


def _cache_hit_rate(cache_hits: int, total_solves: int) -> str:
    """Return a stable percentage string for the solver cache hit rate."""
    if total_solves == 0:
        return "0.0%"
    return f"{(cache_hits / total_solves) * 100.0:.1f}%"


def _seq(seq: int | None) -> int:
    """Return a printable sequence number sentinel."""
    return seq if seq is not None else -1


def _rank_counts(
    counts: Mapping[CountKeyT, CountStats],
) -> list[tuple[CountKeyT, CountStats]]:
    """Rank diagnostic buckets by count, then key for deterministic summaries."""
    return sorted(counts.items(), key=lambda item: (-item[1].count, str(item[0])))
