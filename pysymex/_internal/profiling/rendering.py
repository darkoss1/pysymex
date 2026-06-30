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

"""Persist and render typed scan profile reports."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.profiling.hotspots import ProfileHotspot
    from pysymex._internal.profiling.model import MetricDelta, ScanProfileReport


def _write_summary(report: ScanProfileReport, output_dir: str | Path) -> Path:
    """Write the machine-readable profile summary and return its path."""
    target_dir = Path(output_dir)
    target_dir.mkdir(parents=True, exist_ok=True)
    stem = report.profile_run.stats_path.stem if report.profile_run is not None else "scan-profile"
    summary_path = target_dir / f"{stem}.json"
    if report.profile_run is not None and summary_path == report.profile_run.stats_path:
        summary_path = target_dir / f"{stem}.summary.json"
    report_with_path = report.with_summary_path(summary_path)
    summary_path.write_text(
        json.dumps(report_with_path.to_dict(), indent=2, sort_keys=True),
        encoding="utf-8",
    )
    return summary_path


def _format(report: ScanProfileReport) -> str:
    """Return the deterministic human-facing profile report."""
    aggregate = report.aggregate
    lines = [
        "Developer Profile",
        "Overview",
        f"  files scanned: {aggregate.files_scanned}",
        f"  code objects: {aggregate.code_objects}",
        f"  CLI wall time: {aggregate.wall_time_seconds:.3f} s",
        f"  measured scan time: {aggregate.scan_elapsed_seconds:.3f} s",
        f"  profiler session: {aggregate.profiled_seconds:.3f} s",
        f"  profiler/CLI coverage: {aggregate.profile_coverage_ratio:.1%}",
        f"  measured paths/sec: {aggregate.path_rate:.2f}",
    ]
    lines.extend(_format_environment(report))
    lines.extend(
        [
            "Path and Solver Pressure",
            f"  paths explored: {aggregate.paths_explored}",
            f"  paths pruned: {aggregate.paths_pruned}",
            f"  prune ratio: {aggregate.pruned_ratio:.1%}",
            f"  logical solver queries: {aggregate.logical_solver_queries}",
            f"  physical Z3 checks: {aggregate.solver_calls}",
            f"  solver calls/path: {aggregate.solver_calls_per_path:.2f}",
            f"  solver outcomes: sat={aggregate.solver_sat}, unsat={aggregate.solver_unsat}, "
            f"unknown/timeout={aggregate.solver_unknown}",
            f"  solver time: {aggregate.solver_time_ms:.2f} ms "
            f"({aggregate.solver_time_ratio:.1%} of measured scan time)",
            f"  solver ms/check: {aggregate.solver_ms_per_call:.2f}",
            f"  solver result-cache hits: {aggregate.solver_cache_hits} "
            f"({aggregate.solver_cache_hit_rate:.1%})",
            f"  Z3 AST cache: hits={aggregate.z3_ast_cache_hits}, "
            f"misses={aggregate.z3_ast_cache_misses}, "
            f"rate={aggregate.z3_ast_cache_hit_rate:.1%}",
            "Detector and Soundness Signals",
            f"  detector sink attempts: {aggregate.detector_attempts}",
            f"  detector feasibility cache: hits={aggregate.detector_cache_hits}, "
            f"misses={aggregate.detector_cache_misses}, "
            f"rate={aggregate.detector_cache_hit_rate:.1%}",
            f"  candidate issues: {aggregate.candidate_issues}",
            f"  confirmed issues: {aggregate.confirmed_issues}",
            f"  degraded operations: {aggregate.degraded_operations}",
            f"  top degraded labels: {_format_label_counts(report.degraded_labels)}",
            "Memory",
            f"  avg memory: {aggregate.avg_memory_mb:.2f} MB",
            f"  max memory: {aggregate.max_memory_mb:.2f} MB",
        ],
    )
    lines.extend(_format_time_accounting(report))
    lines.extend(_format_bottlenecks(report))
    lines.extend(_format_files(report))
    lines.extend(_format_hotspot_sections(report))
    lines.extend(_format_comparison(report))
    lines.extend(_format_artifacts(report))
    return "\n".join(lines)


def _format_environment(report: ScanProfileReport) -> list[str]:
    """Format bounded runtime and scan configuration metadata."""
    lines = ["Reproduction Context"]
    metadata = report.profile_run.metadata if report.profile_run is not None else None
    if metadata is None:
        lines.append("  runtime metadata: unavailable")
    else:
        lines.extend(
            [
                f"  generated: {metadata.generated_at_utc}",
                f"  Python: {metadata.python_implementation} {metadata.python_version}",
                f"  platform: {metadata.platform}",
                f"  profiler mode: {metadata.profiler_mode}",
                f"  profiler scope: {metadata.scope}",
                _format_profiler_measurement(metadata),
            ],
        )
    config = report.configuration
    if config is None:
        lines.append("  scan configuration: unavailable")
    else:
        lines.extend(
            [
                f"  target: {config.target_path}",
                f"  selection: pattern={config.scan_pattern or '-'}",
                f"  limits: paths={config.max_paths}, depth={config.max_depth}, "
                f"timeout={config.timeout_seconds}s, iterations={config.max_iterations}",
                f"  execution: workers={config.workers}, cache={_on_off(config.cache_enabled)}, "
                f"sandbox={_on_off(config.sandbox_enabled)}, trace={config.trace_verbosity}, "
                f"auto={config.auto_tune}, overflow={config.detect_overflow}",
                f"  profiling: mode={config.profile_mode}, "
                f"sample_interval={config.profile_sample_interval_ms:g}ms",
            ],
        )
    return lines


def _format_profiler_measurement(metadata: object) -> str:
    """Format profiler-mode-specific measurement notes."""
    profiler_mode = getattr(metadata, "profiler_mode", "cprofile")
    if profiler_mode == "sample":
        interval = getattr(metadata, "sample_interval_seconds", None)
        samples = getattr(metadata, "sample_count", 0)
        dropped = getattr(metadata, "dropped_samples", 0)
        interval_ms = interval * 1000.0 if isinstance(interval, float) else 0.0
        return (
            f"  measurement: statistical stack sampling; interval={interval_ms:g}ms, "
            f"samples={samples}, dropped={dropped}; trace is not implied"
        )
    return "  measurement: deterministic cProfile call tracing; compare equivalent profiled runs"


def _profile_count_label(report: ScanProfileReport) -> str:
    """Return the stable count label for hotspot tables."""
    metadata = report.profile_run.metadata if report.profile_run is not None else None
    if metadata is not None and metadata.profiler_mode == "sample":
        return "samples"
    return "calls"


def _format_time_accounting(report: ScanProfileReport) -> list[str]:
    """Format exclusive cProfile phase accounting."""
    lines = ["Exclusive Time by Phase"]
    profile_run = report.profile_run
    if profile_run is None or not profile_run.phase_breakdown:
        return [*lines, "  -"]
    for index, phase in enumerate(profile_run.phase_breakdown[:10], start=1):
        lines.append(
            f"  {index}. {phase.phase}: {phase.internal_time_seconds * 1000:.2f}ms "
            f"({phase.profile_share:.1%}), {_profile_count_label(report)}={phase.total_calls}, "
            f"frames={phase.frame_count}",
        )
    return lines


def _format_bottlenecks(report: ScanProfileReport) -> list[str]:
    """Format ordered bottleneck diagnoses."""
    lines = ["Bottleneck Signals"]
    if not report.bottlenecks:
        return [*lines, "  none: no dominant bottleneck signal crossed the profiling thresholds"]
    for index, bottleneck in enumerate(report.bottlenecks, start=1):
        lines.append(f"  {index}. [{bottleneck.severity}] {bottleneck.kind}: {bottleneck.evidence}")
        lines.append(f"     next: {bottleneck.next_step}")
    return lines


def _format_files(report: ScanProfileReport) -> list[str]:
    """Format the slowest per-file evidence rows."""
    lines = ["Slowest Files"]
    if not report.files:
        return [*lines, "  -"]
    for index, item in enumerate(report.files[:5], start=1):
        lines.append(
            f"  {index}. {item.file_path}: {item.elapsed_seconds:.3f}s, "
            f"paths={item.paths_explored}, solver={item.solver_time_ms:.2f}ms, "
            f"degraded={item.degraded_count}",
        )
    return lines


def _format_hotspot_sections(report: ScanProfileReport) -> list[str]:
    """Format cumulative, exclusive, and external/runtime hotspot tables."""
    profile_run = report.profile_run
    if profile_run is None:
        return ["Cumulative Engine Hotspots", "  -", "Self-Time Engine Hotspots", "  -"]
    count_label = _profile_count_label(report)
    lines = ["Cumulative Engine Hotspots"]
    lines.extend(
        _format_hotspots(profile_run.cumulative_hotspots, limit=10, count_label=count_label),
    )
    lines.append("Self-Time Engine Hotspots")
    lines.extend(_format_hotspots(profile_run.internal_hotspots, limit=10, count_label=count_label))
    lines.append("External and Runtime Self-Time")
    lines.extend(_format_hotspots(profile_run.external_hotspots, limit=8, count_label=count_label))
    return lines


def _format_hotspots(
    hotspots: Sequence[ProfileHotspot],
    *,
    limit: int,
    count_label: str = "calls",
) -> list[str]:
    """Format profiler hotspots with count density and phase ownership."""
    if not hotspots:
        return ["  -"]
    return [
        (
            f"  {index}. {item.file_path}:{item.line_number} {item.function_name} "
            f"phase={item.phase} cum={item.cumulative_time_seconds * 1000:.2f}ms "
            f"self={item.internal_time_seconds * 1000:.2f}ms {count_label}={item.total_calls} "
            f"self/call={item.internal_microseconds_per_call:.2f}us"
        )
        for index, item in enumerate(hotspots[:limit], start=1)
    ]


def _format_comparison(report: ScanProfileReport) -> list[str]:
    """Format optional baseline deltas and comparability warnings."""
    comparison = report.comparison
    if comparison is None:
        return []
    lines = ["Baseline Comparison", f"  baseline: {comparison.baseline_path}"]
    lines.append(f"  comparable configuration: {'yes' if comparison.compatible else 'no'}")
    for note in comparison.notes:
        lines.append(f"  note: {note}")
    for item in comparison.metrics:
        lines.append(_format_metric_delta(item))
    return lines


def _format_metric_delta(item: MetricDelta) -> str:
    """Format one baseline metric delta."""
    relative = "n/a" if item.relative_delta is None else f"{item.relative_delta:+.1%}"
    return (
        f"  [{item.status}] {item.metric}: {item.baseline:.3f} -> {item.current:.3f} "
        f"{item.unit} ({relative})"
    )


def _format_artifacts(report: ScanProfileReport) -> list[str]:
    """Format generated artifact locations last for easy command-line discovery."""
    lines = ["Artifacts", f"  trace directory: {report.trace_output_dir}"]
    if report.profile_run is not None:
        lines.append(f"  profile artifact: {report.profile_run.stats_path}")
    if report.profile_summary_path is not None:
        lines.append(f"  profile summary: {report.profile_summary_path}")
    return lines


def _format_label_counts(labels: Sequence[tuple[str, int]]) -> str:
    """Format sorted label counts."""
    if not labels:
        return "-"
    return ", ".join(f"{label}={count}" for label, count in labels[:5])


def _on_off(value: bool) -> str:
    """Return a stable enabled/disabled label."""
    return "enabled" if value else "disabled"


class ScanProfileReports:
    """Namespace for scoped helpers formerly exposed as module-level functions."""

    write_summary = staticmethod(_write_summary)
    format = staticmethod(_format)
