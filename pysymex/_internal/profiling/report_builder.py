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

"""Internal assembly helpers for :class:`ScanProfileReport`."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

from pysymex._internal.profiling.diagnosis import diagnose_bottlenecks
from pysymex._internal.profiling.model import (
    FileProfile,
    ProfileConfiguration,
    ScanAggregateProfile,
    ScanProfileReport,
    ScanProfileResult,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence
    from pathlib import Path

    from pysymex._internal.profiling.session import ProfileRun


def assemble_scan_profile_report(
    results: Sequence[ScanProfileResult],
    *,
    trace_output_dir: str,
    profile_run: ProfileRun | None = None,
    stats_metrics: Mapping[str, object] | None = None,
    wall_time_seconds: float | None = None,
    profile_summary_path: Path | None = None,
    configuration: ProfileConfiguration | None = None,
) -> ScanProfileReport:
    """Build a profile report from scan, stats, and optional cProfile evidence."""
    files = tuple(sorted((_file_profile(result) for result in results), key=_file_sort_key))
    aggregate = _aggregate_profile(
        files,
        stats_metrics=stats_metrics or {},
        wall_time_seconds=wall_time_seconds,
        profile_run=profile_run,
    )
    degraded_labels = tuple(
        Counter(label for result in results for label in result.degraded_passes).most_common(10),
    )
    bottlenecks = diagnose_bottlenecks(
        aggregate=aggregate,
        files=files,
        degraded_labels=degraded_labels,
        profile_run=profile_run,
    )
    return ScanProfileReport(
        aggregate=aggregate,
        files=files,
        bottlenecks=bottlenecks,
        degraded_labels=degraded_labels,
        profile_run=profile_run,
        profile_summary_path=profile_summary_path,
        trace_output_dir=trace_output_dir,
        configuration=configuration,
    )


def _file_profile(result: ScanProfileResult) -> FileProfile:
    """Build one file-profile row from a scan result."""
    stats = result.solver_stats
    solver_calls = _int_stat(stats, "z3_check_calls")
    if solver_calls == 0:
        solver_calls = _int_stat(stats, "queries")
    confirmed = sum(issue.get("replay_status") == "confirmed" for issue in result.issues)
    return FileProfile(
        file_path=result.file_path,
        elapsed_seconds=max(0.0, result.elapsed_time),
        code_objects=max(0, result.code_objects),
        paths_explored=max(0, result.paths_explored),
        paths_pruned=max(0, result.paths_pruned),
        solver_calls=solver_calls,
        solver_time_ms=_float_stat(stats, "solver_time_ms"),
        solver_unknown=_int_stat(stats, "unknown_results"),
        detector_attempts=_int_stat(stats, "detector_sink_attempts"),
        issue_count=len(result.issues),
        confirmed_issue_count=confirmed,
        degraded_count=len(result.degraded_passes),
        avg_memory_mb=max(0.0, result.avg_memory_mb),
        error=result.error,
        logical_solver_queries=_int_stat(stats, "logical_queries"),
        solver_sat=_int_stat(stats, "sat_results"),
        solver_unsat=_int_stat(stats, "unsat_results"),
        solver_cache_hits=_int_stat(stats, "cache_hits"),
        z3_ast_cache_hits=_int_stat(stats, "z3_ast_cache_hits"),
        z3_ast_cache_misses=_int_stat(stats, "z3_ast_cache_misses"),
        detector_cache_hits=_int_stat(stats, "detector_query_cache_hits"),
        detector_cache_misses=_int_stat(stats, "detector_query_cache_misses"),
    )


def _aggregate_profile(
    files: tuple[FileProfile, ...],
    *,
    stats_metrics: Mapping[str, object],
    wall_time_seconds: float | None,
    profile_run: ProfileRun | None,
) -> ScanAggregateProfile:
    """Aggregate file rows and optional global stats metrics."""
    scan_elapsed = sum(item.elapsed_seconds for item in files)
    observed_wall = max(0.0, wall_time_seconds if wall_time_seconds is not None else scan_elapsed)
    paths = sum(item.paths_explored for item in files)
    pruned = sum(item.paths_pruned for item in files)
    solver_calls = sum(item.solver_calls for item in files)
    solver_time_ms = sum(item.solver_time_ms for item in files)
    solver_time_seconds = solver_time_ms / 1000.0
    logical_queries = sum(item.logical_solver_queries for item in files)
    solver_cache_hits = sum(item.solver_cache_hits for item in files)
    ast_hits = sum(item.z3_ast_cache_hits for item in files)
    ast_misses = sum(item.z3_ast_cache_misses for item in files)
    detector_hits = sum(item.detector_cache_hits for item in files)
    detector_misses = sum(item.detector_cache_misses for item in files)
    avg_memory = _float_stat(stats_metrics, "avg_memory_mb")
    if avg_memory == 0.0 and files:
        memory_samples = [item.avg_memory_mb for item in files if item.avg_memory_mb > 0.0]
        avg_memory = sum(memory_samples) / len(memory_samples) if memory_samples else 0.0
    max_memory = max(
        _float_stat(stats_metrics, "max_memory_mb"),
        *(item.avg_memory_mb for item in files),
        0.0,
    )
    profiled_seconds = profile_run.profiled_seconds if profile_run is not None else 0.0
    accounted_paths = paths + pruned
    return ScanAggregateProfile(
        files_scanned=len(files),
        files_with_errors=sum(1 for item in files if item.error is not None),
        code_objects=sum(item.code_objects for item in files),
        wall_time_seconds=observed_wall,
        scan_elapsed_seconds=scan_elapsed,
        paths_explored=paths,
        paths_pruned=pruned,
        solver_calls=solver_calls,
        solver_time_ms=solver_time_ms,
        solver_unknown=sum(item.solver_unknown for item in files),
        detector_attempts=sum(item.detector_attempts for item in files),
        candidate_issues=sum(item.issue_count - item.confirmed_issue_count for item in files),
        confirmed_issues=sum(item.confirmed_issue_count for item in files),
        degraded_operations=sum(item.degraded_count for item in files),
        avg_memory_mb=avg_memory,
        max_memory_mb=max_memory,
        path_rate=_safe_div(paths, scan_elapsed or observed_wall),
        solver_calls_per_path=_safe_div(solver_calls, paths),
        solver_ms_per_call=_safe_div(solver_time_ms, solver_calls),
        pruned_ratio=_safe_div(pruned, accounted_paths),
        logical_solver_queries=logical_queries,
        solver_sat=sum(item.solver_sat for item in files),
        solver_unsat=sum(item.solver_unsat for item in files),
        solver_cache_hits=solver_cache_hits,
        solver_cache_hit_rate=_safe_div(solver_cache_hits, solver_cache_hits + solver_calls),
        z3_ast_cache_hits=ast_hits,
        z3_ast_cache_misses=ast_misses,
        z3_ast_cache_hit_rate=_safe_div(ast_hits, ast_hits + ast_misses),
        detector_cache_hits=detector_hits,
        detector_cache_misses=detector_misses,
        detector_cache_hit_rate=_safe_div(detector_hits, detector_hits + detector_misses),
        solver_time_ratio=_safe_div(solver_time_seconds, scan_elapsed),
        non_solver_seconds=max(0.0, scan_elapsed - solver_time_seconds),
        profiled_seconds=profiled_seconds,
        profile_coverage_ratio=_safe_div(profiled_seconds, observed_wall),
        unprofiled_wall_seconds=max(0.0, observed_wall - profiled_seconds),
    )


def _file_sort_key(item: FileProfile) -> tuple[float, float, str]:
    """Sort slowest files first, then solver-heavy files."""
    return (-item.elapsed_seconds, -item.solver_time_ms, item.file_path)


def _int_stat(stats: Mapping[str, object], key: str) -> int:
    """Return a non-negative integer stat."""
    value = stats.get(key, 0)
    if isinstance(value, bool) or not isinstance(value, int):
        return 0
    return max(0, value)


def _float_stat(stats: Mapping[str, object], key: str) -> float:
    """Return a non-negative numeric stat."""
    value = stats.get(key, 0.0)
    if isinstance(value, bool) or not isinstance(value, int | float):
        return 0.0
    return max(0.0, float(value))


def _safe_div(numerator: float, denominator: float) -> float:
    """Return a safe non-negative division result."""
    if denominator <= 0:
        return 0.0
    return max(0.0, float(numerator) / float(denominator))
