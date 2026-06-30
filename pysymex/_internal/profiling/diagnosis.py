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

"""Derive deterministic bottleneck diagnoses from scan profile evidence."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.profiling.model import FileProfile, ScanAggregateProfile, ScanBottleneck

if TYPE_CHECKING:
    from collections.abc import Sequence

    from pysymex._internal.profiling.hotspots import ProfileHotspot
    from pysymex._internal.profiling.session import ProfileRun


def diagnose_bottlenecks(
    *,
    aggregate: ScanAggregateProfile,
    files: tuple[FileProfile, ...],
    degraded_labels: tuple[tuple[str, int], ...],
    profile_run: ProfileRun | None,
) -> tuple[ScanBottleneck, ...]:
    """Derive bottleneck signals without changing execution or result classification."""
    bottlenecks: list[ScanBottleneck] = []
    if aggregate.solver_calls > 0 and (
        aggregate.solver_time_ratio >= 0.35 or aggregate.solver_ms_per_call >= 25.0
    ):
        bottlenecks.append(
            ScanBottleneck(
                kind="solver pressure",
                severity="high" if aggregate.solver_time_ratio >= 0.50 else "medium",
                evidence=(
                    f"{aggregate.solver_time_ms:.2f} ms in solver across "
                    f"{aggregate.solver_calls} calls "
                    f"({aggregate.solver_time_ratio:.1%} of measured scan time)"
                ),
                next_step="inspect query shape, theory mix, and cache misses before tuning limits",
            ),
        )
    elif aggregate.scan_elapsed_seconds >= 0.25 and aggregate.solver_time_ratio < 0.20:
        bottlenecks.append(
            ScanBottleneck(
                kind="non-solver overhead",
                severity="medium",
                evidence=(
                    f"{aggregate.non_solver_seconds:.3f} s outside solver checks "
                    f"({1.0 - aggregate.solver_time_ratio:.1%} of measured scan time)"
                ),
                next_step="use phase and self-time tables to locate repeated Python or Z3-AST work",
            ),
        )
    if aggregate.solver_unknown > 0:
        bottlenecks.append(
            ScanBottleneck(
                kind="solver uncertainty",
                severity="high",
                evidence=f"{aggregate.solver_unknown} solver unknown or timeout result(s)",
                next_step="treat affected paths as inconclusive; inspect traces for query shape",
            ),
        )
    if aggregate.paths_explored >= 1000 or aggregate.solver_calls_per_path >= 2.5:
        bottlenecks.append(
            ScanBottleneck(
                kind="path explosion",
                severity="high" if aggregate.paths_explored >= 5000 else "medium",
                evidence=(
                    f"{aggregate.paths_explored} paths, "
                    f"{aggregate.solver_calls_per_path:.2f} solver calls/path"
                ),
                next_step="use traces to identify branch families producing path growth",
            ),
        )
    bottlenecks.extend(_cache_bottlenecks(aggregate))
    if aggregate.degraded_operations > 0:
        bottlenecks.append(
            ScanBottleneck(
                kind="degraded analysis",
                severity="high",
                evidence=_format_label_counts(degraded_labels),
                next_step="fix unsupported or resource-limited operations before trusting speed signals",
            ),
        )
    if aggregate.max_memory_mb >= 512.0:
        bottlenecks.append(
            ScanBottleneck(
                kind="memory pressure",
                severity="high" if aggregate.max_memory_mb >= 1024.0 else "medium",
                evidence=f"peak observed memory {aggregate.max_memory_mb:.2f} MB",
                next_step="inspect state copies, object retention, and trace verbosity",
            ),
        )
    bottlenecks.extend(_file_distribution_bottlenecks(files, aggregate.scan_elapsed_seconds))
    if profile_run is not None:
        bottlenecks.extend(_python_profile_bottlenecks(profile_run))
    if aggregate.profiled_seconds > 0.0 and aggregate.profile_coverage_ratio < 0.50:
        bottlenecks.append(
            ScanBottleneck(
                kind="profile scope gap",
                severity="info",
                evidence=(
                    f"cProfile covered {aggregate.profile_coverage_ratio:.1%} of CLI wall time; "
                    f"{aggregate.unprofiled_wall_seconds:.3f} s was outside the session"
                ),
                next_step="interpret Python hotspots as parent scan work, not whole-command accounting",
            ),
        )
    return tuple(bottlenecks)


def _cache_bottlenecks(aggregate: ScanAggregateProfile) -> tuple[ScanBottleneck, ...]:
    """Return low-hit-rate signals only when the sample count is meaningful."""
    signals: list[ScanBottleneck] = []
    solver_attempts = aggregate.solver_cache_hits + aggregate.solver_calls
    if solver_attempts >= 50 and aggregate.solver_cache_hit_rate < 0.10:
        signals.append(
            ScanBottleneck(
                kind="solver cache churn",
                severity="medium",
                evidence=(
                    f"{aggregate.solver_cache_hit_rate:.1%} hit rate across "
                    f"{solver_attempts} solver cache attempts"
                ),
                next_step="inspect equivalent query fingerprints and cache invalidation boundaries",
            ),
        )
    ast_attempts = aggregate.z3_ast_cache_hits + aggregate.z3_ast_cache_misses
    if ast_attempts >= 100 and aggregate.z3_ast_cache_hit_rate < 0.20:
        signals.append(
            ScanBottleneck(
                kind="Z3 AST translation churn",
                severity="medium",
                evidence=(
                    f"{aggregate.z3_ast_cache_hit_rate:.1%} hit rate across "
                    f"{ast_attempts} translation attempts"
                ),
                next_step="inspect structurally equivalent AST translation and cache key reuse",
            ),
        )
    detector_attempts = aggregate.detector_cache_hits + aggregate.detector_cache_misses
    if detector_attempts >= 50 and aggregate.detector_cache_hit_rate < 0.10:
        signals.append(
            ScanBottleneck(
                kind="detector feasibility cache churn",
                severity="medium",
                evidence=(
                    f"{aggregate.detector_cache_hit_rate:.1%} hit rate across "
                    f"{detector_attempts} detector feasibility queries"
                ),
                next_step="inspect repeated branch/evidence constraints before adding solver work",
            ),
        )
    return tuple(signals)


def _file_distribution_bottlenecks(
    files: tuple[FileProfile, ...],
    measured_seconds: float,
) -> tuple[ScanBottleneck, ...]:
    """Return signals for file-level skew."""
    if len(files) < 2 or measured_seconds <= 0.0:
        return ()
    slowest = files[0]
    ratio = slowest.elapsed_seconds / measured_seconds
    if ratio < 0.50:
        return ()
    return (
        ScanBottleneck(
            kind="single-file hotspot",
            severity="medium",
            evidence=f"{slowest.file_path} consumed {ratio:.1%} of measured scan time",
            next_step="profile that file alone to remove cross-file scheduling noise",
        ),
    )


def _dominant_profile_hotspot(profile_run: ProfileRun) -> ProfileHotspot:
    """Return the most useful cumulative hotspot for diagnosis.

    Sampling profiles naturally put the CLI/root frame at the top of every stack.
    Skip those wrappers so the bottleneck signal names the first engine phase that
    actually owns symbolic-execution work.
    """
    mode = profile_run.metadata.profiler_mode if profile_run.metadata is not None else "cprofile"
    if mode != "sample":
        return profile_run.cumulative_hotspots[0]
    return next(
        (
            item
            for item in profile_run.cumulative_hotspots
            if item.phase not in {"cli_and_reporting", "other_engine"}
        ),
        profile_run.cumulative_hotspots[0],
    )


def _python_profile_bottlenecks(profile_run: ProfileRun) -> tuple[ScanBottleneck, ...]:
    """Return phase, cumulative hotspot, and call-amplification signals."""
    signals: list[ScanBottleneck] = []
    if profile_run.cumulative_hotspots and profile_run.profiled_seconds > 0.0:
        top = _dominant_profile_hotspot(profile_run)
        ratio = top.cumulative_time_seconds / profile_run.profiled_seconds
        if ratio >= 0.25:
            signals.append(
                ScanBottleneck(
                    kind="python hotspot",
                    severity="high" if ratio >= 0.50 else "medium",
                    evidence=(
                        f"{top.file_path}:{top.line_number} {top.function_name} consumed "
                        f"{top.cumulative_time_seconds * 1000:.2f} ms cumulative ({ratio:.1%})"
                    ),
                    next_step="inspect its self-time and dominant child phase before optimizing",
                ),
            )
    if profile_run.phase_breakdown:
        phase = profile_run.phase_breakdown[0]
        if phase.profile_share >= 0.15:
            signals.append(
                ScanBottleneck(
                    kind="dominant profile phase",
                    severity="high" if phase.profile_share >= 0.40 else "medium",
                    evidence=(
                        f"{phase.phase} used {phase.internal_time_seconds * 1000:.2f} ms "
                        f"exclusive ({phase.profile_share:.1%} of profiled self time)"
                    ),
                    next_step="inspect self-time hotspots in that phase and their call density",
                ),
            )
        formula_phase = next(
            (item for item in profile_run.phase_breakdown if item.phase == "formula_and_evidence"),
            None,
        )
        if (
            formula_phase is not None
            and formula_phase.total_calls >= 10_000
            and formula_phase.internal_time_seconds >= 0.01
        ):
            microseconds_per_call = (
                formula_phase.internal_time_seconds * 1_000_000.0 / formula_phase.total_calls
            )
            signals.append(
                ScanBottleneck(
                    kind="formula and evidence amplification",
                    severity="medium",
                    evidence=(
                        f"{formula_phase.total_calls} calls consumed "
                        f"{formula_phase.internal_time_seconds * 1000:.2f} ms exclusive "
                        f"({microseconds_per_call:.2f} us/call)"
                    ),
                    next_step="inspect repeated AST walking, simplification, and witness probing",
                ),
            )
    if profile_run.internal_hotspots and profile_run.profiled_seconds > 0.0:
        amplified = next(
            (
                item
                for item in profile_run.internal_hotspots
                if item.total_calls >= 5_000
                and item.internal_time_seconds / profile_run.profiled_seconds >= 0.01
            ),
            None,
        )
        if amplified is not None:
            signals.append(
                ScanBottleneck(
                    kind="call amplification",
                    severity="medium",
                    evidence=(
                        f"{amplified.file_path}:{amplified.line_number} "
                        f"{amplified.function_name} ran {amplified.total_calls} times at "
                        f"{amplified.internal_microseconds_per_call:.2f} us self/call"
                    ),
                    next_step="reduce repeated equivalent work before micro-optimizing each call",
                ),
            )
    return tuple(signals)


def _format_label_counts(labels: Sequence[tuple[str, int]]) -> str:
    """Format sorted label counts."""
    if not labels:
        return "-"
    return ", ".join(f"{label}={count}" for label, count in labels[:5])
