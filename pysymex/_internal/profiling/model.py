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

"""Typed data model for scan profile artifacts and comparisons.

These frozen records are the single source of truth for the versioned JSON
profile schema. They contain evidence only and do not influence execution.
"""

from __future__ import annotations

import dataclasses
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, Protocol, cast

if TYPE_CHECKING:
    from pathlib import Path

    from pysymex._internal.profiling.session import ProfileRun

Severity = Literal["high", "medium", "low", "info"]
MetricDirection = Literal["higher", "lower", "neutral"]
MetricStatus = Literal["improved", "regressed", "stable", "changed"]


@dataclass(frozen=True, slots=True)
class ProfileConfiguration:
    """Scan settings required to reproduce profile conditions."""

    target_path: str
    workers: int
    max_paths: int | None
    max_depth: int | None
    timeout_seconds: float | None
    max_iterations: int | None
    cache_enabled: bool
    sandbox_enabled: bool
    trace_verbosity: str
    profile_mode: str = "sample"
    profile_sample_interval_ms: float = 5.0
    auto_tune: bool = True
    detect_overflow: bool = False
    scan_pattern: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class FileProfile:
    """Per-file profile evidence derived from a scan result."""

    file_path: str
    elapsed_seconds: float
    code_objects: int
    paths_explored: int
    paths_pruned: int
    solver_calls: int
    solver_time_ms: float
    solver_unknown: int
    detector_attempts: int
    issue_count: int
    confirmed_issue_count: int
    degraded_count: int
    avg_memory_mb: float
    error: str | None
    logical_solver_queries: int = 0
    solver_sat: int = 0
    solver_unsat: int = 0
    solver_cache_hits: int = 0
    z3_ast_cache_hits: int = 0
    z3_ast_cache_misses: int = 0
    detector_cache_hits: int = 0
    detector_cache_misses: int = 0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class ScanAggregateProfile:
    """Aggregated scan-profile evidence across all file results."""

    files_scanned: int
    files_with_errors: int
    code_objects: int
    wall_time_seconds: float
    scan_elapsed_seconds: float
    paths_explored: int
    paths_pruned: int
    solver_calls: int
    solver_time_ms: float
    solver_unknown: int
    detector_attempts: int
    candidate_issues: int
    confirmed_issues: int
    degraded_operations: int
    avg_memory_mb: float
    max_memory_mb: float
    path_rate: float
    solver_calls_per_path: float
    solver_ms_per_call: float
    pruned_ratio: float
    logical_solver_queries: int = 0
    solver_sat: int = 0
    solver_unsat: int = 0
    solver_cache_hits: int = 0
    solver_cache_hit_rate: float = 0.0
    z3_ast_cache_hits: int = 0
    z3_ast_cache_misses: int = 0
    z3_ast_cache_hit_rate: float = 0.0
    detector_cache_hits: int = 0
    detector_cache_misses: int = 0
    detector_cache_hit_rate: float = 0.0
    solver_time_ratio: float = 0.0
    non_solver_seconds: float = 0.0
    profiled_seconds: float = 0.0
    profile_coverage_ratio: float = 0.0
    unprofiled_wall_seconds: float = 0.0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class ScanBottleneck:
    """One deterministic bottleneck diagnosis with concrete evidence."""

    kind: str
    severity: Severity
    evidence: str
    next_step: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class MetricDelta:
    """One normalized baseline delta with explicit optimization direction."""

    metric: str
    baseline: float
    current: float
    absolute_delta: float
    relative_delta: float | None
    direction: MetricDirection
    status: MetricStatus
    unit: str

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return dataclasses.asdict(self)


@dataclass(frozen=True, slots=True)
class ProfileComparison:
    """Comparison against one prior JSON profile artifact."""

    baseline_path: str
    compatible: bool
    notes: tuple[str, ...]
    metrics: tuple[MetricDelta, ...]

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "baseline_path": self.baseline_path,
            "compatible": self.compatible,
            "notes": list(self.notes),
            "metrics": [item.to_dict() for item in self.metrics],
        }


class ScanProfileResult(Protocol):
    """Scan-result fields consumed by profiling diagnostics."""

    @property
    def file_path(self) -> str: ...

    @property
    def issues(self) -> Sequence[Mapping[str, object]]: ...

    @property
    def code_objects(self) -> int: ...

    @property
    def paths_explored(self) -> int: ...

    @property
    def paths_pruned(self) -> int: ...

    @property
    def elapsed_time(self) -> float: ...

    @property
    def avg_memory_mb(self) -> float: ...

    @property
    def error(self) -> str | None: ...

    @property
    def degraded_passes(self) -> Sequence[str]: ...

    @property
    def solver_stats(self) -> Mapping[str, object]: ...


@dataclass(frozen=True, slots=True)
class ScanProfileReport:
    """Full scan profiling report ready for text or JSON rendering."""

    aggregate: ScanAggregateProfile
    files: tuple[FileProfile, ...]
    bottlenecks: tuple[ScanBottleneck, ...]
    degraded_labels: tuple[tuple[str, int], ...]
    profile_run: ProfileRun | None
    profile_summary_path: Path | None
    trace_output_dir: str
    configuration: ProfileConfiguration | None = None
    comparison: ProfileComparison | None = None

    def with_summary_path(self, path: Path) -> ScanProfileReport:
        """Return a copy that records the persisted summary path."""
        return dataclasses.replace(self, profile_summary_path=path)

    def with_comparison(self, comparison: ProfileComparison | None) -> ScanProfileReport:
        """Return a copy that records optional baseline comparison evidence."""
        return dataclasses.replace(self, comparison=comparison)

    @classmethod
    def from_scan_results(
        cls,
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
        from pysymex._internal.profiling.report_builder import assemble_scan_profile_report

        return assemble_scan_profile_report(
            results,
            trace_output_dir=trace_output_dir,
            profile_run=profile_run,
            stats_metrics=stats_metrics,
            wall_time_seconds=wall_time_seconds,
            profile_summary_path=profile_summary_path,
            configuration=configuration,
        )

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "configuration": (
                self.configuration.to_dict() if self.configuration is not None else None
            ),
            "aggregate": self.aggregate.to_dict(),
            "files": [item.to_dict() for item in self.files],
            "bottlenecks": [item.to_dict() for item in self.bottlenecks],
            "degraded_labels": [
                {"label": label, "count": count} for label, count in self.degraded_labels
            ],
            "profile_run": self.profile_run.to_dict() if self.profile_run is not None else None,
            "comparison": self.comparison.to_dict() if self.comparison is not None else None,
            "profile_summary_path": (
                str(self.profile_summary_path) if self.profile_summary_path is not None else None
            ),
            "trace_output_dir": self.trace_output_dir,
        }


def read_mapping(value: object) -> Mapping[str, object] | None:
    """Return a string-keyed mapping when a decoded JSON value has that shape."""
    if not isinstance(value, Mapping):
        return None
    object_mapping = cast("Mapping[object, object]", value)
    if not all(isinstance(key, str) for key in object_mapping):
        return None
    return cast("Mapping[str, object]", object_mapping)
