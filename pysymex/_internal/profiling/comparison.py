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

"""Load prior profile artifacts and compute noise-aware metric deltas."""

from __future__ import annotations

import json
from dataclasses import dataclass, replace
from pathlib import Path
from typing import TYPE_CHECKING

from pysymex._internal.profiling.model import (
    MetricDelta,
    MetricDirection,
    ProfileComparison,
    ScanProfileReport,
    read_mapping,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

_RELATIVE_NOISE_FLOOR = 0.05


class ProfileBaselineError(ValueError):
    """Raised when a baseline artifact is missing or structurally invalid."""


@dataclass(frozen=True, slots=True)
class _MetricSpec:
    key: str
    direction: MetricDirection
    unit: str
    noise_floor: float = _RELATIVE_NOISE_FLOOR


_METRICS = (
    _MetricSpec("scan_elapsed_seconds", "lower", "s"),
    _MetricSpec("path_rate", "higher", "paths/s"),
    _MetricSpec("paths_explored", "neutral", "paths", 0.0),
    _MetricSpec("solver_calls_per_path", "lower", "calls/path"),
    _MetricSpec("solver_ms_per_call", "lower", "ms/call"),
    _MetricSpec("solver_unknown", "lower", "count", 0.0),
    _MetricSpec("degraded_operations", "lower", "count", 0.0),
    _MetricSpec("max_memory_mb", "lower", "MB"),
)


def compare_profile_report(
    report: ScanProfileReport,
    baseline_path: str | Path,
) -> ProfileComparison:
    """Compare a report with one prior JSON artifact without altering scan evidence."""
    path = Path(baseline_path)
    try:
        decoded = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        msg = f"cannot read profile baseline {path}: {exc}"
        raise ProfileBaselineError(msg) from exc
    except json.JSONDecodeError as exc:
        msg = f"invalid profile baseline JSON {path}: {exc}"
        raise ProfileBaselineError(msg) from exc
    baseline = read_mapping(decoded)
    if baseline is None:
        msg = f"profile baseline {path} must contain a JSON object"
        raise ProfileBaselineError(msg)
    aggregate = read_mapping(baseline.get("aggregate"))
    if aggregate is None:
        msg = f"profile baseline {path} is missing aggregate metrics"
        raise ProfileBaselineError(msg)

    notes, compatible = _compatibility_notes(report, baseline)
    current = report.aggregate.to_dict()
    metrics = tuple(
        _metric_delta(
            spec,
            baseline=_number(aggregate, spec.key),
            current=_number(current, spec.key),
        )
        for spec in _METRICS
    )
    if not compatible:
        metrics = tuple(
            replace(item, status="stable" if item.status == "stable" else "changed")
            for item in metrics
        )
    return ProfileComparison(
        baseline_path=str(path),
        compatible=compatible,
        notes=notes,
        metrics=metrics,
    )


def _compatibility_notes(
    report: ScanProfileReport,
    baseline: Mapping[str, object],
) -> tuple[tuple[str, ...], bool]:
    """Return explicit comparability notes for schema and scan settings."""
    baseline_map = read_mapping(baseline)
    if baseline_map is None:
        return ("baseline root is not a mapping",), False
    notes: list[str] = []
    baseline_config = read_mapping(baseline_map.get("configuration"))
    current_config = report.configuration.to_dict() if report.configuration is not None else None
    if baseline_config is None or current_config is None:
        notes.append("configuration metadata is missing from one profile")
    else:
        for key in (
            "target_path",
            "workers",
            "max_paths",
            "max_depth",
            "timeout_seconds",
            "max_iterations",
            "cache_enabled",
            "sandbox_enabled",
            "trace_verbosity",
            "auto_tune",
            "detect_overflow",
            "scan_pattern",
            "profile_mode",
            "profile_sample_interval_ms",
        ):
            if baseline_config.get(key) != current_config.get(key):
                notes.append(
                    f"configuration differs for {key}: "
                    f"baseline={baseline_config.get(key)!r}, current={current_config.get(key)!r}",
                )
    baseline_run = read_mapping(baseline_map.get("profile_run"))
    baseline_metadata = (
        read_mapping(baseline_run.get("metadata")) if baseline_run is not None else None
    )
    current_metadata = report.profile_run.metadata if report.profile_run is not None else None
    if (baseline_metadata is None) != (current_metadata is None):
        notes.append("runtime metadata is missing from one profile")
    elif baseline_metadata is not None and current_metadata is not None:
        current_runtime = current_metadata.to_dict()
        for key in (
            "python_version",
            "python_implementation",
            "platform",
            "scope",
            "profiler_mode",
        ):
            if baseline_metadata.get(key) != current_runtime.get(key):
                notes.append(
                    f"runtime differs for {key}: "
                    f"baseline={baseline_metadata.get(key)!r}, "
                    f"current={current_runtime.get(key)!r}",
                )
    return tuple(notes), not notes


def _metric_delta(spec: _MetricSpec, *, baseline: float, current: float) -> MetricDelta:
    """Build one normalized metric delta with a deterministic noise floor."""
    absolute = current - baseline
    relative = absolute / baseline if baseline != 0.0 else None
    changed = abs(relative) > spec.noise_floor if relative is not None else current != baseline
    if not changed:
        status = "stable"
    elif spec.direction == "neutral":
        status = "changed"
    elif (spec.direction == "higher" and absolute > 0.0) or (
        spec.direction == "lower" and absolute < 0.0
    ):
        status = "improved"
    else:
        status = "regressed"
    return MetricDelta(
        metric=spec.key,
        baseline=baseline,
        current=current,
        absolute_delta=absolute,
        relative_delta=relative,
        direction=spec.direction,
        status=status,
        unit=spec.unit,
    )


def _number(mapping: Mapping[str, object], key: str) -> float:
    """Return a numeric profile field or raise a bounded baseline error."""
    values = read_mapping(mapping)
    if values is None:
        msg = "profile metric container is not a mapping"
        raise ProfileBaselineError(msg)
    value = values.get(key)
    if isinstance(value, bool) or not isinstance(value, int | float):
        msg = f"profile baseline metric {key!r} is missing or non-numeric"
        raise ProfileBaselineError(msg)
    return float(value)
