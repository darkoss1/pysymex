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

"""Extract and classify deterministic Python profiler evidence.

This module owns conversion of raw :mod:`cProfile` frames into stable hotspot,
origin, and phase records. It does not aggregate scan results or diagnose
symbolic-execution bottlenecks.
"""

from __future__ import annotations

import pstats
from collections import defaultdict
from collections.abc import Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, cast

from pysymex._internal.profiling.classification import (
    ProfileFrameOrigin,
    ProfileFramePolicy,
    ProfilePhase,
    resolve_profile_path,
)

if TYPE_CHECKING:
    import cProfile
    from pathlib import Path

_ProfileKey = tuple[str, int, str]
_CallerStats = Mapping[_ProfileKey, tuple[int, int, float, float]]
_ProfileStatsEntry = tuple[int, int, float, float, _CallerStats]
_ProfileStats = Mapping[_ProfileKey, _ProfileStatsEntry]


@dataclass(frozen=True, slots=True)
class ProfileHotspot:
    """One function-level cProfile hotspot with stable ownership metadata."""

    file_path: str
    line_number: int
    function_name: str
    primitive_calls: int
    total_calls: int
    internal_time_seconds: float
    cumulative_time_seconds: float
    origin: ProfileFrameOrigin = "engine"
    phase: ProfilePhase = "other_engine"

    @property
    def internal_microseconds_per_call(self) -> float:
        """Return exclusive Python time per observed call."""
        if self.total_calls <= 0:
            return 0.0
        return self.internal_time_seconds * 1_000_000.0 / self.total_calls

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "file": self.file_path,
            "line": self.line_number,
            "function": self.function_name,
            "origin": self.origin,
            "phase": self.phase,
            "primitive_calls": self.primitive_calls,
            "total_calls": self.total_calls,
            "internal_time_seconds": self.internal_time_seconds,
            "cumulative_time_seconds": self.cumulative_time_seconds,
            "internal_microseconds_per_call": self.internal_microseconds_per_call,
        }


@dataclass(frozen=True, slots=True)
class ProfilePhaseBreakdown:
    """Exclusive profiler time attributed to one stable subsystem phase."""

    phase: ProfilePhase
    internal_time_seconds: float
    profile_share: float
    primitive_calls: int
    total_calls: int
    frame_count: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "phase": self.phase,
            "internal_time_seconds": self.internal_time_seconds,
            "profile_share": self.profile_share,
            "primitive_calls": self.primitive_calls,
            "total_calls": self.total_calls,
            "frame_count": self.frame_count,
        }


@dataclass(frozen=True, slots=True)
class ProfileOriginBreakdown:
    """Exclusive profiler time attributed to one frame origin."""

    origin: ProfileFrameOrigin
    internal_time_seconds: float
    profile_share: float
    frame_count: int

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "origin": self.origin,
            "internal_time_seconds": self.internal_time_seconds,
            "profile_share": self.profile_share,
            "frame_count": self.frame_count,
        }


@dataclass(frozen=True, slots=True)
class PythonProfileSummary:
    """Classified hotspot and exclusive-time evidence from one cProfile run."""

    cumulative_hotspots: tuple[ProfileHotspot, ...]
    internal_hotspots: tuple[ProfileHotspot, ...]
    external_hotspots: tuple[ProfileHotspot, ...]
    phase_breakdown: tuple[ProfilePhaseBreakdown, ...]
    origin_breakdown: tuple[ProfileOriginBreakdown, ...]
    total_internal_time_seconds: float
    total_calls: int


def collect_python_profile(
    profile: cProfile.Profile,
    *,
    project_root: Path,
    target_path: Path,
    limit: int,
) -> PythonProfileSummary:
    """Return classified hotspots and exclusive-time accounting for a completed run."""
    stats = pstats.Stats(profile)
    raw_stats = cast("_ProfileStats", getattr(stats, "stats", {}))
    root = resolve_profile_path(project_root)
    target = resolve_profile_path(target_path)
    hotspots = tuple(
        _hotspot_from_entry(key, entry, project_root=root, target_path=target)
        for key, entry in raw_stats.items()
    )
    total_internal_time = sum(item.internal_time_seconds for item in hotspots)
    main_frames = tuple(item for item in hotspots if item.origin in {"engine", "target"})
    external_frames = tuple(
        item for item in hotspots if item.origin in {"dependency", "runtime", "project"}
    )
    return PythonProfileSummary(
        cumulative_hotspots=_sorted_hotspots(main_frames, limit=limit, sort_by="cumulative"),
        internal_hotspots=_sorted_hotspots(main_frames, limit=limit, sort_by="internal"),
        external_hotspots=_sorted_hotspots(external_frames, limit=limit, sort_by="internal"),
        phase_breakdown=_phase_breakdown(hotspots, total_internal_time),
        origin_breakdown=_origin_breakdown(hotspots, total_internal_time),
        total_internal_time_seconds=total_internal_time,
        total_calls=sum(item.total_calls for item in hotspots),
    )


def collect_sampling_profile(
    *,
    leaf_counts: Mapping[_ProfileKey, int],
    cumulative_counts: Mapping[_ProfileKey, int],
    project_root: Path,
    target_path: Path,
    profiled_seconds: float,
    limit: int,
) -> PythonProfileSummary:
    """Return classified hotspot evidence from statistical stack samples.

    ``leaf_counts`` represents sampled self-time. ``cumulative_counts`` represents
    sampled stack residence time. Both are converted into seconds using the
    completed profiler session duration, so the resulting report stays compatible
    with the deterministic cProfile-backed schema while avoiding call tracing.
    """
    root = resolve_profile_path(project_root)
    target = resolve_profile_path(target_path)
    total_samples = sum(max(0, count) for count in leaf_counts.values())
    if total_samples <= 0 or profiled_seconds <= 0.0:
        return PythonProfileSummary(
            cumulative_hotspots=(),
            internal_hotspots=(),
            external_hotspots=(),
            phase_breakdown=(),
            origin_breakdown=(),
            total_internal_time_seconds=0.0,
            total_calls=0,
        )

    hotspot_keys = frozenset((*leaf_counts.keys(), *cumulative_counts.keys()))
    hotspots = tuple(
        _sample_hotspot_from_counts(
            key,
            leaf_count=max(0, leaf_counts.get(key, 0)),
            cumulative_count=max(0, cumulative_counts.get(key, 0)),
            total_samples=total_samples,
            profiled_seconds=profiled_seconds,
            project_root=root,
            target_path=target,
        )
        for key in hotspot_keys
    )
    total_internal_time = sum(item.internal_time_seconds for item in hotspots)
    main_frames = tuple(item for item in hotspots if item.origin in {"engine", "target"})
    external_frames = tuple(
        item for item in hotspots if item.origin in {"dependency", "runtime", "project"}
    )
    return PythonProfileSummary(
        cumulative_hotspots=_sorted_hotspots(main_frames, limit=limit, sort_by="cumulative"),
        internal_hotspots=_sorted_hotspots(main_frames, limit=limit, sort_by="internal"),
        external_hotspots=_sorted_hotspots(external_frames, limit=limit, sort_by="internal"),
        phase_breakdown=_phase_breakdown(hotspots, total_internal_time),
        origin_breakdown=_origin_breakdown(hotspots, total_internal_time),
        total_internal_time_seconds=total_internal_time,
        total_calls=total_samples,
    )


def _hotspot_from_entry(
    key: _ProfileKey,
    entry: _ProfileStatsEntry,
    *,
    project_root: Path,
    target_path: Path,
) -> ProfileHotspot:
    """Build one classified hotspot from a raw pstats entry."""
    file_path, line_number, function_name = key
    primitive_calls, total_calls, internal_time, cumulative_time, _callers = entry
    origin, display_path, phase = ProfileFramePolicy.classify(
        file_path,
        function_name,
        project_root=project_root,
        target_path=target_path,
    )
    return ProfileHotspot(
        file_path=display_path,
        line_number=line_number,
        function_name=function_name,
        primitive_calls=primitive_calls,
        total_calls=total_calls,
        internal_time_seconds=internal_time,
        cumulative_time_seconds=cumulative_time,
        origin=origin,
        phase=phase,
    )


def _sample_hotspot_from_counts(
    key: _ProfileKey,
    *,
    leaf_count: int,
    cumulative_count: int,
    total_samples: int,
    profiled_seconds: float,
    project_root: Path,
    target_path: Path,
) -> ProfileHotspot:
    """Build one classified hotspot from statistical sample counts."""
    file_path, line_number, function_name = key
    origin, display_path, phase = ProfileFramePolicy.classify(
        file_path,
        function_name,
        project_root=project_root,
        target_path=target_path,
    )
    return ProfileHotspot(
        file_path=display_path,
        line_number=line_number,
        function_name=function_name,
        primitive_calls=leaf_count,
        total_calls=max(leaf_count, cumulative_count),
        internal_time_seconds=_sample_seconds(
            leaf_count,
            total_samples=total_samples,
            profiled_seconds=profiled_seconds,
        ),
        cumulative_time_seconds=_sample_seconds(
            cumulative_count,
            total_samples=total_samples,
            profiled_seconds=profiled_seconds,
        ),
        origin=origin,
        phase=phase,
    )


def _sample_seconds(count: int, *, total_samples: int, profiled_seconds: float) -> float:
    """Convert a non-negative sample count into approximate wall-time seconds."""
    if count <= 0 or total_samples <= 0 or profiled_seconds <= 0.0:
        return 0.0
    return profiled_seconds * count / total_samples


def _sorted_hotspots(
    hotspots: tuple[ProfileHotspot, ...],
    *,
    limit: int,
    sort_by: Literal["cumulative", "internal"],
) -> tuple[ProfileHotspot, ...]:
    """Return deterministically ordered hotspots."""
    if limit <= 0:
        return ()
    if sort_by == "internal":
        active_hotspots = tuple(item for item in hotspots if item.internal_time_seconds > 0.0)
        return tuple(
            sorted(
                active_hotspots,
                key=lambda item: (
                    -item.internal_time_seconds,
                    -item.cumulative_time_seconds,
                    item.file_path,
                    item.line_number,
                    item.function_name,
                ),
            )[:limit],
        )
    return tuple(
        sorted(
            hotspots,
            key=lambda item: (
                -item.cumulative_time_seconds,
                -item.internal_time_seconds,
                item.file_path,
                item.line_number,
                item.function_name,
            ),
        )[:limit],
    )


def _phase_breakdown(
    hotspots: tuple[ProfileHotspot, ...],
    total_internal_time: float,
) -> tuple[ProfilePhaseBreakdown, ...]:
    """Aggregate exclusive time and calls by subsystem phase."""
    times: defaultdict[ProfilePhase, float] = defaultdict(float)
    primitive_calls: defaultdict[ProfilePhase, int] = defaultdict(int)
    total_calls: defaultdict[ProfilePhase, int] = defaultdict(int)
    frame_counts: defaultdict[ProfilePhase, int] = defaultdict(int)
    for item in hotspots:
        times[item.phase] += item.internal_time_seconds
        primitive_calls[item.phase] += item.primitive_calls
        total_calls[item.phase] += item.total_calls
        frame_counts[item.phase] += 1
    return tuple(
        ProfilePhaseBreakdown(
            phase=phase,
            internal_time_seconds=internal_time,
            profile_share=_safe_ratio(internal_time, total_internal_time),
            primitive_calls=primitive_calls[phase],
            total_calls=total_calls[phase],
            frame_count=frame_counts[phase],
        )
        for phase, internal_time in sorted(times.items(), key=lambda item: (-item[1], item[0]))
        if internal_time > 0.0
    )


def _origin_breakdown(
    hotspots: tuple[ProfileHotspot, ...],
    total_internal_time: float,
) -> tuple[ProfileOriginBreakdown, ...]:
    """Aggregate exclusive time by frame ownership origin."""
    times: defaultdict[ProfileFrameOrigin, float] = defaultdict(float)
    frame_counts: defaultdict[ProfileFrameOrigin, int] = defaultdict(int)
    for item in hotspots:
        times[item.origin] += item.internal_time_seconds
        frame_counts[item.origin] += 1
    return tuple(
        ProfileOriginBreakdown(
            origin=origin,
            internal_time_seconds=internal_time,
            profile_share=_safe_ratio(internal_time, total_internal_time),
            frame_count=frame_counts[origin],
        )
        for origin, internal_time in sorted(times.items(), key=lambda item: (-item[1], item[0]))
        if internal_time > 0.0
    )


def _safe_ratio(numerator: float, denominator: float) -> float:
    """Return a non-negative ratio with a zero denominator fallback."""
    if denominator <= 0.0:
        return 0.0
    return max(0.0, numerator / denominator)
