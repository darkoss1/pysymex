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

"""Low-overhead runtime profiling session and artifact metadata for scan profiling."""

from __future__ import annotations

import cProfile
import json
import os
import platform
import signal
import threading
import time
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, Protocol, cast

from pysymex._internal.profiling.hotspots import (
    ProfileHotspot,
    ProfileOriginBreakdown,
    ProfilePhaseBreakdown,
    collect_python_profile,
    collect_sampling_profile,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from types import FrameType

_HOTSPOT_LIMIT = 25
_MAX_STACK_DEPTH = 256
_MIN_SAMPLE_INTERVAL_SECONDS = 0.001
ProfileMode = Literal["sample", "cprofile"]
_ProfileKey = tuple[str, int, str]
DEFAULT_PROFILE_MODE: ProfileMode = "sample"
DEFAULT_PROFILE_SAMPLE_INTERVAL_SECONDS = 0.005
PROFILE_MODE_CHOICES: tuple[ProfileMode, ...] = ("sample", "cprofile")


@dataclass(frozen=True, slots=True)
class _SignalTimerApis:
    """Unix interval-timer constants and callables when the host exposes them."""

    sigalrm: int
    itimer_real: int
    setitimer: Callable[[int, float, float], None]
    getitimer: Callable[[int], tuple[float, float]]


def _signal_timer_apis() -> _SignalTimerApis | None:
    """Return Unix interval-timer APIs when the host exposes them."""
    sigalrm = getattr(signal, "SIGALRM", None)
    itimer_real = getattr(signal, "ITIMER_REAL", None)
    setitimer = getattr(signal, "setitimer", None)
    getitimer = getattr(signal, "getitimer", None)
    if (
        not isinstance(sigalrm, int)
        or not isinstance(itimer_real, int)
        or not callable(setitimer)
        or not callable(getitimer)
    ):
        return None
    return _SignalTimerApis(
        sigalrm=sigalrm,
        itimer_real=itimer_real,
        setitimer=cast("Callable[[int, float, float], None]", setitimer),
        getitimer=cast("Callable[[int], tuple[float, float]]", getitimer),
    )


class _SamplerBackend(Protocol):
    """Small protocol shared by concrete sample collectors."""

    leaf_counts: Counter[_ProfileKey]
    cumulative_counts: Counter[_ProfileKey]
    samples_recorded: int
    samples_dropped: int
    backend_name: str

    def start(self) -> None: ...

    def stop(self) -> None: ...

    def to_artifact(self) -> dict[str, object]: ...


@dataclass(frozen=True, slots=True)
class ProfileRuntimeMetadata:
    """Reproduction metadata for one parent-process profiling session."""

    generated_at_utc: str
    python_version: str
    python_implementation: str
    platform: str
    process_id: int
    target_path: str
    scope: str = "parent_process"
    profiler_mode: ProfileMode = DEFAULT_PROFILE_MODE
    sample_interval_seconds: float | None = None
    sample_count: int = 0
    dropped_samples: int = 0

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "generated_at_utc": self.generated_at_utc,
            "python_version": self.python_version,
            "python_implementation": self.python_implementation,
            "platform": self.platform,
            "process_id": self.process_id,
            "target_path": self.target_path,
            "scope": self.scope,
            "profiler_mode": self.profiler_mode,
            "sample_interval_seconds": self.sample_interval_seconds,
            "sample_count": self.sample_count,
            "dropped_samples": self.dropped_samples,
        }


@dataclass(frozen=True, slots=True)
class ProfileRun:
    """Completed Python profiler run and its classified evidence."""

    stats_path: Path
    profiled_seconds: float
    cumulative_hotspots: tuple[ProfileHotspot, ...]
    internal_hotspots: tuple[ProfileHotspot, ...]
    external_hotspots: tuple[ProfileHotspot, ...] = ()
    phase_breakdown: tuple[ProfilePhaseBreakdown, ...] = ()
    origin_breakdown: tuple[ProfileOriginBreakdown, ...] = ()
    total_internal_time_seconds: float = 0.0
    total_calls: int = 0
    metadata: ProfileRuntimeMetadata | None = None

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-safe representation."""
        return {
            "stats_path": str(self.stats_path),
            "profiled_seconds": self.profiled_seconds,
            "total_internal_time_seconds": self.total_internal_time_seconds,
            "total_calls": self.total_calls,
            "metadata": self.metadata.to_dict() if self.metadata is not None else None,
            "phase_breakdown": [item.to_dict() for item in self.phase_breakdown],
            "origin_breakdown": [item.to_dict() for item in self.origin_breakdown],
            "cumulative_hotspots": [item.to_dict() for item in self.cumulative_hotspots],
            "internal_hotspots": [item.to_dict() for item in self.internal_hotspots],
            "external_hotspots": [item.to_dict() for item in self.external_hotspots],
        }


class ScanProfilerSession:
    """Collect scan profiling evidence without distorting the hot path by default."""

    def __init__(
        self,
        *,
        output_dir: Path,
        project_root: Path,
        target_path: Path,
        mode: ProfileMode = DEFAULT_PROFILE_MODE,
        sample_interval_seconds: float = DEFAULT_PROFILE_SAMPLE_INTERVAL_SECONDS,
    ) -> None:
        """Prepare a stopped profiling session."""
        self._output_dir = output_dir
        self._project_root = project_root
        self._target_path = target_path
        self._mode: ProfileMode = mode
        self._sample_interval_seconds = _validated_sample_interval(sample_interval_seconds)
        self._profile = cProfile.Profile() if mode == "cprofile" else None
        self._sampler: _SamplerBackend | None = None
        self._started_at = 0.0
        self._started_at_utc = ""
        self._finished_run: ProfileRun | None = None
        self._running = False

    @classmethod
    def start(
        cls,
        *,
        output_dir: str | Path,
        project_root: str | Path,
        target_path: str | Path,
        mode: ProfileMode = DEFAULT_PROFILE_MODE,
        sample_interval_seconds: float = DEFAULT_PROFILE_SAMPLE_INTERVAL_SECONDS,
    ) -> ScanProfilerSession:
        """Create and start a profiling session."""
        session = cls(
            output_dir=Path(output_dir),
            project_root=Path(project_root),
            target_path=Path(target_path),
            mode=mode,
            sample_interval_seconds=sample_interval_seconds,
        )
        session.start_collection()
        return session

    @property
    def is_running(self) -> bool:
        """Return whether profiler collection is currently active."""
        return self._running

    @property
    def mode(self) -> ProfileMode:
        """Return the active profiler mode."""
        return self._mode

    def start_collection(self) -> None:
        """Start profiler collection."""
        if self._running:
            return
        self._started_at = time.perf_counter()
        self._started_at_utc = datetime.now(UTC).isoformat()
        if self._mode == "cprofile":
            self._require_cprofile().enable()
        else:
            self._sampler = _make_sampler(self._sample_interval_seconds)
            self._sampler.start()
        self._running = True

    def finish(self) -> ProfileRun:
        """Stop profiling, persist raw evidence, and return classified hotspots."""
        if self._finished_run is not None:
            return self._finished_run

        if self._running:
            self._stop_collection()
        profiled_seconds = max(0.0, time.perf_counter() - self._started_at)

        self._output_dir.mkdir(parents=True, exist_ok=True)
        if self._mode == "cprofile":
            self._finished_run = self._finish_cprofile(profiled_seconds)
        else:
            self._finished_run = self._finish_sampling(profiled_seconds)
        return self._finished_run

    def _stop_collection(self) -> None:
        """Stop the active profiler backend."""
        if self._mode == "cprofile":
            self._require_cprofile().disable()
        elif self._sampler is not None:
            self._sampler.stop()
        self._running = False

    def _finish_cprofile(self, profiled_seconds: float) -> ProfileRun:
        """Persist and classify deterministic cProfile evidence."""
        profile = self._require_cprofile()
        stats_path = self._output_dir / f"{self._artifact_stem()}.pstats"
        profile.dump_stats(str(stats_path))
        summary = collect_python_profile(
            profile,
            project_root=self._project_root,
            target_path=self._target_path,
            limit=_HOTSPOT_LIMIT,
        )
        return ProfileRun(
            stats_path=stats_path,
            profiled_seconds=profiled_seconds,
            cumulative_hotspots=summary.cumulative_hotspots,
            internal_hotspots=summary.internal_hotspots,
            external_hotspots=summary.external_hotspots,
            phase_breakdown=summary.phase_breakdown,
            origin_breakdown=summary.origin_breakdown,
            total_internal_time_seconds=summary.total_internal_time_seconds,
            total_calls=summary.total_calls,
            metadata=self._metadata(
                scope="parent_process",
                sample_interval_seconds=None,
                sample_count=0,
                dropped_samples=0,
            ),
        )

    def _finish_sampling(self, profiled_seconds: float) -> ProfileRun:
        """Persist and classify low-overhead statistical sample evidence."""
        sampler = self._sampler or _NullSampler(self._sample_interval_seconds)
        sample_path = self._output_dir / f"{self._artifact_stem()}.samples.json"
        sample_path.write_text(
            json.dumps(sampler.to_artifact(), indent=2, sort_keys=True),
            encoding="utf-8",
        )
        summary = collect_sampling_profile(
            leaf_counts=sampler.leaf_counts,
            cumulative_counts=sampler.cumulative_counts,
            project_root=self._project_root,
            target_path=self._target_path,
            profiled_seconds=profiled_seconds,
            limit=_HOTSPOT_LIMIT,
        )
        return ProfileRun(
            stats_path=sample_path,
            profiled_seconds=profiled_seconds,
            cumulative_hotspots=summary.cumulative_hotspots,
            internal_hotspots=summary.internal_hotspots,
            external_hotspots=summary.external_hotspots,
            phase_breakdown=summary.phase_breakdown,
            origin_breakdown=summary.origin_breakdown,
            total_internal_time_seconds=summary.total_internal_time_seconds,
            total_calls=summary.total_calls,
            metadata=self._metadata(
                scope=sampler.backend_name,
                sample_interval_seconds=self._sample_interval_seconds,
                sample_count=sampler.samples_recorded,
                dropped_samples=sampler.samples_dropped,
            ),
        )

    def _metadata(
        self,
        *,
        scope: str,
        sample_interval_seconds: float | None,
        sample_count: int,
        dropped_samples: int,
    ) -> ProfileRuntimeMetadata:
        """Build stable runtime metadata for the completed profile run."""
        return ProfileRuntimeMetadata(
            generated_at_utc=self._started_at_utc,
            python_version=platform.python_version(),
            python_implementation=platform.python_implementation(),
            platform=platform.platform(),
            process_id=os.getpid(),
            target_path=str(self._target_path),
            scope=scope,
            profiler_mode=self._mode,
            sample_interval_seconds=sample_interval_seconds,
            sample_count=max(0, sample_count),
            dropped_samples=max(0, dropped_samples),
        )

    def _require_cprofile(self) -> cProfile.Profile:
        """Return the deterministic profiler or fail for impossible mode skew."""
        if self._profile is None:
            msg = "cProfile backend is not active for this profile session"
            raise RuntimeError(msg)
        return self._profile

    def _artifact_stem(self) -> str:
        """Return a collision-resistant filesystem-safe artifact stem."""
        timestamp = time.strftime("%Y%m%d-%H%M%S")
        target_name = _safe_stem(self._target_path)
        return f"scan-{timestamp}-{os.getpid()}-{time.time_ns() % 1_000_000_000:09d}-{target_name}"


class _SignalSampler:
    """Statistical sampler using CPython's main-thread signal checkpoint."""

    backend_name = "parent_process_main_thread_signal"

    def __init__(self, interval_seconds: float) -> None:
        self._interval_seconds = interval_seconds
        self._active = False
        self._previous_handler: Any = None
        self._previous_timer: tuple[float, float] = (0.0, 0.0)
        self.leaf_counts: Counter[_ProfileKey] = Counter()
        self.cumulative_counts: Counter[_ProfileKey] = Counter()
        self.samples_recorded = 0
        self.samples_dropped = 0

    def start(self) -> None:
        """Install and start the interval timer when it is safe to do so."""
        if threading.current_thread() is not threading.main_thread():
            return
        apis = _signal_timer_apis()
        if apis is None:
            return
        try:
            previous_timer = apis.getitimer(apis.itimer_real)
        except (AttributeError, OSError, ValueError):
            return
        if previous_timer != (0.0, 0.0):
            return
        try:
            self._previous_handler = signal.getsignal(apis.sigalrm)
            self._previous_timer = previous_timer
            signal.signal(apis.sigalrm, self._handle_signal)
            apis.setitimer(apis.itimer_real, self._interval_seconds, self._interval_seconds)
            self._active = True
        except (AttributeError, OSError, ValueError):
            self._restore()

    def stop(self) -> None:
        """Stop sampling and restore the previous signal state."""
        self._restore()

    def to_artifact(self) -> dict[str, object]:
        """Return compact JSON evidence for offline inspection."""
        return {
            "profiler_mode": "sample",
            "backend": self.backend_name,
            "interval_seconds": self._interval_seconds,
            "samples_recorded": self.samples_recorded,
            "samples_dropped": self.samples_dropped,
            "leaf_counts": _encoded_counts(self.leaf_counts),
            "cumulative_counts": _encoded_counts(self.cumulative_counts),
        }

    def _handle_signal(self, _signum: int, frame: FrameType | None) -> None:
        """Record one sample from the interrupted main-thread frame."""
        if frame is None:
            self.samples_dropped += 1
            return
        stack = _extract_stack(frame)
        if not stack:
            self.samples_dropped += 1
            return
        leaf = stack[0]
        self.leaf_counts[leaf] += 1
        self.cumulative_counts.update(stack)
        self.samples_recorded += 1

    def _restore(self) -> None:
        """Best-effort restoration of the previous interval timer and handler."""
        if not self._active:
            return
        self._active = False
        apis = _signal_timer_apis()
        if apis is None:
            return
        try:
            apis.setitimer(apis.itimer_real, 0.0, 0.0)
            signal.signal(apis.sigalrm, self._previous_handler)
            delay, interval = self._previous_timer
            if delay > 0.0 or interval > 0.0:
                apis.setitimer(apis.itimer_real, delay, interval)
        except (AttributeError, OSError, ValueError):
            return


class _NullSampler:
    """No-op sampler used when platform signal timers are unavailable or already in use."""

    backend_name = "sample_unavailable"

    def __init__(self, interval_seconds: float) -> None:
        self._interval_seconds = interval_seconds
        self.leaf_counts: Counter[_ProfileKey] = Counter()
        self.cumulative_counts: Counter[_ProfileKey] = Counter()
        self.samples_recorded = 0
        self.samples_dropped = 0

    def start(self) -> None:
        """Start a no-op sampler."""
        return

    def stop(self) -> None:
        """Stop a no-op sampler."""
        return

    def to_artifact(self) -> dict[str, object]:
        """Return JSON evidence explaining why no samples were collected."""
        return {
            "profiler_mode": "sample",
            "backend": self.backend_name,
            "interval_seconds": self._interval_seconds,
            "samples_recorded": 0,
            "samples_dropped": 0,
            "leaf_counts": [],
            "cumulative_counts": [],
        }


def _make_sampler(interval_seconds: float) -> _SamplerBackend:
    """Return the safest available low-overhead sampling backend."""
    return _SignalSampler(interval_seconds)


def _extract_stack(frame: FrameType) -> tuple[_ProfileKey, ...]:
    """Return leaf-to-root profile keys for a sampled frame."""
    keys: list[_ProfileKey] = []
    current: FrameType | None = frame
    while current is not None and len(keys) < _MAX_STACK_DEPTH:
        code = current.f_code
        keys.append((code.co_filename, current.f_lineno, code.co_name))
        current = current.f_back
    return tuple(keys)


def _encoded_counts(counts: Counter[_ProfileKey]) -> list[dict[str, object]]:
    """Return deterministic JSON-safe sample counts."""
    return [
        {"file": file_path, "line": line_number, "function": function_name, "count": count}
        for (file_path, line_number, function_name), count in sorted(
            counts.items(),
            key=lambda item: (-item[1], item[0][0], item[0][1], item[0][2]),
        )
    ]


def _validated_sample_interval(value: float) -> float:
    """Return a bounded non-zero sampling interval."""
    if value < _MIN_SAMPLE_INTERVAL_SECONDS:
        return _MIN_SAMPLE_INTERVAL_SECONDS
    return value


def _safe_stem(path: Path) -> str:
    """Return a compact stem safe for profile artifact names."""
    stem = path.stem or "target"
    return "".join(char if char.isalnum() or char in ("-", "_") else "_" for char in stem)[:40]
