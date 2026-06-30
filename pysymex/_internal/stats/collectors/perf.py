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

"""Performance metrics collector for scan-time informational counters.

Collects path counts, per-flush rates, scan-average path rates, stats event
activity, and memory samples.  These metrics are human-facing diagnostics only;
they are never consumed by the symbolic executor for scheduling or pruning.
"""

from __future__ import annotations

import os
import time

import psutil

from pysymex._internal.logging.root import get_logger
from pysymex._internal.stats.types import Event, EventType

from .base import MetricCollector

logger = get_logger(__name__)


def _ewma(current: float, new_val: float, alpha: float) -> float:
    """Compute an exponentially weighted moving average sample."""
    return alpha * new_val + (1.0 - alpha) * current


class PerfCollector(MetricCollector):
    """Collector for high-res timing and memory analytics."""

    def __init__(self) -> None:
        """Initialize the performance collector.

        Sets up initial metrics counters, high-resolution timers, process metrics via
        psutil, and EWMA state variables.
        """
        self._process = psutil.Process(os.getpid())
        self.reset()

    def reset(self) -> None:
        """Reset scan-local performance counters and timing anchors."""
        self._metrics: dict[str, float | int | str] = {
            "path_exploration_rate": 0.0,
            "path_exploration_rate_avg": 0.0,
            "engine_activity_rate": 0.0,
            "total_paths_explored": 0.0,
            "max_memory_mb": 0.0,
            "avg_memory_mb": 0.0,
        }
        self._start_time = time.perf_counter_ns()
        self.last_rate_timestamp_ns = self._start_time
        self._last_total_paths = 0.0
        self._last_total_events = 0.0
        self._total_events = 0.0
        self._memory_samples = 0
        self._memory_sum_mb = 0.0

    def process(self, events: list[Event]) -> None:
        """Process a batch of execution events to update performance metrics.

        Calculates updated path exploration rate and engine activity rate using
        an Exponentially Weighted Moving Average (EWMA). The average path rate is
        computed against the current stats collection window, not the distance between
        path event timestamps, so final aggregate events cannot inflate throughput.
        Records memory samples from both event data and the current process RSS. A final
        scan-average memory event replaces only the user-facing average so the `--stats`
        summary matches the scan summary, while peak memory still reflects all samples.

        Args:
            events: A list of Event instances containing metrics and metadata.

        """
        new_paths = 0.0
        memory_samples: list[float] = []
        scan_avg_memory: float | None = None
        self._total_events += float(len(events))

        for event in events:
            if event.type == EventType.PATH_EXPLORED:
                new_paths += event.value if event.value > 0 else 1.0
            elif event.type == EventType.MEMORY_SAMPLE and event.value > 0:
                memory_samples.append(event.value)
            elif event.type == EventType.SCAN_AVG_MEMORY and event.value > 0:
                scan_avg_memory = event.value

        self._metrics["total_paths_explored"] = (
            float(self._metrics["total_paths_explored"]) + new_paths
        )
        total_paths = float(self._metrics["total_paths_explored"])

        now_ns = time.perf_counter_ns()
        dt_s = (now_ns - self.last_rate_timestamp_ns) / 1e9
        if dt_s > 0:
            delta_paths = total_paths - self._last_total_paths
            sample_rate = max(0.0, delta_paths / dt_s)
            current_rate = float(self._metrics["path_exploration_rate"])
            self._metrics["path_exploration_rate"] = _ewma(current_rate, sample_rate, 0.35)
            delta_events = self._total_events - self._last_total_events
            sample_activity = max(0.0, delta_events / dt_s)
            current_activity = float(self._metrics["engine_activity_rate"])
            self._metrics["engine_activity_rate"] = _ewma(current_activity, sample_activity, 0.35)
        self.last_rate_timestamp_ns = now_ns
        self._last_total_paths = total_paths
        self._last_total_events = self._total_events

        if total_paths > 0:
            total_time_s = (now_ns - self._start_time) / 1e9
            if total_time_s > 0:
                self._metrics["path_exploration_rate_avg"] = total_paths / total_time_s

        if memory_samples:
            for mem_mb in memory_samples:
                self._record_memory_sample(mem_mb)
        elif scan_avg_memory is None:
            try:
                self._record_memory_sample(self._process.memory_info().rss / (1024 * 1024))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                logger.debug("PerfCollector memory sampling unavailable", exc_info=True)

        if scan_avg_memory is not None:
            self._record_scan_average_memory(scan_avg_memory)

    def get_metrics(self) -> dict[str, float | int | str]:
        """Retrieve a copy of the computed performance metrics.

        Returns:
            dict[str, float | int | str]: A dictionary containing metrics like
            path_exploration_rate, path_exploration_rate_avg, engine_activity_rate,
            total_paths_explored, max_memory_mb, and avg_memory_mb.

        """
        return self._metrics.copy()

    def _record_memory_sample(self, mem_mb: float) -> None:
        """Record a memory utilization sample in megabytes.

        Updates the peak memory usage (max_memory_mb) and recalculates the average
        memory usage (avg_memory_mb) using the running sum of samples.

        Args:
            mem_mb: The sampled memory usage in megabytes.

        """
        if mem_mb > float(self._metrics["max_memory_mb"]):
            self._metrics["max_memory_mb"] = mem_mb
        self._memory_sum_mb += mem_mb
        self._memory_samples += 1
        self._metrics["avg_memory_mb"] = self._memory_sum_mb / self._memory_samples

    def _record_scan_average_memory(self, mem_mb: float) -> None:
        """Record the final per-file scan-average memory value."""
        if mem_mb > float(self._metrics["max_memory_mb"]):
            self._metrics["max_memory_mb"] = mem_mb
        self._metrics["avg_memory_mb"] = mem_mb
