# pysymex: Python Symbolic Execution & Formal Verification
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

from __future__ import annotations

import time
import os
import logging
import psutil
from collections.abc import Callable

logger = logging.getLogger(__name__)

from .base import MetricCollector
from ..types import Event, EventType

EwmaFn = Callable[[float, float, float], float]


def _ewma(current: float, new_val: float, alpha: float) -> float:
    """Compute an exponentially weighted moving average sample."""
    return alpha * new_val + (1.0 - alpha) * current


def _compile_ewma(func: EwmaFn) -> EwmaFn:
    """Return the EWMA function without cold-start JIT/import overhead."""
    return func


_EWMA = _compile_ewma(_ewma)


class PerfCollector(MetricCollector):
    """Collector for high-res timing and memory analytics."""

    def __init__(self) -> None:
        self._metrics: dict[str, float | int | str] = {
            "path_exploration_rate": 0.0,
            "path_exploration_rate_avg": 0.0,
            "engine_activity_rate": 0.0,
            "total_paths_explored": 0.0,
            "max_memory_mb": 0.0,
            "avg_memory_mb": 0.0,
        }
        self._start_time = time.perf_counter_ns()
        self._first_path_time_ns: int | None = None
        self._last_path_time_ns: int | None = None
        self._last_rate_timestamp_ns = self._start_time
        self._last_total_paths = 0.0
        self._last_total_events = 0.0
        self._total_events = 0.0
        self._memory_samples = 0
        self._memory_sum_mb = 0.0
        self._process = psutil.Process(os.getpid())

    def process(self, events: list[Event]) -> None:
        new_paths = 0.0
        self._total_events += float(len(events))

        for event in events:
            if event.type == EventType.PATH_EXPLORED:
                new_paths += event.value if event.value > 0 else 1.0
                if self._first_path_time_ns is None:
                    self._first_path_time_ns = event.timestamp_ns
                self._last_path_time_ns = event.timestamp_ns

        self._metrics["total_paths_explored"] = (
            float(self._metrics["total_paths_explored"]) + new_paths
        )
        total_paths = float(self._metrics["total_paths_explored"])

        now_ns = time.perf_counter_ns()
        dt_s = (now_ns - self._last_rate_timestamp_ns) / 1e9
        if dt_s > 0:
            delta_paths = total_paths - self._last_total_paths
            sample_rate = max(0.0, delta_paths / dt_s)
            current_rate = float(self._metrics["path_exploration_rate"])
            self._metrics["path_exploration_rate"] = _EWMA(current_rate, sample_rate, 0.35)
            delta_events = self._total_events - self._last_total_events
            sample_activity = max(0.0, delta_events / dt_s)
            current_activity = float(self._metrics["engine_activity_rate"])
            self._metrics["engine_activity_rate"] = _EWMA(current_activity, sample_activity, 0.35)
        self._last_rate_timestamp_ns = now_ns
        self._last_total_paths = total_paths
        self._last_total_events = self._total_events

        active_time_s = 0.0
        if self._first_path_time_ns is not None:
            end_ns = self._last_path_time_ns or time.perf_counter_ns()
            active_time_s = max(0.0, (end_ns - self._first_path_time_ns) / 1e9)

        if total_paths > 0:
            if active_time_s > 0:
                self._metrics["path_exploration_rate_avg"] = total_paths / active_time_s
            else:
                total_time_s = (now_ns - self._start_time) / 1e9
                if total_time_s > 0:
                    self._metrics["path_exploration_rate_avg"] = total_paths / total_time_s

        try:
            mem_mb = self._process.memory_info().rss / (1024 * 1024)
            if mem_mb > float(self._metrics["max_memory_mb"]):
                self._metrics["max_memory_mb"] = mem_mb
            self._memory_sum_mb += mem_mb
            self._memory_samples += 1
            self._metrics["avg_memory_mb"] = self._memory_sum_mb / self._memory_samples
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.debug("PerfCollector memory sampling unavailable", exc_info=True)

    def get_metrics(self) -> dict[str, float | int | str]:
        return self._metrics.copy()
