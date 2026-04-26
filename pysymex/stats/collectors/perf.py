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
from collections.abc import Callable
import psutil

logger = logging.getLogger(__name__)

EwmaFn = Callable[[float, float, float], float]

try:
    from numba import njit as _numba_njit
except ImportError:

    def _compile_ewma(func: EwmaFn) -> EwmaFn:
        """Use pure Python when numba is unavailable."""
        return func

else:

    def _compile_ewma(func: EwmaFn) -> EwmaFn:
        """Compile with numba to reduce collector overhead."""
        return _numba_njit(cache=False)(func)


@_compile_ewma
def _ewma(current: float, new_val: float, alpha: float) -> float:
    return alpha * new_val + (1.0 - alpha) * current


from .base import MetricCollector
from ..types import Event, EventType


class PerfCollector(MetricCollector):
    """Collector for high-res timing and memory analytics."""

    def __init__(self) -> None:
        self._metrics: dict[str, float | int | str] = {
            "path_exploration_rate": 0.0,
            "total_paths_explored": 0.0,
            "max_memory_mb": 0.0,
        }
        self._last_time = time.perf_counter_ns()
        self._process = psutil.Process(os.getpid())

    def process(self, events: list[Event]) -> None:
        new_paths = 0

        for event in events:
            if event.type == EventType.PATH_EXPLORED:
                new_paths += 1

        now = time.perf_counter_ns()
        dt_s = (now - self._last_time) / 1e9

        if dt_s > 0:
            rate = new_paths / dt_s
            self._metrics["path_exploration_rate"] = _ewma(
                float(self._metrics["path_exploration_rate"]), rate, 0.2
            )

        self._metrics["total_paths_explored"] = (
            float(self._metrics["total_paths_explored"]) + new_paths
        )

        try:
            mem_mb = self._process.memory_info().rss / (1024 * 1024)
            if mem_mb > float(self._metrics["max_memory_mb"]):
                self._metrics["max_memory_mb"] = mem_mb
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            logger.debug("PerfCollector memory sampling unavailable", exc_info=True)

        self._last_time = now

    def get_metrics(self) -> dict[str, float | int | str]:
        return self._metrics.copy()
