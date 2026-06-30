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

"""File-level scan time budget helpers."""

from __future__ import annotations

import dataclasses
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex._internal.config.execution.settings import ExecutionConfig

SCAN_TIME_LIMIT_DEGRADED_PASS = "resource_limit_time"
_MIN_REMAINING_TIMEOUT_SECONDS = 0.001


@dataclass(frozen=True, slots=True)
class ScanTimeBudget:
    """Track an elective source-file timeout across execution candidates."""

    started_at: float
    timeout_seconds: float | None

    @classmethod
    def start(cls, timeout_seconds: float | None) -> ScanTimeBudget:
        """Start a file-level budget, or automatic mode when no timeout is configured."""
        return cls(started_at=time.perf_counter(), timeout_seconds=timeout_seconds)

    def remaining_seconds(self) -> float | None:
        """Return remaining seconds, or ``None`` for automatic mode."""
        if self.timeout_seconds is None:
            return None
        return max(0.0, self.timeout_seconds - (time.perf_counter() - self.started_at))

    def expired(self) -> bool:
        """Return whether no file-level scan budget remains."""
        remaining = self.remaining_seconds()
        return remaining is not None and remaining <= 0.0

    def config_with_remaining_timeout(self, config: ExecutionConfig) -> ExecutionConfig:
        """Return ``config`` with timeout fields clipped to the remaining file budget."""
        remaining_seconds = self.remaining_seconds()
        if remaining_seconds is None:
            return config
        remaining = max(_MIN_REMAINING_TIMEOUT_SECONDS, remaining_seconds)
        solver_timeout_ms = max(1, min(config.solver_timeout_ms, int(remaining * 1000)))
        return dataclasses.replace(
            config,
            timeout_seconds=remaining,
            solver_timeout_ms=solver_timeout_ms,
        )
