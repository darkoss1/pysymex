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

"""Timeout and graceful degradation helpers."""

from __future__ import annotations

import signal
import sys
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass, field

from pysymex.logger import get_logger
from pysymex.resources.models import AnalysisTimeoutError, LimitExceeded, ResourceSnapshot
from pysymex.resources.tracker import ResourceTracker

logger = get_logger(__name__)


@contextmanager
def timeout_context(
    seconds: float,
    message: str = "Operation timed out",
) -> Generator[None, None, None]:
    """Context manager that enforces a hard wall-clock timeout using SIGALRM."""
    del message
    if sys.platform == "win32":
        logger.debug("timeout_context uses no SIGALRM enforcement on Windows")
        yield
        return

    def handler(_signum: int, frame: object) -> None:
        del frame
        raise AnalysisTimeoutError(seconds, seconds)

    old_handler = signal.signal(signal.SIGALRM, handler)
    signal.setitimer(signal.ITIMER_REAL, seconds)
    try:
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, old_handler)


class GracefulDegradation:
    """Orchestrator for engine self-preservation strategies."""

    def __init__(self, tracker: ResourceTracker) -> None:
        """Initialize the graceful degradation orchestrator.

        Args:
            tracker (ResourceTracker): The resource tracker to monitor limits and degradation state.
        """
        self.tracker = tracker
        self._strategies: list[str] = []

    def should_skip_path(self, path_complexity: int) -> bool:
        """Check if a path should be skipped for degradation."""
        if not self.tracker.is_degraded:
            return False
        return path_complexity > 10

    def should_approximate_constraint(self) -> bool:
        """Check if constraints should be approximated."""
        progress = self.tracker.get_progress()
        return progress["time"] > 90 or progress["paths"] > 95

    def should_stop_early(self) -> bool:
        """Check if analysis should stop early."""
        try:
            self.tracker.check_all_limits()
            return False
        except LimitExceeded:
            logger.warning("Resource limit exceeded; stopping analysis early", exc_info=True)
            return True

    def get_active_strategies(self) -> list[str]:
        """Get list of active degradation strategies."""
        return list(self._strategies)

    def activate_strategy(self, strategy: str) -> None:
        """Activate a degradation strategy."""
        if strategy not in self._strategies:
            self._strategies.append(strategy)
            logger.warning("Activated graceful degradation strategy: %s", strategy)


@dataclass
class PartialResult:
    """Result from an interrupted or degraded analysis run."""

    completed: bool = False
    reason: str | None = None
    paths_completed: int = 0
    paths_remaining_estimate: int = 0
    issues_found: list[object] = field(default_factory=lambda: list[object]())
    warnings: list[str] = field(default_factory=lambda: list[str]())
    resource_snapshot: ResourceSnapshot | None = None

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "completed": self.completed,
            "reason": self.reason,
            "paths_completed": self.paths_completed,
            "paths_remaining_estimate": self.paths_remaining_estimate,
            "issues_found": len(self.issues_found),
            "warnings": self.warnings,
            "resources": self.resource_snapshot.to_dict() if self.resource_snapshot else None,
        }


def create_partial_result(
    tracker: ResourceTracker,
    issues: list[object],
    error: Exception | None = None,
) -> PartialResult:
    """Create a partial result from current tracker state."""
    snap = tracker.snapshot()
    result = PartialResult(
        completed=error is None,
        paths_completed=snap.paths_explored,
        issues_found=issues,
        resource_snapshot=snap,
    )
    if error:
        if isinstance(error, LimitExceeded):
            result.reason = f"Limit exceeded: {error.resource_type.name}"
            logger.warning(
                "Created partial result after resource limit: %s", error.resource_type.name
            )
        else:
            result.reason = str(error)
            logger.warning("Created partial result after analysis error", exc_info=error)
    return result
