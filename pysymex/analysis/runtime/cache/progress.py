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

"""Thread-safe progress reporting for parallel analysis batches."""

from __future__ import annotations

from pysymex.logger import get_logger
import threading
from collections.abc import Callable

logger = get_logger(__name__)


class ProgressReporter:
    """Thread-safe progress tracker with optional observer callbacks.

    Counts completed and failed tasks, firing registered callbacks
    (with ``completed``, ``total``, ``failed`` arguments) after each
    completion.
    """

    def __init__(self) -> None:
        """Initialize a ProgressReporter instance."""
        self.total = 0
        self.completed = 0
        self.failed = 0
        self.lock = threading.Lock()
        self._callbacks: list[Callable[[int, int, int], None]] = []

    def set_total(self, total: int) -> None:
        """Reset counters and set the total task count for a new batch."""
        with self.lock:
            self.total = total
            self.completed = 0
            self.failed = 0

    def report_complete(self, success: bool = True) -> None:
        """Record one task completion (failure if *success* is ``False``)."""
        with self.lock:
            self.completed += 1
            if not success:
                self.failed += 1
            completed = self.completed
            total = self.total
            failed = self.failed
            callbacks = list(self._callbacks)
        for callback in callbacks:
            try:
                callback(completed, total, failed)
            except Exception:
                logger.debug("Progress callback failed", exc_info=True)

    def on_progress(self, callback: Callable[[int, int, int], None]) -> None:
        """Register a callback invoked on each completion with ``(completed, total, failed)``."""
        with self.lock:
            self._callbacks.append(callback)

    @property
    def progress(self) -> float:
        """Return completion fraction (0.0 – 1.0)."""
        with self.lock:
            return self.completed / self.total if self.total > 0 else 0.0

    def format_progress(self) -> str:
        """Return a human-readable string like ``[3/10] 30.0% (1 failed)``."""
        with self.lock:
            pct = (self.completed / self.total * 100) if self.total > 0 else 0.0
            return f"[{self.completed}/{self.total}] {pct:.1f}% ({self.failed} failed)"


__all__ = ["ProgressReporter"]
