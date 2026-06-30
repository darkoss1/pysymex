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

"""Summary bucket records for trace analyzer stream output."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TypeVar

CountKeyT = TypeVar("CountKeyT")


@dataclass
class LatencyStats:
    """Aggregate latency samples for summary output."""

    count: int = 0
    total_ms: float = 0.0
    max_ms: float = 0.0
    max_seq: int | None = None

    def record(self, latency_ms: float, seq: int) -> None:
        """Record one latency sample."""
        self.count += 1
        self.total_ms += latency_ms
        if self.max_seq is None or latency_ms > self.max_ms:
            self.max_ms = latency_ms
            self.max_seq = seq

    @property
    def avg_ms(self) -> float:
        """Return the average latency in milliseconds."""
        if self.count == 0:
            return 0.0
        return self.total_ms / self.count


@dataclass
class CountStats:
    """Count occurrences and sequence bounds for a diagnostic bucket."""

    count: int = 0
    first_seq: int | None = None
    last_seq: int | None = None

    def record(self, seq: int) -> None:
        """Record one occurrence."""
        self.count += 1
        if self.first_seq is None:
            self.first_seq = seq
        self.last_seq = seq
