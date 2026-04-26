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

import abc

from ..types import Event


class MetricCollector(abc.ABC):
    """Base interface for all Metric Collectors."""

    @abc.abstractmethod
    def process(self, events: list[Event]) -> None:
        """Process a batch of events and update internal mathematical models."""
        raise RuntimeError("MetricCollector.process must be implemented by subclasses")

    @abc.abstractmethod
    def get_metrics(self) -> dict[str, float | int | str]:
        """Retrieve the computed metrics."""
        raise RuntimeError("MetricCollector.get_metrics must be implemented by subclasses")
