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

from .base import MetricCollector
from ..types import Event, EventType


class SmtCollector(MetricCollector):
    """Collector for solver theory and hardness heuristic (rho)."""

    def __init__(self) -> None:
        self._sat_count = 0
        self._unsat_count = 0
        self._unknown_count = 0
        self._total_clauses = 0

        self._metrics: dict[str, float | int | str] = {
            "sat_unsat_ratio": 0.0,
        }

    def process(self, events: list[Event]) -> None:
        for event in events:
            if event.type == EventType.SOLVER_SAT:
                self._sat_count += 1
            elif event.type == EventType.SOLVER_UNSAT:
                self._unsat_count += 1
            elif event.type == EventType.SOLVER_UNKNOWN:
                self._unknown_count += 1
            elif event.type == EventType.SOLVER_QUERY:
                clauses = event.metadata.get("clauses")
                if isinstance(clauses, int):
                    self._total_clauses += clauses
                elif isinstance(clauses, float):
                    self._total_clauses += int(clauses)

        total_queries = self._sat_count + self._unsat_count
        if total_queries > 0:
            self._metrics["sat_unsat_ratio"] = self._sat_count / total_queries

    def get_metrics(self) -> dict[str, float | int | str]:
        return self._metrics.copy()
