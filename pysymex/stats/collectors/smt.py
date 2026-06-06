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

"""SMT solver metrics collector.

Analyzes solver query events to track solver query outcomes (satisfiable,
unsatisfiable, and unknown) and aggregates statistics such as clause counts and
the SAT/UNSAT ratio.
"""

from __future__ import annotations

from .base import MetricCollector
from ..types import Event, EventType


def _counter_increment(event: Event) -> int:
    """Return the count represented by a solver counter event."""
    if event.value <= 0:
        return 1
    return max(1, int(event.value))


class SmtCollector(MetricCollector):
    """Collector for solver theory and hardness heuristic (rho)."""

    def __init__(self) -> None:
        """Initialize the SMT metrics collector.

        Initializes query counters (SAT, UNSAT, unknown), the cumulative clause count,
        and the metrics dictionary.
        """
        self.reset()

    def reset(self) -> None:
        """Reset scan-local solver counters."""
        self.query_count = 0
        self.sat_count = 0
        self.unsat_count = 0
        self.unknown_count = 0
        self.total_clauses = 0

        self._metrics: dict[str, float | int | str] = {
            "solver_queries": 0,
            "solver_sat": 0,
            "solver_unsat": 0,
            "solver_unknown": 0,
            "solver_total_clauses": 0,
            "solver_avg_clauses": 0.0,
            "sat_unsat_ratio": 0.0,
        }

    def process(self, events: list[Event]) -> None:
        """Process SMT-related events to update solver metrics.

        Increments counters for satisfiable, unsatisfiable, and unknown solver results.
        Accumulates clause counts from solver queries and recalculates the ratio of
        satisfiable queries to total resolved (SAT + UNSAT) queries.

        Args:
            events: A list of Event instances containing SMT solver metrics.
        """
        for event in events:
            if event.type == EventType.SOLVER_SAT:
                self.sat_count += _counter_increment(event)
            elif event.type == EventType.SOLVER_UNSAT:
                self.unsat_count += _counter_increment(event)
            elif event.type == EventType.SOLVER_UNKNOWN:
                self.unknown_count += _counter_increment(event)
            elif event.type == EventType.SOLVER_QUERY:
                self.query_count += _counter_increment(event)
                clauses = event.metadata.get("clauses")
                if isinstance(clauses, bool):
                    continue
                if isinstance(clauses, int):
                    self.total_clauses += clauses
                elif isinstance(clauses, float):
                    self.total_clauses += int(clauses)

        total_queries = self.sat_count + self.unsat_count
        if total_queries > 0:
            self._metrics["sat_unsat_ratio"] = self.sat_count / total_queries
        self._metrics["solver_queries"] = self.query_count
        self._metrics["solver_sat"] = self.sat_count
        self._metrics["solver_unsat"] = self.unsat_count
        self._metrics["solver_unknown"] = self.unknown_count
        self._metrics["solver_total_clauses"] = self.total_clauses
        if self.query_count > 0:
            self._metrics["solver_avg_clauses"] = self.total_clauses / self.query_count

    def get_metrics(self) -> dict[str, float | int | str]:
        """Retrieve a copy of the computed SMT metrics.

        Returns:
            A dictionary containing raw solver counters, clause aggregates, and
            ``sat_unsat_ratio`` for backwards-compatible display.
        """
        return self._metrics.copy()
