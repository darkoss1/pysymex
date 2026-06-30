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

"""Benchmark workload stat extraction helpers."""

from __future__ import annotations


class WorkloadStatsOps:
    """Domain owner for benchmark workload stat normalization."""

    @staticmethod
    def solver_queries_from_stats(stats: dict[str, object]) -> int:
        """Extract physical Z3 check count from execution result stats."""
        queries = stats.get("z3_check_calls", stats.get("queries", 0))
        if isinstance(queries, bool):
            return 0
        if isinstance(queries, int):
            return queries
        return 0

    @staticmethod
    def solver_outcome_counts_from_stats(stats: dict[str, object]) -> dict[str, int]:
        """Extract solver SAT/UNSAT/UNKNOWN outcome counts from execution stats."""
        outcomes: dict[str, int] = {}
        for source_key, output_key in (
            ("sat_results", "solver_sat"),
            ("unsat_results", "solver_unsat"),
            ("unknown_results", "solver_unknown"),
        ):
            value = stats.get(source_key, 0)
            outcomes[output_key] = (
                0 if isinstance(value, bool) or not isinstance(value, int) else value
            )
        return outcomes

    @staticmethod
    def coverage_count(coverage: set[int]) -> int:
        """Return the concrete number of covered instructions."""
        return len(coverage)
