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

"""File-level execution metrics for source scan orchestration.

This module owns aggregation of per-code-object execution measurements into the
file-level scan evidence consumed by scanner results. It does not execute code,
emit issues, or classify detector findings.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, cast

from pysymex._internal.core.cache.code.instructions import get_instructions
from pysymex._internal.core.outcome import OutcomeEvidence, OutcomePolicy

if TYPE_CHECKING:
    import types

    from pysymex._internal.execution.results.result import ExecutionResult

_AGGREGATE_SOLVER_INT_STATS = (
    "queries",
    "logical_queries",
    "z3_check_calls",
    "sat_results",
    "unsat_results",
    "unknown_results",
    "cache_hits",
    "z3_ast_cache_hits",
    "z3_ast_cache_misses",
)
_AGGREGATE_SOLVER_FLOAT_STATS = ("solver_time_ms",)


@dataclass
class ExecutionMetrics:
    """Aggregate execution measurements reported by a file scan."""

    paths_explored: int = 0
    paths_pruned: int = 0
    memory_samples: list[float] = field(default_factory=list[float])
    execution_errors: list[str] = field(default_factory=list[str])
    degraded_passes: list[str] = field(default_factory=list[str])
    outcome_evidence: list[OutcomeEvidence] = field(default_factory=list[OutcomeEvidence])
    degraded_by_code: dict[int, frozenset[str]] = field(default_factory=dict[int, frozenset[str]])
    complete_coverage: dict[int, frozenset[int]] = field(default_factory=dict[int, frozenset[int]])
    suppressed_issue_offsets_by_code: dict[int, frozenset[int]] = field(
        default_factory=dict[int, frozenset[int]],
    )
    solver_stats: dict[str, object] = field(default_factory=dict[str, object])

    def record(self, code: types.CodeType, execution: ExecutionResult) -> None:
        """Record metrics from an individual execution result."""
        self.paths_explored += execution.paths_explored
        self.paths_pruned += execution.paths_pruned
        self._record_solver_stats(execution.solver_stats)
        self.outcome_evidence.extend(execution.outcome_evidence)
        if execution.avg_memory_mb > 0:
            self.memory_samples.append(execution.avg_memory_mb)
        for degraded_pass in execution.degraded_passes:
            if degraded_pass not in self.degraded_passes:
                self.degraded_passes.append(degraded_pass)
        if execution.degraded_passes:
            existing = self.degraded_by_code.get(id(code), frozenset())
            self.degraded_by_code[id(code)] = existing | frozenset(execution.degraded_passes)
        if execution.paths_completed == 0 or execution.paths_pruned or execution.degraded_passes:
            return
        instructions = list(get_instructions(code))
        self.complete_coverage[id(code)] = frozenset(
            instructions[index].offset
            for index in execution.coverage
            if 0 <= index < len(instructions)
        )
        self.suppressed_issue_offsets_by_code[id(code)] = execution.suppressed_issue_offsets

    def record_degraded_pass(self, degraded_pass: str) -> None:
        """Record one file-level degradation label once."""
        if degraded_pass not in self.degraded_passes:
            self.degraded_passes.append(degraded_pass)

    @property
    def avg_memory_mb(self) -> float:
        """Return the average memory usage across recorded execution samples."""
        if not self.memory_samples:
            return 0.0
        return sum(self.memory_samples) / len(self.memory_samples)

    def record_error(self, code: types.CodeType, exc: Exception) -> None:
        """Preserve an internal pass failure as structured scan-status evidence."""
        self.execution_errors.append(f"{code.co_name}: {type(exc).__name__}({exc})")
        self.outcome_evidence.append(
            OutcomePolicy.evidence_from_exception(exc, source=f"scan_execution:{code.co_name}"),
        )

    @property
    def error(self) -> str | None:
        """Return a consolidated error message if execution errors were recorded."""
        if not self.execution_errors:
            return None
        return f"Execution Error: {'; '.join(self.execution_errors)}"

    def _record_solver_stats(self, stats: dict[str, object]) -> None:
        """Accumulate stable scalar solver counters from an execution result."""
        for key in _AGGREGATE_SOLVER_INT_STATS:
            if key not in stats:
                continue
            value = stats.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int):
                continue
            current = self.solver_stats.get(key, 0)
            if isinstance(current, bool) or not isinstance(current, int):
                current = 0
            self.solver_stats[key] = current + value

        for key in _AGGREGATE_SOLVER_FLOAT_STATS:
            value = stats.get(key, 0.0)
            if isinstance(value, bool) or not isinstance(value, int | float):
                continue
            current = self.solver_stats.get(key, 0.0)
            if isinstance(current, bool) or not isinstance(current, int | float):
                current = 0.0
            self.solver_stats[key] = float(current) + float(value)

        detector_queries = stats.get("detector_queries")
        if isinstance(detector_queries, Mapping):
            query_stats = cast("Mapping[object, object]", detector_queries)
            for source_key, target_key in (
                ("cache_hits", "detector_query_cache_hits"),
                ("cache_misses", "detector_query_cache_misses"),
            ):
                value = query_stats.get(source_key, 0)
                if isinstance(value, bool) or not isinstance(value, int):
                    continue
                current = self.solver_stats.get(target_key, 0)
                if isinstance(current, bool) or not isinstance(current, int):
                    current = 0
                self.solver_stats[target_key] = current + value
        hits = self.solver_stats.get("detector_query_cache_hits", 0)
        misses = self.solver_stats.get("detector_query_cache_misses", 0)
        if isinstance(hits, int) and not isinstance(hits, bool):
            if isinstance(misses, int) and not isinstance(misses, bool):
                self.solver_stats["detector_sink_attempts"] = hits + misses
