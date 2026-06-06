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

"""Telemetry helpers for :class:`TracingSolverProxy`."""

from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import TYPE_CHECKING, Protocol

import z3

from pysymex.logger import get_logger

if TYPE_CHECKING:
    from pysymex.core.solver.engine.results import SolverResult


logger = get_logger(__name__)


class TraceStateLike(Protocol):
    """Protocol representing virtual machine state structures expected by tracing."""

    path_id: int
    pc: int


class SolverTelemetrySink(Protocol):
    """Protocol for classes that consume solver performance and validation events."""

    def on_solve(
        self,
        constraints: list[z3.BoolRef],
        result_str: str,
        latency_ms: float,
        cache_hit: bool,
        model: object,
        path_id: int = 0,
        pc: int = 0,
    ) -> None:
        """Log solver query metadata when a satisfiability check is performed.

        Args:
            constraints: The list of boolean constraints checked by the solver.
            result_str: The solve result status ('sat', 'unsat', or 'unknown').
            latency_ms: Solving latency measured in milliseconds.
            cache_hit: True if the query was resolved via a local results cache.
            model: The satisfying assignment model if result is 'sat', otherwise None.
            path_id: Numeric identifier of the execution path.
            pc: Program counter offset at the query location.
        """
        ...


TraceStateGetter = Callable[[], TraceStateLike | None]


def cache_hits_for(solver: object) -> int:
    """Return the wrapped solver's cache-hit counter if present."""
    return getattr(solver, "_cache_hits", 0)


def z3_check_result_name(result: object) -> str:
    """Map a Z3 check result to trace schema result text."""
    if result == z3.sat:
        return "sat"
    if result == z3.unsat:
        return "unsat"
    return "unknown"


def solver_result_name(result: SolverResult) -> str:
    """Map a structured solver result to trace schema result text."""
    if result.is_sat:
        return "sat"
    if result.is_unsat:
        return "unsat"
    return "unknown"


def emit_solver_telemetry(
    *,
    tracer: SolverTelemetrySink,
    state_getter: TraceStateGetter,
    constraints: Iterable[z3.BoolRef],
    result_str: str,
    latency_ms: float,
    cache_hit: bool,
    model: object,
    method_name: str,
) -> None:
    """Emit solver telemetry without allowing tracing failures to affect execution."""
    try:
        state = state_getter()
        path_id = getattr(state, "path_id", 0) if state is not None else 0
        pc = getattr(state, "pc", 0) if state is not None else 0
        tracer.on_solve(
            constraints=list(constraints),
            result_str=result_str,
            latency_ms=latency_ms,
            cache_hit=cache_hit,
            model=model,
            path_id=path_id,
            pc=pc,
        )
    except Exception:
        logger.warning(
            "TracingSolverProxy.%s telemetry emission failed",
            method_name,
            exc_info=True,
        )


__all__ = [
    "cache_hits_for",
    "emit_solver_telemetry",
    "solver_result_name",
    "z3_check_result_name",
]
