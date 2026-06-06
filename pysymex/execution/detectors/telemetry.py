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

"""Detector feasibility-query telemetry records.

This module owns bounded diagnostic records emitted by detector SAT-query
policy. These records are observational only: they do not participate in
solver, detector, publication, or cache decisions.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Literal, TypeAlias

if TYPE_CHECKING:
    import z3

    from pysymex.execution.session.state import ExecutionSession

DetectorQueryResultSource: TypeAlias = Literal[
    "literal_true",
    "literal_false",
    "cache_hit",
    "inconclusive_prefix_witness",
    "inconclusive_prefix_unknown",
    "zero_float_witness",
    "solver_sat",
    "solver_unsat",
    "witness_after_solver_unknown",
    "solver_unknown",
]
"""Closed set of detector-query decision sources used in trace output."""

_MAX_DETECTOR_QUERY_CONSTRAINT_EXCERPT = 8


@dataclass(frozen=True, slots=True)
class DetectorQueryContext:
    """Instruction and detector metadata attached to one feasibility query."""

    detector_name: str = ""
    issue_kind: str = ""
    path_id: int = 0
    pc: int | None = None
    line_number: int | None = None
    opcode: str = ""
    state_constraints_count: int = 0
    pending_constraint_count: int = 0
    last_inconclusive_feasibility_len: int = -1


@dataclass(frozen=True, slots=True)
class DetectorQueryEvent:
    """Bounded diagnostic outcome for one detector feasibility query.

    The event deliberately stores counts and decision-source metadata rather
    than raw constraints, keeping traces useful for diagnosis without making
    normal execution allocate large solver strings.
    """

    detector_name: str
    issue_kind: str
    path_id: int
    pc: int | None
    line_number: int | None
    opcode: str
    raw_constraints_count: int
    constraints_count: int
    state_constraints_count: int
    pending_constraint_count: int
    last_inconclusive_feasibility_len: int
    inconclusive_prefix_len: int | None
    result: bool
    result_source: DetectorQueryResultSource
    cache_hit: bool
    witness_used: bool
    constraint_excerpt: tuple[z3.BoolRef, ...] = ()


def detector_query_constraint_excerpt(
    constraints: list[z3.BoolRef] | None,
) -> tuple[z3.BoolRef, ...]:
    """Return the latest detector-query constraints without serializing them."""
    if not constraints:
        return ()
    limit = _MAX_DETECTOR_QUERY_CONSTRAINT_EXCERPT
    return tuple(constraints[-limit:])


def emit_detector_query_event(
    *,
    session: ExecutionSession,
    query_context: DetectorQueryContext | None,
    raw_constraints_count: int,
    constraints_count: int,
    inconclusive_prefix_len: int | None,
    result: bool,
    result_source: DetectorQueryResultSource,
    cache_hit: bool,
    witness_used: bool,
    constraints: list[z3.BoolRef] | None = None,
) -> None:
    """Emit passive detector-query telemetry only when an observer is installed."""
    if not session.detector_query_event_observers:
        return
    context = query_context if query_context is not None else DetectorQueryContext()
    session.record_detector_query_event(
        DetectorQueryEvent(
            detector_name=context.detector_name,
            issue_kind=context.issue_kind,
            path_id=context.path_id,
            pc=context.pc,
            line_number=context.line_number,
            opcode=context.opcode,
            raw_constraints_count=raw_constraints_count,
            constraints_count=constraints_count,
            state_constraints_count=context.state_constraints_count,
            pending_constraint_count=context.pending_constraint_count,
            last_inconclusive_feasibility_len=context.last_inconclusive_feasibility_len,
            inconclusive_prefix_len=inconclusive_prefix_len,
            result=result,
            result_source=result_source,
            cache_hit=cache_hit,
            witness_used=witness_used,
            constraint_excerpt=detector_query_constraint_excerpt(constraints),
        )
    )


__all__ = [
    "detector_query_constraint_excerpt",
    "DetectorQueryContext",
    "DetectorQueryEvent",
    "DetectorQueryResultSource",
    "emit_detector_query_event",
]
