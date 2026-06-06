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

"""Path-feasibility trace event emission behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel

from pysymex.tracing.schemas import PathFeasibilityTraceEvent, TracerConfig
from pysymex.tracing.tracer.helpers import serialize_constraint_entries

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.feasibility.telemetry import PathFeasibilityEvent
    from pysymex.tracing.z3.serializer import Z3Serializer


class TracerPathFeasibilityMixin:
    """Structured trace emission for path-feasibility policy outcomes."""

    if TYPE_CHECKING:
        config: TracerConfig
        _current_state: VMState | None
        _serializer: Z3Serializer

        def _next_seq(self) -> int:
            """Allocate and return the next event sequence number."""
            ...

        def _write_event(self, event: BaseModel, *, force_flush: bool) -> None:
            """Write a telemetry event to the trace output buffer."""
            ...

    def on_path_feasibility_event(self, event: PathFeasibilityEvent) -> None:
        """Emit structured telemetry for one path-feasibility policy decision."""
        if not self.config.enabled:
            return

        state = self._current_state
        trace_event = PathFeasibilityTraceEvent(
            seq=self._next_seq(),
            path_id=event.path_id if event.path_id != 0 else _current_path_id(state),
            pc=event.pc if event.pc is not None else _current_pc(state),
            source_line=event.line_number,
            pending_constraint_count=event.pending_constraint_count,
            path_constraints_count=event.path_constraints_count,
            known_sat_prefix_len=event.known_sat_prefix_len,
            query_prefix_len=event.query_prefix_len,
            query_constraints_count=event.query_constraints_count,
            result=event.result,
            result_source=event.result_source,
            solver_called=event.solver_called,
            hard_theory_skipped=event.hard_theory_skipped,
            policy_latency_ms=event.policy_latency_ms,
            query_constraint_excerpt=serialize_constraint_entries(
                self._serializer,
                event.query_constraint_excerpt,
                "path-feasibility query constraint excerpt",
                limit=self.config.max_constraint_display,
            ),
        )
        self._write_event(trace_event, force_flush=False)


def _current_path_id(state: VMState | None) -> int:
    """Return the active path identifier when feasibility context omitted it."""
    return state.path_id if state is not None else 0


def _current_pc(state: VMState | None) -> int | None:
    """Return the active program counter when feasibility context omitted it."""
    return state.pc if state is not None else None


__all__ = ["TracerPathFeasibilityMixin"]
