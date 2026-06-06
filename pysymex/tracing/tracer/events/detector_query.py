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

"""Detector feasibility-query trace event emission behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel

from pysymex.tracing.schemas import DetectorQueryTraceEvent, TracerConfig
from pysymex.tracing.tracer.helpers import serialize_constraint_entries

if TYPE_CHECKING:
    from pysymex.core.state.record import VMState
    from pysymex.execution.detectors import DetectorQueryEvent
    from pysymex.tracing.z3.serializer import Z3Serializer


class TracerDetectorQueryMixin:
    """Structured trace emission for detector feasibility-query outcomes."""

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

    def on_detector_query_event(self, event: DetectorQueryEvent) -> None:
        """Emit structured telemetry for one detector feasibility query."""
        if not self.config.enabled:
            return

        state = self._current_state
        trace_event = DetectorQueryTraceEvent(
            seq=self._next_seq(),
            path_id=event.path_id if event.path_id != 0 else _current_path_id(state),
            pc=event.pc if event.pc is not None else _current_pc(state),
            source_line=event.line_number,
            detector_name=event.detector_name,
            issue_kind=event.issue_kind,
            opcode=event.opcode,
            raw_constraints_count=event.raw_constraints_count,
            constraints_count=event.constraints_count,
            state_constraints_count=event.state_constraints_count,
            pending_constraint_count=event.pending_constraint_count,
            last_inconclusive_feasibility_len=event.last_inconclusive_feasibility_len,
            inconclusive_prefix_len=event.inconclusive_prefix_len,
            result=event.result,
            result_source=event.result_source,
            cache_hit=event.cache_hit,
            witness_used=event.witness_used,
            constraint_excerpt=serialize_constraint_entries(
                self._serializer,
                event.constraint_excerpt,
                "detector query constraint excerpt",
                limit=self.config.max_constraint_display,
            ),
        )
        self._write_event(trace_event, force_flush=False)


def _current_path_id(state: VMState | None) -> int:
    """Return the active path identifier when detector context omitted it."""
    return state.path_id if state is not None else 0


def _current_pc(state: VMState | None) -> int | None:
    """Return the active program counter when detector context omitted it."""
    return state.pc if state is not None else None


__all__ = ["TracerDetectorQueryMixin"]
