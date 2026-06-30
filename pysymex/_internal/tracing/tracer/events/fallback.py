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

"""Fallback and degraded-execution trace event emission behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex._internal.tracing.schemas.events import FallbackTraceEvent

if TYPE_CHECKING:
    from collections.abc import Callable

    from pydantic import BaseModel

    from pysymex._internal.config.tracing.settings import TracerConfig
    from pysymex._internal.core.state.record import VMState
    from pysymex._internal.execution.fallback.types import FallbackEvent

_MAX_FALLBACK_REASON_CHARS = 500


class TracerFallbackMixin:
    """Structured trace emission for existing fallback/degraded events."""

    if TYPE_CHECKING:
        config: TracerConfig
        _current_state: VMState | None
        _fallback_line_resolver: Callable[[int], int | None] | None

        def _next_seq(self) -> int:
            """Allocate and return the next event sequence number."""
            ...

        def _write_event(self, event: BaseModel, *, force_flush: bool) -> None:
            """Write a telemetry event to the trace output buffer."""
            ...

    def on_fallback_event(self, event: FallbackEvent) -> None:
        """Emit structured telemetry for one recorded fallback event."""
        if not self.config.enabled:
            return

        state = self._current_state
        pc = event.pc
        if pc is None and state is not None:
            pc = state.pc
        source_line = event.line_number
        if source_line is None and pc is not None and self._fallback_line_resolver is not None:
            source_line = self._fallback_line_resolver(pc)

        trace_event = FallbackTraceEvent(
            seq=self._next_seq(),
            path_id=state.path_id if state is not None else 0,
            pc=pc,
            source_line=source_line,
            function_name=event.function_name,
            label=event.label,
            owner=event.owner,
            kind=event.kind.value,
            soundness=event.soundness.value,
            false_positive_risk=event.false_positive_risk.value,
            false_negative_risk=event.false_negative_risk.value,
            reason=_bounded_reason(event.reason),
        )
        self._write_event(trace_event, force_flush=False)


def _bounded_reason(reason: str) -> str:
    """Return a trace-safe reason string with a fixed maximum size."""
    if len(reason) <= _MAX_FALLBACK_REASON_CHARS:
        return reason
    return f"{reason[:_MAX_FALLBACK_REASON_CHARS]}..."
