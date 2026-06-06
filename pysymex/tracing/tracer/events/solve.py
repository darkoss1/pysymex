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

"""Solver telemetry event emission behavior."""

from __future__ import annotations

from typing import TYPE_CHECKING

import z3
from pydantic import BaseModel

from pysymex.tracing.schemas import SolveEvent, TracerConfig
from pysymex.tracing.tracer.helpers import serialize_model_excerpt
from pysymex.tracing.z3.serializer import Z3Serializer


class TracerSolveMixin:
    """Solver telemetry event emission behavior."""

    if TYPE_CHECKING:
        config: TracerConfig
        _serializer: Z3Serializer

        def _next_seq(self) -> int:
            """Allocate and return the next event sequence number.

            Returns:
                The next sequential integer identifier.
            """
            ...

        def _write_event(self, event: BaseModel, *, force_flush: bool) -> None:
            """Write a telemetry event to the trace output buffer.

            Args:
                event: The event payload model to write.
                force_flush: Whether to flush the output file immediately.
            """
            ...

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
        """Emit an SMT solver telemetry event.

        Args:
            constraints:  The constraint list that was checked.
            result_str:   ``"sat"``, ``"unsat"``, or ``"unknown"``.
            latency_ms:   Wall-clock query time in milliseconds.
            cache_hit:    Whether the result was found in the LRU cache.
            model:        The Z3 model (satisfying assignment), or ``None``.
            path_id:      Execution path for context.
            pc:           Program counter for context.
        """
        if not self.config.enabled:
            return

        model_excerpt: dict[str, str] | None = None
        if result_str == "sat" and model is not None:
            model_excerpt = serialize_model_excerpt(
                self._serializer,
                model,
                max_vars=30,
                failure_message="Failed to serialize solver telemetry model",
            )

        result_val = result_str if result_str in ("sat", "unsat", "unknown") else "unknown"

        event = SolveEvent(
            seq=self._next_seq(),
            path_id=path_id,
            pc=pc,
            num_constraints=len(constraints) if constraints else 0,
            result=result_val,
            solver_latency_ms=round(latency_ms, 3),
            cache_hit=cache_hit,
            model_excerpt=model_excerpt,
        )
        self._write_event(event, force_flush=False)


__all__ = ["TracerSolveMixin"]
