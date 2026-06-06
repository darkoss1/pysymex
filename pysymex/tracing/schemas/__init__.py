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

"""Typed event schemas for the pysymex execution tracer.

All event models are immutable Pydantic v2 BaseModels that serialise to a
single JSONL line via ``model_dump_json()``.  The :data:`TraceEvent` type is a
discriminated union of all nine event types, enabling O(1) dispatch and
safe round-tripping via ``pydantic.TypeAdapter``.

Log structure (Keyframe + Delta):
  - **system_context** -- very first line; static environment metadata.
  - **step**           -- incremental delta per executed instruction.
  - **keyframe**       -- full-state snapshot on fork / prune / issue.
  - **solve**          -- SMT telemetry per solver invocation.
  - **detector_query** -- detector feasibility-query decisions.
  - **path_feasibility** -- execution path-feasibility policy decisions.
  - **scheduler**      -- path-frontier enqueue/select decisions.
  - **fallback**       -- degraded precision, unsupported, unknown, or bound event.
  - **issue**          -- detected bug with severity, model, causality.

Design decisions
~~~~~~~~~~~~~~~~
* All models use ``ConfigDict(frozen=True)`` so instances are immutable and
  hashable, preventing accidental mutation before serialisation.
* ``event_type`` literal fields carry a default value, making them optional
  in constructors while always being emitted in JSON output.
* The discriminated union on ``event_type`` allows ``TypeAdapter(TraceEvent)``
  to reliably round-trip any event from raw JSON without a manual dispatch.
* ``str`` fields holding Z3 SMT-LIB text are not validated beyond the type
  constraint; validation is the responsibility of the Z3 serialisation layer.
* ``seq`` is a monotonically-increasing integer common to all event types.
"""

from __future__ import annotations

from pysymex.config.tracing import TracerConfig, VerbosityLevel
from pysymex.tracing.schemas.events import (
    DetectorQueryTraceEvent,
    FallbackTraceEvent,
    IssueEvent,
    KeyframeEvent,
    PathFeasibilityTraceEvent,
    SchedulerTraceEvent,
    SolveEvent,
    StepDeltaEvent,
    SystemContextEvent,
    TraceEvent,
)
from pysymex.tracing.schemas.primitives import (
    ConstraintEntry,
    StackDiff,
    VarDiff,
)


__all__ = [
    "ConstraintEntry",
    "DetectorQueryTraceEvent",
    "FallbackTraceEvent",
    "IssueEvent",
    "KeyframeEvent",
    "PathFeasibilityTraceEvent",
    "SchedulerTraceEvent",
    "SolveEvent",
    "StackDiff",
    "StepDeltaEvent",
    "SystemContextEvent",
    "TraceEvent",
    "TracerConfig",
    "VarDiff",
    "VerbosityLevel",
]
