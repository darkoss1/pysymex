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

"""Concrete trace event schemas and event union."""

from __future__ import annotations

import sys
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field

from pysymex._internal.tracing.schemas.primitives import (
    ConfigScalar,
    ConstraintEntry,
    StackDiff,
    TraceSchemaDefaults,
    VarDiff,
)


class SystemContextEvent(BaseModel):
    """First line of every trace file -- static analysis-session metadata."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["system_context"] = "system_context"
    timestamp_iso: str = ""
    pysymex_version: str = ""
    z3_version: str = "unavailable"
    function_name: str = ""
    function_signature: str = ""
    source_file: str = "<unknown>"
    python_version: str = Field(default_factory=lambda: sys.version)
    initial_symbolic_args: dict[str, str] = Field(
        default_factory=TraceSchemaDefaults.empty_string_map,
    )
    tracer_config: dict[str, ConfigScalar] = Field(
        default_factory=TraceSchemaDefaults.empty_config_map,
    )


class StepDeltaEvent(BaseModel):
    """Incremental diff emitted after every successfully dispatched instruction."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["step"] = "step"
    seq: int = 0
    path_id: int = 0
    pc: int = 0
    offset: int = 0
    opcode: str = "UNKNOWN"
    step_latency_ms: float | None = None
    source_line: int | None = None
    source_text: str | None = None
    stack_diff: StackDiff = Field(default_factory=StackDiff)
    var_diff: VarDiff = Field(default_factory=VarDiff)
    mem_diff: dict[str, str] = Field(default_factory=TraceSchemaDefaults.empty_string_map)
    constraint_added: ConstraintEntry | None = None


class KeyframeEvent(BaseModel):
    """Full-state snapshot -- emitted on fork, prune, and issue events."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["keyframe"] = "keyframe"
    seq: int = 0
    trigger: Literal["fork", "prune", "issue"] = "prune"
    path_id: int = 0
    parent_path_id: int | None = None
    child_path_ids: list[int] | None = None
    pc: int = 0
    depth: int = 0
    stack: list[str] = Field(default_factory=TraceSchemaDefaults.empty_strings)
    local_vars: dict[str, str] = Field(default_factory=TraceSchemaDefaults.empty_string_map)
    global_vars: dict[str, str] = Field(default_factory=TraceSchemaDefaults.empty_string_map)
    path_constraints: list[ConstraintEntry] = Field(
        default_factory=TraceSchemaDefaults.empty_constraints,
    )
    prune_reason: str | None = None


class SolveEvent(BaseModel):
    """SMT solver invocation telemetry."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["solve"] = "solve"
    seq: int = 0
    path_id: int = 0
    pc: int = 0
    num_constraints: int = 0
    result: Literal["sat", "unsat", "unknown"] = "unknown"
    solver_latency_ms: float = 0.0
    cache_hit: bool = False
    model_excerpt: dict[str, str] | None = None


class DetectorQueryTraceEvent(BaseModel):
    """Detector feasibility-query outcome telemetry."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["detector_query"] = "detector_query"
    seq: int = 0
    path_id: int = 0
    pc: int | None = None
    source_line: int | None = None
    detector_name: str = ""
    issue_kind: str = ""
    opcode: str = ""
    raw_constraints_count: int = 0
    constraints_count: int = 0
    state_constraints_count: int = 0
    pending_constraint_count: int = 0
    last_inconclusive_feasibility_len: int = -1
    inconclusive_prefix_len: int | None = None
    result: bool = False
    result_source: Literal[
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
    ] = "solver_unknown"
    cache_hit: bool = False
    witness_used: bool = False
    constraint_excerpt: list[ConstraintEntry] = Field(
        default_factory=TraceSchemaDefaults.empty_constraints,
    )


class PathFeasibilityTraceEvent(BaseModel):
    """Path-feasibility policy outcome telemetry."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["path_feasibility"] = "path_feasibility"
    seq: int = 0
    path_id: int = 0
    pc: int | None = None
    source_line: int | None = None
    pending_constraint_count: int = 0
    path_constraints_count: int = 0
    known_sat_prefix_len: int = 0
    query_prefix_len: int = 0
    query_constraints_count: int = 0
    result: Literal["feasible", "infeasible", "inconclusive"] = "inconclusive"
    result_source: Literal[
        "literal_true",
        "literal_false",
        "simplified_false",
        "literal_substitution_false",
        "literal_substitution_true",
        "hard_theory_witness",
        "hard_theory_skipped",
        "solver_sat",
        "solver_unsat",
        "solver_unknown",
    ] = "solver_unknown"
    solver_called: bool = False
    hard_theory_skipped: bool = False
    policy_latency_ms: float = 0.0
    query_constraint_excerpt: list[ConstraintEntry] = Field(
        default_factory=TraceSchemaDefaults.empty_constraints,
    )


class SchedulerTraceEvent(BaseModel):
    """Path-frontier enqueue and selection telemetry."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["scheduler"] = "scheduler"
    seq: int = 0
    action: Literal["enqueue", "select"] = "select"
    decision_source: Literal["polar_native", "cegis_execute", "first_live_fallback"] = (
        "polar_native"
    )
    queue_state_id: int | None = None
    path_id: int = 0
    pc: int | None = None
    source_line: int | None = None
    depth: int = 0
    pending_constraint_count: int = 0
    path_constraints_count: int = 0
    frontier_size_before: int = 0
    frontier_size_after: int = 0
    branch_degree: int | None = None
    priority: float | None = None
    detector_obligation_count: int = 0
    estimated_resident_units: int = 0
    unsupported_live_count: int = 0
    havoc_live_count: int = 0
    reason: str = ""


class FallbackTraceEvent(BaseModel):
    """Structured degraded-execution or fallback telemetry."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["fallback"] = "fallback"
    seq: int = 0
    path_id: int = 0
    pc: int | None = None
    source_line: int | None = None
    function_name: str | None = None
    label: str = ""
    owner: str = ""
    kind: str = ""
    soundness: str = ""
    false_positive_risk: str = ""
    false_negative_risk: str = ""
    reason: str = ""


class IssueEvent(BaseModel):
    """A bug or vulnerability found by a detector."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["issue"] = "issue"
    seq: int = 0
    path_id: int = 0
    pc: int = 0
    source_line: int | None = None
    severity: str = "HIGH"
    detector_name: str = ""
    issue_kind: str = "UNKNOWN"
    message: str = ""
    source_text: str | None = None
    confidence: float = 1.0
    likelihood_score: float = 1.0
    constraints_at_issue: list[ConstraintEntry] = Field(
        default_factory=TraceSchemaDefaults.empty_constraints,
    )
    z3_model: dict[str, str] | None = None


TraceEvent = Annotated[
    SystemContextEvent
    | StepDeltaEvent
    | KeyframeEvent
    | SolveEvent
    | DetectorQueryTraceEvent
    | PathFeasibilityTraceEvent
    | SchedulerTraceEvent
    | FallbackTraceEvent
    | IssueEvent,
    Field(discriminator="event_type"),
]
"""Discriminated union of all trace events keyed on ``event_type``.

Usage (reading a trace file)::

    from pydantic import TypeAdapter
    from pysymex._internal.tracing.schemas.events import TraceEvent

    adapter = TypeAdapter(TraceEvent)
    events = [adapter.validate_json(line) for line in open("trace.jsonl")]
"""
