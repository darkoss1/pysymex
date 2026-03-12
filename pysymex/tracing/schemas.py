"""Typed event schemas for the pysymex execution tracer.

All event models are immutable Pydantic v2 BaseModels that serialise to a
single JSONL line via ``model_dump_json()``.  The :data:`TraceEvent` type is a
discriminated union of all five event types, enabling O(1) dispatch and
safe round-tripping via ``pydantic.TypeAdapter``.

Log structure (Keyframe + Delta):
  - **system_context** -- very first line; static environment metadata.
  - **step**           -- incremental delta per executed instruction.
  - **keyframe**       -- full-state snapshot on fork / prune / issue.
  - **solve**          -- SMT telemetry per solver invocation.
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

import os
import sys
from enum import StrEnum
from typing import Annotated, Literal, TypeAlias, Union

from pydantic import BaseModel, ConfigDict, Field


class VerbosityLevel(StrEnum):
    """Controls how much data the tracer emits."""

    QUIET = "quiet"
    DELTA_ONLY = "delta_only"
    FULL = "full"


class TracerConfig(BaseModel):
    """Runtime configuration for ExecutionTracer."""

    model_config = ConfigDict(frozen=True)

    output_dir: str = ".pysymex/traces"
    verbosity: VerbosityLevel = VerbosityLevel.DELTA_ONLY
    delta_batch_size: int = Field(default=50, gt=0)
    keyframe_on_fork: bool = True
    keyframe_on_prune: bool = True
    keyframe_on_issue: bool = True
    max_constraint_display: int = Field(default=50, gt=0)
    compression_level: int = Field(default=6, ge=0, le=9)
    enabled: bool = False
    """Tracing is **opt-in**.  Set ``enabled=True`` explicitly, or set the
    ``PY_SYMEX_TRACE=1`` environment variable and call :meth:`from_env`."""

    @classmethod
    def from_env(cls, **overrides: object) -> TracerConfig:
        """Construct a :class:`TracerConfig` whose ``enabled`` flag is driven
        by the ``PY_SYMEX_TRACE`` environment variable.

        The variable is considered *truthy* when its lowercased value is one
        of ``"1"``, ``"true"``, ``"yes"``, or ``"on"``.

        Any keyword arguments in *overrides* are forwarded verbatim to the
        constructor and take precedence over env-var resolution.

        Args:
            **overrides: Any :class:`TracerConfig` field values that should
                         override env-var-resolved defaults.

        Returns:
            A new :class:`TracerConfig` instance.

        Example::

            # Enable tracing with a custom output directory, driven by env:
            cfg = TracerConfig.from_env(output_dir="/tmp/my_traces")
        """
        _TRUTHY = frozenset(("1", "true", "yes", "on"))
        env_val = os.environ.get("PY_SYMEX_TRACE", "0").strip().lower()
        enabled = env_val in _TRUTHY

        # Professional touch: allow overriding compression level via env
        env_comp = os.environ.get("PY_SYMEX_TRACE_COMPRESSION", "6").strip()
        comp_level = int(env_comp) if env_comp.isdigit() else 6

        return cls(
            enabled=overrides.pop("enabled", enabled),
            compression_level=overrides.pop("compression_level", comp_level),
            **overrides,
        )


class ConstraintEntry(BaseModel):
    """A single path constraint enriched with its causal origin."""

    model_config = ConfigDict(frozen=True)

    smtlib: str
    causality: str


class StackDiff(BaseModel):
    """Net change to the symbolic stack after one instruction."""

    model_config = ConfigDict(frozen=True)

    popped: int = Field(default=0, ge=0)
    pushed: list[str] = Field(default_factory=list)


class VarDiff(BaseModel):
    """Net change to the variable namespace after one instruction."""

    model_config = ConfigDict(frozen=True)

    modified: dict[str, str] = Field(default_factory=dict)
    added: dict[str, str] = Field(default_factory=dict)
    removed: list[str] = Field(default_factory=list)


_ConfigScalar: TypeAlias = str | int | float | bool | None


def _new_constraint_list() -> list[ConstraintEntry]:
    """Typed factory for ConstraintEntry list fields.

    A named factory (vs. ``default_factory=list``) lets pyright strict mode
    resolve the element type as ``ConstraintEntry`` instead of ``Unknown``.
    """
    return []


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
    initial_symbolic_args: dict[str, str] = Field(default_factory=dict)
    tracer_config: dict[str, _ConfigScalar] = Field(default_factory=dict)


class StepDeltaEvent(BaseModel):
    """Incremental diff emitted after every successfully dispatched instruction."""

    model_config = ConfigDict(frozen=True)

    event_type: Literal["step"] = "step"
    seq: int = 0
    path_id: int = 0
    pc: int = 0
    offset: int = 0
    opcode: str = "UNKNOWN"
    source_line: int | None = None
    source_text: str | None = None
    stack_diff: StackDiff = Field(default_factory=StackDiff)
    var_diff: VarDiff = Field(default_factory=VarDiff)
    mem_diff: dict[str, str] = Field(default_factory=dict)
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
    stack: list[str] = Field(default_factory=list)
    local_vars: dict[str, str] = Field(default_factory=dict)
    global_vars: dict[str, str] = Field(default_factory=dict)
    path_constraints: list[ConstraintEntry] = Field(default_factory=_new_constraint_list)
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
    constraints_at_issue: list[ConstraintEntry] = Field(default_factory=_new_constraint_list)
    z3_model: dict[str, str] | None = None


TraceEvent: TypeAlias = Annotated[
    Union[SystemContextEvent, StepDeltaEvent, KeyframeEvent, SolveEvent, IssueEvent],
    Field(discriminator="event_type"),
]
"""Discriminated union of all trace events keyed on ``event_type``.

Usage (reading a trace file)::

    from pydantic import TypeAdapter
    from pysymex.tracing.schemas import TraceEvent

    adapter = TypeAdapter(TraceEvent)
    events = [adapter.validate_json(line) for line in open("trace.jsonl")]
"""
