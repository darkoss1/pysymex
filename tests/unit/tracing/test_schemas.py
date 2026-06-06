from __future__ import annotations

import os

from pydantic import TypeAdapter

from pysymex.tracing.schemas import (
    ConstraintEntry,
    DetectorQueryTraceEvent,
    FallbackTraceEvent,
    PathFeasibilityTraceEvent,
    SchedulerTraceEvent,
    StepDeltaEvent,
    TraceEvent,
    TracerConfig,
)
from pysymex.config.tracing import TracerConfig as CanonicalTracerConfig
from pysymex.tracing.schemas.events import StepDeltaEvent as CanonicalStepDeltaEvent


def test_tracer_config_from_env_truthy() -> None:
    old_trace = os.environ.get("PY_SYMEX_TRACE")
    old_comp = os.environ.get("PY_SYMEX_TRACE_COMPRESSION")
    try:
        os.environ["PY_SYMEX_TRACE"] = "true"
        os.environ["PY_SYMEX_TRACE_COMPRESSION"] = "9"
        cfg = TracerConfig.from_env(output_dir="out")
        assert cfg.enabled is True
        assert cfg.compression_level == 9
        assert cfg.output_dir == "out"
    finally:
        if old_trace is None:
            os.environ.pop("PY_SYMEX_TRACE", None)
        else:
            os.environ["PY_SYMEX_TRACE"] = old_trace
        if old_comp is None:
            os.environ.pop("PY_SYMEX_TRACE_COMPRESSION", None)
        else:
            os.environ["PY_SYMEX_TRACE_COMPRESSION"] = old_comp


def test_trace_event_union_round_trip_for_step_event() -> None:
    adapter: TypeAdapter[StepDeltaEvent] = TypeAdapter(StepDeltaEvent)
    event = StepDeltaEvent(seq=7, path_id=2, pc=9, opcode="LOAD_CONST", step_latency_ms=0.125)
    parsed = adapter.validate_json(event.model_dump_json())

    assert isinstance(parsed, StepDeltaEvent)
    assert parsed.event_type == "step"
    assert parsed.seq == 7
    assert parsed.step_latency_ms == 0.125


def test_trace_event_union_round_trip_for_fallback_event() -> None:
    adapter: TypeAdapter[TraceEvent] = TypeAdapter(TraceEvent)
    event = FallbackTraceEvent(
        seq=9,
        path_id=3,
        pc=17,
        source_line=42,
        label="solver_unknown",
        owner="execution.feasibility",
        kind="unknown",
        soundness="inconclusive",
        false_positive_risk="low",
        false_negative_risk="high",
        reason="solver returned unknown",
    )
    parsed = adapter.validate_json(event.model_dump_json())

    assert isinstance(parsed, FallbackTraceEvent)
    assert parsed.event_type == "fallback"
    assert parsed.path_id == 3
    assert parsed.soundness == "inconclusive"


def test_trace_event_union_round_trip_for_detector_query_event() -> None:
    adapter: TypeAdapter[TraceEvent] = TypeAdapter(TraceEvent)
    event = DetectorQueryTraceEvent(
        seq=10,
        path_id=4,
        pc=22,
        source_line=64,
        detector_name="division-by-zero",
        issue_kind="DIVISION_BY_ZERO",
        opcode="BINARY_OP",
        raw_constraints_count=4,
        constraints_count=3,
        state_constraints_count=2,
        pending_constraint_count=1,
        last_inconclusive_feasibility_len=-1,
        result=True,
        result_source="solver_sat",
        cache_hit=False,
        witness_used=False,
        constraint_excerpt=[
            ConstraintEntry(smtlib="(> trace_detector_schema_x 0)", causality="unit")
        ],
    )
    parsed = adapter.validate_json(event.model_dump_json())

    assert isinstance(parsed, DetectorQueryTraceEvent)
    assert parsed.event_type == "detector_query"
    assert parsed.detector_name == "division-by-zero"
    assert parsed.result_source == "solver_sat"
    assert parsed.constraint_excerpt[0].causality == "unit"


def test_trace_event_union_round_trip_for_path_feasibility_event() -> None:
    adapter: TypeAdapter[TraceEvent] = TypeAdapter(TraceEvent)
    event = PathFeasibilityTraceEvent(
        seq=11,
        path_id=5,
        pc=28,
        source_line=70,
        pending_constraint_count=12,
        path_constraints_count=20,
        known_sat_prefix_len=8,
        query_prefix_len=8,
        query_constraints_count=12,
        result="feasible",
        result_source="hard_theory_witness",
        solver_called=False,
        hard_theory_skipped=False,
        policy_latency_ms=0.25,
        query_constraint_excerpt=[
            ConstraintEntry(smtlib="(> trace_path_schema_x 0)", causality="unit")
        ],
    )
    parsed = adapter.validate_json(event.model_dump_json())

    assert isinstance(parsed, PathFeasibilityTraceEvent)
    assert parsed.event_type == "path_feasibility"
    assert parsed.result == "feasible"
    assert parsed.result_source == "hard_theory_witness"
    assert parsed.query_constraint_excerpt[0].smtlib == "(> trace_path_schema_x 0)"


def test_trace_event_union_round_trip_for_scheduler_event() -> None:
    adapter: TypeAdapter[TraceEvent] = TypeAdapter(TraceEvent)
    event = SchedulerTraceEvent(
        seq=12,
        action="select",
        decision_source="polar_native",
        queue_state_id=3,
        path_id=8,
        pc=34,
        source_line=88,
        depth=5,
        pending_constraint_count=2,
        path_constraints_count=10,
        frontier_size_before=7,
        frontier_size_after=6,
        branch_degree=4,
        priority=42.5,
        detector_obligation_count=1,
        estimated_resident_units=9,
        unsupported_live_count=0,
        havoc_live_count=0,
        reason="unit scheduler event",
    )
    parsed = adapter.validate_json(event.model_dump_json())

    assert isinstance(parsed, SchedulerTraceEvent)
    assert parsed.event_type == "scheduler"
    assert parsed.action == "select"
    assert parsed.decision_source == "polar_native"
    assert parsed.priority == 42.5


def test_schema_facade_reexports_canonical_models() -> None:
    assert TracerConfig is CanonicalTracerConfig
    assert StepDeltaEvent is CanonicalStepDeltaEvent
