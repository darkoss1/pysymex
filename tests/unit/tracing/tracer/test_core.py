"""Tests for pysymex.tracing.tracer.core — ExecutionTracer behavior."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

import z3

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.config.tracing import VerbosityLevel
from pysymex.execution.detectors import DetectorQueryEvent
from pysymex.execution.fallback import FallbackEvent, FallbackKind, RiskLevel, SoundnessTag
from pysymex.execution.feasibility.telemetry import PathFeasibilityEvent
from pysymex.execution.scheduling.telemetry import SchedulerEvent
from pysymex.tracing.tracer.core import ExecutionTracer
from pysymex.tracing.schemas import TracerConfig

if TYPE_CHECKING:
    import dis

    from pysymex.core.state.record import VMState
    from pysymex.execution.executors.core import SymbolicExecutor


class _MemoryTraceWriter:
    """In-memory trace writer for unit tests."""

    def __init__(self) -> None:
        self.text = ""

    def write(self, s: str, /) -> int:
        self.text += s
        return len(s)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


class TestExecutionTracer:
    """Tests for ExecutionTracer initialization and config."""

    def test_init_default_config(self) -> None:
        """ExecutionTracer initializes with default config."""
        tracer = ExecutionTracer()
        assert tracer.config is not None
        assert tracer.seq == 0
        assert tracer.file is None

    def test_init_custom_config(self) -> None:
        """ExecutionTracer accepts custom config."""
        config = TracerConfig(enabled=False)
        tracer = ExecutionTracer(config=config)
        assert tracer.config.enabled is False

    def test_registry_property(self) -> None:
        """registry property returns Z3SemanticRegistry."""
        tracer = ExecutionTracer()
        assert tracer.registry is not None

    def test_end_session_without_start(self) -> None:
        """end_session() on un-started tracer returns None."""
        tracer = ExecutionTracer(config=TracerConfig(enabled=False))
        result = tracer.end_session()
        assert result is None

    def test_context_manager(self) -> None:
        """ExecutionTracer works as context manager."""
        config = TracerConfig(enabled=False)
        with ExecutionTracer(config=config) as tracer:
            assert tracer.file is None

    def test_step_event_includes_dispatch_latency(self) -> None:
        """pre_step/post_step emit step_latency_ms for opcode bottleneck analysis."""
        writer = _MemoryTraceWriter()
        tracer = ExecutionTracer(
            config=TracerConfig(
                enabled=True,
                verbosity=VerbosityLevel.DELTA_ONLY,
                delta_batch_size=1,
            )
        )
        tracer.file = writer

        state = cast(
            "VMState",
            SimpleNamespace(
                stack=[],
                local_vars={},
                global_vars={},
                memory={},
                path_constraints=[],
                path_id=7,
                pc=3,
            ),
        )
        instr = cast(
            "dis.Instruction",
            SimpleNamespace(opname="NOP", offset=3, starts_line=None, positions=None),
        )

        tracer.pre_step(cast("SymbolicExecutor", object()), state)
        tracer.post_step(cast("SymbolicExecutor", object()), state, instr)

        event = json.loads(writer.text.strip())
        assert event["event_type"] == "step"
        assert event["path_id"] == 7
        assert event["step_latency_ms"] >= 0.0

    def test_fallback_event_includes_degraded_decision_context(self) -> None:
        writer = _MemoryTraceWriter()
        tracer = ExecutionTracer(config=TracerConfig(enabled=True, delta_batch_size=1))
        tracer.file = writer
        state = cast(
            "VMState",
            SimpleNamespace(
                stack=[],
                local_vars={},
                global_vars={},
                memory={},
                path_constraints=[],
                path_id=11,
                pc=99,
            ),
        )
        tracer.pre_step(cast("SymbolicExecutor", object()), state)

        tracer.on_fallback_event(
            FallbackEvent(
                kind=FallbackKind.UNKNOWN,
                label="solver_unknown_path_feasibility",
                owner="execution.feasibility",
                reason="x" * 600,
                line_number=123,
                soundness=SoundnessTag.INCONCLUSIVE,
                false_positive_risk=RiskLevel.LOW,
                false_negative_risk=RiskLevel.HIGH,
            )
        )

        event = json.loads(writer.text.strip())
        assert event["event_type"] == "fallback"
        assert event["path_id"] == 11
        assert event["pc"] == 99
        assert event["source_line"] == 123
        assert event["label"] == "solver_unknown_path_feasibility"
        assert event["kind"] == "unknown"
        assert event["soundness"] == "inconclusive"
        assert event["false_positive_risk"] == "low"
        assert event["false_negative_risk"] == "high"
        assert len(event["reason"]) == 503
        assert event["reason"].endswith("...")

    def test_detector_query_event_includes_query_decision_context(self) -> None:
        writer = _MemoryTraceWriter()
        tracer = ExecutionTracer(config=TracerConfig(enabled=True, delta_batch_size=1))
        tracer.file = writer
        state = cast(
            "VMState",
            SimpleNamespace(
                stack=[],
                local_vars={},
                global_vars={},
                memory={},
                path_constraints=[],
                path_id=15,
                pc=101,
            ),
        )
        tracer.pre_step(cast("SymbolicExecutor", object()), state)

        tracer.on_detector_query_event(
            DetectorQueryEvent(
                detector_name="division-by-zero",
                issue_kind="DIVISION_BY_ZERO",
                path_id=15,
                pc=101,
                line_number=32,
                opcode="BINARY_OP",
                raw_constraints_count=5,
                constraints_count=4,
                state_constraints_count=3,
                pending_constraint_count=2,
                last_inconclusive_feasibility_len=-1,
                inconclusive_prefix_len=None,
                result=True,
                result_source="solver_sat",
                cache_hit=False,
                witness_used=False,
                constraint_excerpt=(z3.Int("trace_detector_query_x") > 0,),
            )
        )

        event = json.loads(writer.text.strip())
        assert event["event_type"] == "detector_query"
        assert event["path_id"] == 15
        assert event["pc"] == 101
        assert event["source_line"] == 32
        assert event["detector_name"] == "division-by-zero"
        assert event["issue_kind"] == "DIVISION_BY_ZERO"
        assert event["raw_constraints_count"] == 5
        assert event["constraints_count"] == 4
        assert event["pending_constraint_count"] == 2
        assert event["result"] is True
        assert event["result_source"] == "solver_sat"
        assert event["cache_hit"] is False
        assert event["witness_used"] is False
        assert len(event["constraint_excerpt"]) == 1
        assert event["constraint_excerpt"][0]["causality"] == "detector query constraint excerpt"
        assert "trace_detector_query_x" in event["constraint_excerpt"][0]["smtlib"]

    def test_issue_event_prefers_explicit_detector_name(self) -> None:
        writer = _MemoryTraceWriter()
        tracer = ExecutionTracer(
            config=TracerConfig(enabled=True, delta_batch_size=1, keyframe_on_issue=False)
        )
        tracer.file = writer
        state = cast(
            "VMState",
            SimpleNamespace(
                stack=[],
                local_vars={},
                global_vars={},
                memory={},
                path_constraints=[],
                path_id=17,
                pc=103,
            ),
        )

        tracer.on_issue(
            cast("SymbolicExecutor", object()),
            state,
            Issue(
                kind=IssueKind.ATTRIBUTE_ERROR,
                message="missing attribute",
                pc=103,
                function_name="target",
                detector_name="model-side-effect",
            ),
        )

        event = json.loads(writer.text.strip())
        assert event["event_type"] == "issue"
        assert event["detector_name"] == "model-side-effect"

    def test_path_feasibility_event_includes_policy_decision_context(self) -> None:
        writer = _MemoryTraceWriter()
        tracer = ExecutionTracer(config=TracerConfig(enabled=True, delta_batch_size=1))
        tracer.file = writer
        state = cast(
            "VMState",
            SimpleNamespace(
                stack=[],
                local_vars={},
                global_vars={},
                memory={},
                path_constraints=[],
                path_id=19,
                pc=141,
            ),
        )
        tracer.pre_step(cast("SymbolicExecutor", object()), state)

        tracer.on_path_feasibility_event(
            PathFeasibilityEvent(
                path_id=19,
                pc=141,
                line_number=52,
                pending_constraint_count=12,
                path_constraints_count=17,
                known_sat_prefix_len=5,
                query_prefix_len=5,
                query_constraints_count=12,
                result="inconclusive",
                result_source="hard_theory_skipped",
                solver_called=False,
                hard_theory_skipped=True,
                policy_latency_ms=0.25,
                query_constraint_excerpt=(z3.Int("trace_path_feasibility_x") > 0,),
            )
        )

        event = json.loads(writer.text.strip())
        assert event["event_type"] == "path_feasibility"
        assert event["path_id"] == 19
        assert event["pc"] == 141
        assert event["source_line"] == 52
        assert event["pending_constraint_count"] == 12
        assert event["path_constraints_count"] == 17
        assert event["known_sat_prefix_len"] == 5
        assert event["query_constraints_count"] == 12
        assert event["result"] == "inconclusive"
        assert event["result_source"] == "hard_theory_skipped"
        assert event["solver_called"] is False
        assert event["hard_theory_skipped"] is True
        assert event["policy_latency_ms"] == 0.25
        assert len(event["query_constraint_excerpt"]) == 1
        assert (
            event["query_constraint_excerpt"][0]["causality"]
            == "path-feasibility query constraint excerpt"
        )
        assert "trace_path_feasibility_x" in event["query_constraint_excerpt"][0]["smtlib"]

    def test_scheduler_event_includes_frontier_decision_context(self) -> None:
        writer = _MemoryTraceWriter()
        tracer = ExecutionTracer(config=TracerConfig(enabled=True, delta_batch_size=1))
        tracer.file = writer

        tracer.on_scheduler_event(
            SchedulerEvent(
                action="select",
                decision_source="polar_native",
                queue_state_id=4,
                path_id=21,
                pc=77,
                line_number=91,
                depth=8,
                pending_constraint_count=3,
                path_constraints_count=12,
                frontier_size_before=5,
                frontier_size_after=4,
                branch_degree=2,
                priority=15.25,
                detector_obligation_count=1,
                estimated_resident_units=6,
                unsupported_live_count=0,
                havoc_live_count=0,
                reason="unit scheduler decision",
            )
        )

        event = json.loads(writer.text.strip())
        assert event["event_type"] == "scheduler"
        assert event["action"] == "select"
        assert event["decision_source"] == "polar_native"
        assert event["path_id"] == 21
        assert event["pc"] == 77
        assert event["source_line"] == 91
        assert event["frontier_size_before"] == 5
        assert event["frontier_size_after"] == 4
        assert event["priority"] == 15.25
        assert event["detector_obligation_count"] == 1
