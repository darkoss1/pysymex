from __future__ import annotations

from typing import cast

from pysymex._internal.execution.fallback.types import FallbackEvent, FallbackKind, SoundnessTag
from pysymex._internal.execution.results.result import ExecutionResult
from pysymex._internal.execution.session.state.core import ExecutionSession
from pysymex._internal.limits.models import ResourceSnapshot


def test_execution_result_from_session_worklist_stats_include_fallback_visibility() -> None:
    """POLAR worklist diagnostics expose unsupported and precision-loss fallback facts."""
    session = ExecutionSession()
    session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.UNSUPPORTED,
            label="unsupported_truth_protocol",
            owner="execution.opcodes",
            reason="truth protocol is unsupported",
            soundness=SoundnessTag.UNSUPPORTED,
        )
    )
    session.record_fallback_event(
        FallbackEvent(
            kind=FallbackKind.PRECISION_LOSS,
            label="unmodeled_call_abstraction",
            owner="execution.calls",
            reason="call was abstracted with havoc",
            soundness=SoundnessTag.PRECISION_LOSS,
        )
    )

    result = ExecutionResult.from_session(
        session=session,
        final_issues=[],
        resource_snapshot=ResourceSnapshot(),
        solver_stats={},
        detector_query_stats={},
        state_merger_stats={},
        worklist_stats={"enabled": True},
        function_name="target",
        source_file="<test>",
        include_final_stack=False,
        include_final_exception=False,
    )

    worklist_stats = cast("dict[str, object]", result.solver_stats["worklist"])
    kind_counts = cast("dict[str, int]", worklist_stats["fallback_kind_counts"])
    soundness_counts = cast("dict[str, int]", worklist_stats["fallback_soundness_counts"])

    assert worklist_stats["enabled"] is True
    assert worklist_stats["degraded_pass_count"] == 2
    assert worklist_stats["fallback_event_count"] == 2
    assert kind_counts[FallbackKind.UNSUPPORTED.value] == 1
    assert kind_counts[FallbackKind.PRECISION_LOSS.value] == 1
    assert soundness_counts[SoundnessTag.UNSUPPORTED.value] == 1
    assert soundness_counts[SoundnessTag.PRECISION_LOSS.value] == 1
