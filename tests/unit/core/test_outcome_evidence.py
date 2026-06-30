from __future__ import annotations

from pysymex._internal.core.outcome import (
    AnalysisOutcome,
    OutcomePolicy,
    OutcomeSubreason,
)
from pysymex._internal.execution.fallback.types import FallbackEvent, FallbackKind, SoundnessTag


def test_fallback_event_soundness_drives_outcome_without_string_guessing() -> None:
    event = FallbackEvent(
        kind=FallbackKind.PRECISION_LOSS,
        label="unsupported_in_label_but_precision_loss",
        owner="unit",
        reason="kept going imprecisely",
        soundness=SoundnessTag.PRECISION_LOSS,
    )

    evidence = OutcomePolicy.evidence_from_fallback_event(event)

    assert evidence.outcome is AnalysisOutcome.DEGRADED
    assert evidence.subreason is OutcomeSubreason.DEGRADED_PRECISION


def test_unsupported_fallback_event_beats_detector_issue() -> None:
    event = FallbackEvent(
        kind=FallbackKind.UNSUPPORTED,
        label="unsupported_vm_state",
        owner="execution.fallback",
        reason="bad continuation",
        soundness=SoundnessTag.UNSUPPORTED,
    )
    evidence = OutcomePolicy.evidence_from_fallback_event(event)

    outcome, subreason = OutcomePolicy.classify(
        issues=[{"kind": "TYPE_ERROR"}],
        degraded_passes=[],
        outcome_evidence=[evidence],
    )

    assert outcome is AnalysisOutcome.UNSUPPORTED
    assert subreason == "unsupported_vm_state"


def test_internal_exception_becomes_engine_failure_evidence() -> None:
    evidence = OutcomePolicy.evidence_from_exception(
        RuntimeError("unexpected internal bug"), source="unit"
    )

    assert evidence.outcome is AnalysisOutcome.ENGINE_FAILURE
    assert evidence.subreason is OutcomeSubreason.ENGINE_CRASH
    assert evidence.source == "unit"
