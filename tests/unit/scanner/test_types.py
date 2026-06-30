from __future__ import annotations

from pysymex._internal.core.outcome import AnalysisOutcome, OutcomeEvidence, OutcomeSubreason
from pysymex._internal.scanner.types import ScanResult


def test_scan_result_to_dict_serializes_non_primitives() -> None:
    result = ScanResult(
        file_path="a.py",
        timestamp="now",
        issues=[{"kind": "X", "detail": {"k": object()}}],
        code_objects=2,
        paths_explored=3,
        paths_pruned=1,
        degraded_passes=["solver_unknown_detector_query"],
    )
    data = result.to_dict()
    assert data["file"] == "a.py"
    assert isinstance(data["issues"], list)
    assert data["code_objects"] == 2
    assert data["paths_pruned"] == 1
    assert data["degraded_passes"] == ["solver_unknown_detector_query"]
    assert data["outcome"] == "INCONCLUSIVE"


def test_scan_result_to_dict_sorts_unordered_issue_values() -> None:
    result = ScanResult(
        file_path="a.py",
        timestamp="now",
        issues=[
            {"values": {"gamma", "alpha", "beta"}},
            {"frozen": frozenset(("zeta", "delta"))},
        ],
    )

    data = result.to_dict()

    assert data["issues"] == [
        {"values": ["alpha", "beta", "gamma"]},
        {"frozen": ["delta", "zeta"]},
    ]


def test_scan_result_analysis_outcome_classification() -> None:
    # 1. SAFE
    r = ScanResult("safe.py", "now")
    assert r.outcome is AnalysisOutcome.SAFE
    assert r.outcome_subreason is None

    # 2. ISSUE_FOUND for detector/operator bugs.
    r = ScanResult("bug.py", "now", issues=[{"kind": "DIVISION_BY_ZERO"}])
    assert r.outcome is AnalysisOutcome.ISSUE_FOUND
    assert r.outcome_subreason == "zero_division"

    r = ScanResult("bug.py", "now", issues=[{"kind": "TYPE_ERROR"}])
    assert r.outcome is AnalysisOutcome.ISSUE_FOUND
    assert r.outcome_subreason == "type_error"

    # 3. ISSUE_FOUND (e.g. contract violation, assertion error, null dereference)
    r = ScanResult("bug.py", "now", issues=[{"kind": "CONTRACT_VIOLATION"}])
    assert r.outcome is AnalysisOutcome.ISSUE_FOUND
    assert r.outcome_subreason == "contract_violation"

    r = ScanResult("bug.py", "now", issues=[{"kind": "RESOURCE_LEAK"}])
    assert r.outcome is AnalysisOutcome.ISSUE_FOUND
    assert r.outcome_subreason == "resource_leak"

    # 4. DEGRADED (e.g. havoc fallback, stdlib approximation, imprecise import)
    r = ScanResult("degraded.py", "now", degraded_passes=["havoc_fallback_pass"])
    assert r.outcome is AnalysisOutcome.DEGRADED
    assert r.outcome_subreason == "havoc_fallback"

    r = ScanResult("degraded.py", "now", degraded_passes=["approximate_stdlib_pass"])
    assert r.outcome is AnalysisOutcome.DEGRADED
    assert r.outcome_subreason == "approximate_stdlib"

    # 5. UNSUPPORTED (e.g. unsupported opcode, unsupported coroutine)
    r = ScanResult("unsupported.py", "now", degraded_passes=["unsupported_opcode_312"])
    assert r.outcome is AnalysisOutcome.UNSUPPORTED
    assert r.outcome_subreason == "unsupported_opcode"

    # 6. INCONCLUSIVE (e.g. timeout, solver unknown)
    r = ScanResult(
        "inconclusive.py",
        "now",
        outcome_evidence=[
            OutcomeEvidence(
                AnalysisOutcome.INCONCLUSIVE,
                OutcomeSubreason.SOLVER_TIMEOUT,
                "solver_timeout",
                source="unit-test",
            )
        ],
    )
    assert r.outcome is AnalysisOutcome.INCONCLUSIVE
    assert r.outcome_subreason == "solver_timeout"

    r = ScanResult("inconclusive.py", "now", degraded_passes=["solver_unknown_path_feasibility"])
    assert r.outcome is AnalysisOutcome.INCONCLUSIVE
    assert r.outcome_subreason == "solver_unknown"

    # 7. ENGINE_FAILURE (e.g. stack corruption, internal exception crash)
    r = ScanResult(
        "crash.py",
        "now",
        outcome_evidence=[
            OutcomeEvidence(
                AnalysisOutcome.ENGINE_FAILURE,
                OutcomeSubreason.STACK_UNDERFLOW,
                "stack_underflow",
                source="unit-test",
            )
        ],
    )
    assert r.outcome is AnalysisOutcome.ENGINE_FAILURE
    assert r.outcome_subreason == "stack_underflow"

    r = ScanResult(
        "crash.py",
        "now",
        error="Internal exception traceback...",
        outcome_evidence=[
            OutcomeEvidence(
                AnalysisOutcome.ENGINE_FAILURE,
                OutcomeSubreason.ENGINE_CRASH,
                "engine_crash",
                source="unit-test",
            )
        ],
    )
    assert r.outcome is AnalysisOutcome.ENGINE_FAILURE
    assert r.outcome_subreason == "engine_crash"

    # 8. Check serialization
    data = r.to_dict()
    assert data["outcome"] == "ENGINE_FAILURE"
    assert data["outcome_subreason"] == "engine_crash"


def test_analysis_outcome_separates_explicit_raise_from_operator_bug() -> None:
    explicit_raise = ScanResult(
        "raise.py",
        "now",
        issues=[
            {
                "kind": "UNHANDLED_EXCEPTION",
                "message": "Path raises unhandled exception: ZeroDivisionError",
                "detector_name": "user_exception",
            }
        ],
    )
    assert explicit_raise.outcome is AnalysisOutcome.TARGET_EXCEPTION
    assert explicit_raise.outcome_subreason == "target_exception"

    operator_bug = ScanResult("division.py", "now", issues=[{"kind": "DIVISION_BY_ZERO"}])
    assert operator_bug.outcome is AnalysisOutcome.ISSUE_FOUND
    assert operator_bug.outcome_subreason == "zero_division"


def test_analysis_outcome_precedence_is_global() -> None:
    issue: dict[str, object] = {"kind": "TYPE_ERROR", "message": "Possible TypeError"}

    assert (
        ScanResult(
            "crash.py",
            "now",
            issues=[issue],
            error="stack underflow",
            outcome_evidence=[
                OutcomeEvidence(
                    AnalysisOutcome.ENGINE_FAILURE,
                    OutcomeSubreason.STACK_UNDERFLOW,
                    "stack_underflow",
                    source="unit-test",
                )
            ],
        ).outcome
        is AnalysisOutcome.ENGINE_FAILURE
    )
    assert (
        ScanResult(
            "unsupported.py",
            "now",
            issues=[issue],
            degraded_passes=["unsupported_opcode_CACHE"],
        ).outcome
        is AnalysisOutcome.UNSUPPORTED
    )
    assert (
        ScanResult(
            "unknown.py",
            "now",
            issues=[issue],
            degraded_passes=["solver_unknown_path_feasibility"],
        ).outcome
        is AnalysisOutcome.INCONCLUSIVE
    )


def test_analysis_outcome_subreason_enum_is_exported() -> None:
    assert OutcomeSubreason.ZERO_DIVISION.value == "zero_division"


def test_structured_outcome_evidence_takes_precedence_over_issues() -> None:
    result = ScanResult(
        "mixed.py",
        "now",
        issues=[{"kind": "TYPE_ERROR", "message": "target issue"}],
        degraded_passes=["havoc_fallback"],
        outcome_evidence=[
            OutcomeEvidence(
                outcome=AnalysisOutcome.ENGINE_FAILURE,
                subreason=OutcomeSubreason.VM_INVARIANT_ERROR,
                label="vm_invariant_error",
                source="unit-test",
                detail="stack continuation mismatch",
            )
        ],
    )

    assert result.outcome is AnalysisOutcome.ENGINE_FAILURE
    assert result.outcome_subreason == "vm_invariant_error"
    data = result.to_dict()
    assert data["outcome_evidence"] == [
        {
            "outcome": "ENGINE_FAILURE",
            "subreason": "vm_invariant_error",
            "label": "vm_invariant_error",
            "source": "unit-test",
            "detail": "stack continuation mismatch",
        }
    ]


def test_structured_degradation_evidence_without_legacy_label_is_classified() -> None:
    result = ScanResult(
        "fallback.py",
        "now",
        outcome_evidence=[
            OutcomeEvidence(
                outcome=AnalysisOutcome.UNSUPPORTED,
                subreason=OutcomeSubreason.UNSUPPORTED_VM_STATE,
                label="unsupported_vm_state",
                source="execution.fallback",
            )
        ],
    )

    assert result.outcome is AnalysisOutcome.UNSUPPORTED
    assert result.outcome_subreason == "unsupported_vm_state"
