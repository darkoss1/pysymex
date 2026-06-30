from __future__ import annotations

from pathlib import Path

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.core.outcome import (
    AnalysisOutcome,
    IssueKind,
    OutcomeEvidence,
    OutcomeSubreason,
)
from pysymex._internal.execution.results.result import ExecutionResult
from pysymex._internal.reporting.sarif.generator import SARIFGenerator


def test_has_issues() -> None:
    empty = ExecutionResult()
    issue = Issue(kind=IssueKind.TYPE_ERROR, message="boom")
    non_empty = ExecutionResult(issues=[issue])

    assert empty.has_issues() is False
    assert non_empty.has_issues() is True


def test_get_issues_by_kind() -> None:
    type_issue = Issue(kind=IssueKind.TYPE_ERROR, message="type")
    key_issue = Issue(kind=IssueKind.KEY_ERROR, message="key")
    result = ExecutionResult(issues=[type_issue, key_issue])

    only_type = result.get_issues_by_kind(IssueKind.TYPE_ERROR)

    assert only_type == [type_issue]


def test_format_summary() -> None:
    result = ExecutionResult(
        function_name="f",
        paths_explored=2,
        paths_completed=1,
        total_time_seconds=0.5,
        coverage={0, 2},
    )

    summary = result.format_summary()

    assert "Function: f" in summary
    assert "Outcome: SAFE" in summary
    assert "Paths explored: 2" in summary
    assert "No issues found!" in summary


def test_degraded_summary_and_sarif_do_not_claim_success() -> None:
    result = ExecutionResult(degraded_passes=["solver_unknown_detector_query"])

    summary = result.format_summary()
    sarif = SARIFGenerator().generate_execution_result(result).to_dict()
    invocation = sarif["runs"][0]["invocations"][0]  # type: ignore[index]

    assert "Analysis degraded: solver_unknown_detector_query" in summary
    assert "No issues found!" not in summary
    assert invocation["executionSuccessful"] is False  # type: ignore[index]
    assert invocation["properties"]["degradedPasses"] == [  # type: ignore[index]
        "solver_unknown_detector_query"
    ]


def test_to_dict() -> None:
    issue = Issue(kind=IssueKind.VALUE_ERROR, message="bad", filename="m.py", line_number=7)
    result = ExecutionResult(
        issues=[issue],
        function_name="f",
        source_file="m.py",
        paths_explored=3,
        paths_completed=2,
        paths_pruned=1,
        coverage={1, 9},
        total_time_seconds=1.2,
    )

    as_dict = result.to_dict()

    assert as_dict["function_name"] == "f"
    assert as_dict["source_file"] == "m.py"
    assert as_dict["coverage_size"] == 2
    assert isinstance(as_dict["issues"], list)
    assert as_dict["degraded_passes"] == []


def test_execution_result_sarif_generation(tmp_path: Path) -> None:
    issue = Issue(
        kind=IssueKind.DIVISION_BY_ZERO,
        message="possible division by zero",
        filename="a.py",
        line_number=12,
    )
    result = ExecutionResult(
        issues=[issue],
        function_name="f",
        source_file="a.py",
        paths_explored=4,
        paths_completed=3,
        paths_pruned=1,
        coverage={1, 2, 3},
        total_time_seconds=0.01,
    )
    out = tmp_path / "execution-result.sarif"

    sarif = SARIFGenerator().generate_execution_result(result)
    sarif.save(out)

    assert sarif.runs
    assert out.exists()


def test_execution_result_outcome_classification() -> None:
    empty = ExecutionResult()
    assert empty.outcome is AnalysisOutcome.SAFE
    assert empty.outcome_subreason is None

    issue = Issue(
        kind=IssueKind.UNHANDLED_EXCEPTION, message="Path raises unhandled exception: TypeError"
    )
    r_exc = ExecutionResult(issues=[issue])
    assert r_exc.outcome is AnalysisOutcome.TARGET_EXCEPTION
    assert r_exc.outcome_subreason == "target_exception"

    issue_bug = Issue(kind=IssueKind.TYPE_ERROR, message="bad operand")
    r_type_bug = ExecutionResult(issues=[issue_bug])
    assert r_type_bug.outcome is AnalysisOutcome.ISSUE_FOUND
    assert r_type_bug.outcome_subreason == "type_error"

    issue_bug = Issue(kind=IssueKind.CONTRACT_VIOLATION, message="violated")
    r_bug = ExecutionResult(issues=[issue_bug])
    assert r_bug.outcome is AnalysisOutcome.ISSUE_FOUND
    assert r_bug.outcome_subreason == "contract_violation"

    r_degraded = ExecutionResult(degraded_passes=["havoc_fallback_pass"])
    assert r_degraded.outcome is AnalysisOutcome.DEGRADED
    assert r_degraded.outcome_subreason == "havoc_fallback"

    r_unsupported = ExecutionResult(degraded_passes=["unsupported_opcode_pass"])
    assert r_unsupported.outcome is AnalysisOutcome.UNSUPPORTED
    assert r_unsupported.outcome_subreason == "unsupported_opcode"

    # Check to_dict serialization of outcome
    as_dict = empty.to_dict()
    assert as_dict["outcome"] == "SAFE"
    assert as_dict["outcome_subreason"] is None


def test_execution_result_outcome_precedence_is_global() -> None:
    issue = Issue(kind=IssueKind.TYPE_ERROR, message="bad operand")
    result = ExecutionResult(issues=[issue], degraded_passes=["unsupported_opcode_RESERVED"])
    assert result.outcome is AnalysisOutcome.UNSUPPORTED
    assert result.outcome_subreason == "unsupported_opcode"

    result = ExecutionResult(issues=[issue], degraded_passes=["solver_timeout_detector_query"])
    assert result.outcome is AnalysisOutcome.INCONCLUSIVE
    assert result.outcome_subreason == "solver_timeout"


def test_execution_result_structured_evidence_serializes_and_classifies() -> None:
    result = ExecutionResult(
        issues=[Issue(kind=IssueKind.TYPE_ERROR, message="bad operand")],
        outcome_evidence=[
            OutcomeEvidence(
                outcome=AnalysisOutcome.INCONCLUSIVE,
                subreason=OutcomeSubreason.RESOURCE_EXHAUSTED,
                label="resource_limit_time",
                source="scan.budget",
            )
        ],
    )

    assert result.outcome is AnalysisOutcome.INCONCLUSIVE
    assert result.outcome_subreason == "resource_exhausted"
    assert result.to_dict()["outcome_evidence"] == [
        {
            "outcome": "INCONCLUSIVE",
            "subreason": "resource_exhausted",
            "label": "resource_limit_time",
            "source": "scan.budget",
            "detail": None,
        }
    ]
