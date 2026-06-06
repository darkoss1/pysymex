from __future__ import annotations

from pysymex.analysis.detectors import Issue, IssueKind
from pysymex.scanner.issue_sink import ScannerIssueSink
from pysymex.scanner.types import ScanResult


def test_issue_sink_preserves_detector_confidence_metadata() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=False,
    )
    issue = Issue(
        kind=IssueKind.TYPE_ERROR,
        message="possible type error",
        pc=12,
        line_number=7,
        confidence=0.5,
        likelihood=0.25,
        suppression_reason="havoc-derived operand",
    )

    sink.handle_issue(issue)

    assert result.issues[0]["confidence"] == 0.5
    assert result.issues[0]["likelihood"] == 0.25
    assert result.issues[0]["suppression_reason"] == "havoc-derived operand"


def test_issue_sink_normalizes_empty_counterexample_to_no_trigger() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=False,
    )

    sink.handle_issue(
        Issue(
            kind=IssueKind.DIVISION_BY_ZERO,
            message="division by zero",
            pc=12,
            line_number=7,
            counterexample={},
        )
    )

    assert result.issues[0]["counterexample"] is None


def test_issue_sink_allows_trigger_to_replace_same_key_empty_counterexample() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    shared = {
        "kind": "DIVISION_BY_ZERO",
        "message": "division by zero",
        "line": 7,
        "pc": 12,
        "function_name": "target",
        "class_name": None,
        "full_path": "target.py",
    }

    sink.handle_issue({**shared, "counterexample": {}})
    sink.handle_issue({**shared, "counterexample": {"x": 0}})

    assert len(result.issues) == 1
    assert result.issues[0]["counterexample"] == {"x": 0}
