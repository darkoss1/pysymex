from __future__ import annotations

from pysymex._internal.analysis.detectors.detector.types import Issue
from pysymex._internal.analysis.records import IssueRecord
from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.scanner.issues import ScannerIssueSink
from pysymex._internal.scanner.types import ScanResult


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


def test_issue_sink_trigger_dominates_same_message_helper_site() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    shared = {
        "kind": "VALUE_ERROR",
        "message": "Possible ValueError: closed handle",
        "function_name": "target",
        "class_name": None,
        "full_path": "target",
    }

    sink.handle_issue({**shared, "line": 18, "pc": 56, "counterexample": None})
    sink.handle_issue({**shared, "line": 83, "pc": 7, "counterexample": {"mode": 13}})

    assert result.issues == [
        {**shared, "line": 83, "pc": 7, "counterexample": {"mode": 13}},
    ]


def test_issue_sink_drops_later_same_message_helper_site_without_trigger() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    shared = {
        "kind": "ATTRIBUTE_ERROR",
        "message": "Possible AttributeError: missing_hard",
        "function_name": "target",
        "class_name": None,
        "full_path": "target",
    }

    sink.handle_issue({**shared, "line": 83, "pc": 8, "counterexample": {"mode": 11}})
    sink.handle_issue({**shared, "line": 52, "pc": 36, "counterexample": None})

    assert result.issues == [
        {**shared, "line": 83, "pc": 8, "counterexample": {"mode": 11}},
    ]


def test_issue_sink_preserves_distinct_trigger_backed_same_message_findings() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    shared = {
        "kind": "DIVISION_BY_ZERO",
        "message": "Possible ZeroDivisionError: division by zero",
        "function_name": "target",
        "class_name": None,
        "full_path": "target",
    }

    sink.handle_issue({**shared, "line": 17, "pc": 11, "counterexample": {"mode": 0}})
    sink.handle_issue({**shared, "line": 45, "pc": 29, "counterexample": {"mode": 5}})

    assert result.issues == [
        {**shared, "line": 17, "pc": 11, "counterexample": {"mode": 0}},
        {**shared, "line": 45, "pc": 29, "counterexample": {"mode": 5}},
    ]


def test_issue_sink_collapses_trigger_backed_same_source_operation_variants() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    shared = {
        "kind": "UNBOUND_VARIABLE",
        "line": 11,
        "column": 15,
        "pc": 11,
        "function_name": "late",
        "class_name": None,
        "full_path": "late",
    }

    sink.handle_issue(
        {
            **shared,
            "message": "Variable 'hidden' may be unbound (UnboundLocalError) (+ 1 variant)",
            "counterexample": {"mode": 10},
        }
    )
    sink.handle_issue(
        {
            **shared,
            "message": "Variable 'hidden' may be unbound (UnboundLocalError)",
            "counterexample": {"mode": 2},
        }
    )

    assert result.issues == [
        {
            **shared,
            "message": "Variable 'hidden' may be unbound (UnboundLocalError) (+ 1 variant)",
            "counterexample": {"mode": 10},
        }
    ]


def test_issue_sink_preserves_trigger_backed_same_operation_in_distinct_contexts() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    shared = {
        "kind": "TYPE_ERROR",
        "message": "Cannot concatenate 'str' with non-'str' operand",
        "line": 18,
        "column": 25,
        "pc": 29,
        "class_name": None,
        "counterexample": {"mode": 3},
    }

    sink.handle_issue({**shared, "function_name": "drive", "full_path": "drive"})
    sink.handle_issue({**shared, "function_name": "target", "full_path": "target"})

    assert result.issues == [
        {**shared, "function_name": "drive", "full_path": "drive"},
        {**shared, "function_name": "target", "full_path": "target"},
    ]


def test_issue_sink_specialized_unbound_suppresses_generic_unhandled_wrapper() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    specialized: IssueRecord = {
        "kind": "UNBOUND_VARIABLE",
        "message": "Variable 'hidden' may be unbound (UnboundLocalError)",
        "line": 11,
        "pc": 11,
        "function_name": "late",
        "class_name": None,
        "full_path": "late",
        "counterexample": {"mode": 10},
    }
    generic: IssueRecord = {
        "kind": "UNHANDLED_EXCEPTION",
        "message": (
            "Path raises unhandled exception: UnboundLocalError: cannot access local "
            "variable 'hidden' where it is not associated with a value"
        ),
        "line": 17,
        "pc": 11,
        "function_name": "target",
        "class_name": None,
        "full_path": "target",
        "counterexample": {"mode": 2},
    }

    sink.handle_issue(specialized)
    sink.handle_issue(generic)

    assert result.issues == [specialized]


def test_issue_sink_later_specialized_name_error_removes_generic_wrapper() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    generic: IssueRecord = {
        "kind": "UNHANDLED_EXCEPTION",
        "message": "Path raises unhandled exception: NameError: name 'missing' is not defined",
        "line": 21,
        "pc": 8,
        "function_name": "target",
        "class_name": None,
        "full_path": "target",
        "counterexample": {"mode": 1},
    }
    specialized: IssueRecord = {
        "kind": "NAME_ERROR",
        "message": "Variable 'missing' may be unbound (NameError)",
        "line": 7,
        "pc": 2,
        "function_name": "helper",
        "class_name": None,
        "full_path": "helper",
        "counterexample": {"mode": 2},
    }

    sink.handle_issue(generic)
    sink.handle_issue(specialized)

    assert result.issues == [specialized]


def test_issue_sink_keeps_unrelated_name_family_unhandled_wrapper() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    specialized: IssueRecord = {
        "kind": "UNBOUND_VARIABLE",
        "message": "Variable 'hidden' may be unbound (UnboundLocalError)",
        "line": 11,
        "pc": 11,
        "function_name": "late",
        "class_name": None,
        "full_path": "late",
        "counterexample": {"mode": 10},
    }
    unrelated: IssueRecord = {
        "kind": "UNHANDLED_EXCEPTION",
        "message": (
            "Path raises unhandled exception: UnboundLocalError: cannot access local "
            "variable 'other' where it is not associated with a value"
        ),
        "line": 17,
        "pc": 11,
        "function_name": "target",
        "class_name": None,
        "full_path": "target",
        "counterexample": {"mode": 2},
    }

    sink.handle_issue(specialized)
    sink.handle_issue(unrelated)

    assert result.issues == [specialized, unrelated]


def test_issue_sink_precise_column_replaces_imprecise_same_line_message() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    shared = {
        "kind": "UNHANDLED_EXCEPTION",
        "message": "Path raises unhandled exception: RuntimeError: cleanup failed",
        "line": 55,
        "counterexample": None,
    }

    sink.handle_issue(
        {
            **shared,
            "pc": 40,
            "function_name": "target",
            "class_name": None,
            "full_path": "target",
        }
    )
    sink.handle_issue(
        {
            **shared,
            "column": 12,
            "pc": 77,
            "function_name": "cleanup",
            "class_name": None,
            "full_path": "cleanup",
        }
    )

    assert result.issues == [
        {
            **shared,
            "column": 12,
            "pc": 77,
            "function_name": "cleanup",
            "class_name": None,
            "full_path": "cleanup",
        }
    ]


def test_issue_sink_preserves_precise_same_line_message_in_distinct_contexts() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    shared = {
        "kind": "VALUE_ERROR",
        "message": "Possible ValueError: below absolute zero",
        "line": 9,
        "column": 12,
        "pc": 34,
        "class_name": None,
        "counterexample": None,
    }

    sink.handle_issue({**shared, "function_name": "celsius", "full_path": "Thermometer.celsius"})
    sink.handle_issue({**shared, "function_name": "target", "full_path": "target"})

    assert result.issues == [
        {**shared, "function_name": "celsius", "full_path": "Thermometer.celsius"},
        {**shared, "function_name": "target", "full_path": "target"},
    ]


def test_issue_sink_preserves_distinct_trigger_backed_same_line_findings() -> None:
    result = ScanResult(file_path="target.py", timestamp="now")
    sink = ScannerIssueSink(
        result=result,
        blocked_resolution_sites=set(),
        dedup_enabled=True,
    )
    shared = {
        "kind": "UNHANDLED_EXCEPTION",
        "line": 51,
        "function_name": "target",
        "class_name": None,
        "full_path": "target",
    }

    sink.handle_issue(
        {
            **shared,
            "message": "Path raises unhandled exception: RuntimeError: outer finally",
            "pc": 101,
            "counterexample": {"mode": 4},
        }
    )
    sink.handle_issue(
        {
            **shared,
            "message": "Path raises unhandled exception: RuntimeError: generator raised StopIteration",
            "pc": 134,
            "counterexample": {"mode": 1},
        }
    )

    assert len(result.issues) == 2
    assert {issue["pc"] for issue in result.issues} == {101, 134}
