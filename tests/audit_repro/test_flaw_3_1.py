import pytest
from pysymex.execution.executor import analyze
from pysymex.analysis.detectors import IssueKind


def test_division_by_zero_detection():
    """Verify that division by zero is detected (Flaw 3.1)."""

    def code_to_test(x: int, y: int):
        if y == 0:
            return 1
        # If y can be 0 here (it shouldn't because of the check above),
        # but let's try a case where it CAN be zero.
        return x / y

    def bug_code(x: int, y: int):
        # Here y is unconstrained, so y=0 is possible.
        return x / y

    # Analyze bug_code
    results = analyze(bug_code, symbolic_args={"x": "int", "y": "int"})

    # We expect a DIVISION_BY_ZERO issue
    div_zero_issues = [i for i in results.issues if i.kind == IssueKind.DIVISION_BY_ZERO]

    # Debug print issues
    for issue in results.issues:
        print(f"Issue found: {issue.kind} - {issue.message}")

    assert len(div_zero_issues) > 0, "Division by zero was NOT detected (husht)!"


def test_division_by_zero_no_false_positive():
    """Verify no false positive when zero is guarded."""

    def safe_code(x: int, y: int):
        if y == 0:
            return 0
        return x / y

    results = analyze(safe_code, symbolic_args={"x": "int", "y": "int"})
    div_zero_issues = [i for i in results.issues if i.kind == IssueKind.DIVISION_BY_ZERO]
    assert len(div_zero_issues) == 0, "False positive division by zero detected!"


def test_concrete_division_by_zero():
    """Verify that concrete division by zero is detected as an Issue, not a crash."""

    def concrete_bug():
        return 1 / 0

    results = analyze(concrete_bug)
    div_zero_issues = [i for i in results.issues if i.kind == IssueKind.DIVISION_BY_ZERO]

    # Debug print issues
    for issue in results.issues:
        print(f"Issue found: {issue.kind} - {issue.message}")

    assert len(div_zero_issues) > 0, "Concrete division by zero was NOT detected!"
