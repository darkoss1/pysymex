from __future__ import annotations

from pathlib import Path
from typing import cast

from pysymex.reporting.html.conversion import create_report_from_result, save_html_report
from pysymex.reporting.html.models import (
    AnalysisReport,
    IssueReport,
)
from pysymex.reporting.html.rendering import generate_html_report


def test_issue_and_analysis_report_to_dict() -> None:
    issue = IssueReport("high", "TYPE_ERROR", "bad", file_path="a.py", line_number=4)
    report = AnalysisReport(
        title="R",
        timestamp="t",
        duration_seconds=0.5,
        file_path="a.py",
        function_name="f",
        issues=[issue],
    )
    data = report.to_dict()
    issues = cast("list[dict[str, object]]", data["issues"])
    assert issues[0]["type"] == "TYPE_ERROR"
    assert data["file"] == "a.py"


def test_generate_and_save_html_report(tmp_path: Path) -> None:
    report = AnalysisReport(title="<unsafe>", timestamp="t", duration_seconds=1.0)
    html = generate_html_report(report)
    out = tmp_path / "report.html"
    save_html_report(report, out)

    assert "&lt;unsafe&gt;" in html
    assert out.exists()


def test_html_report_exposes_escaped_analysis_failure_without_clean_claim() -> None:
    report = AnalysisReport(
        title="Failed scan",
        timestamp="t",
        duration_seconds=1.0,
        success=False,
        error_message="Syntax Error: <invalid>",
    )

    html = generate_html_report(report)

    assert "Analysis error:" in html
    assert "Syntax Error: &lt;invalid&gt;" in html
    assert "No findings reported" in html
    assert "All explored paths completed" not in html


def test_create_report_from_result_maps_issue_like_objects() -> None:
    class _Issue:
        type = "TYPE_ERROR"
        message = "boom"
        severity = "high"
        line_number = 9

    class _Result:
        issues = [_Issue()]
        paths_explored = 2
        paths_completed = 1
        max_depth = 5
        error = None

    report = create_report_from_result(_Result(), "f.py", "run", 0.2)
    assert report.issues[0].issue_type == "TYPE_ERROR"
    assert report.paths_explored == 2


def test_create_report_from_result_preserves_analysis_failure() -> None:
    class _Result:
        issues: list[object] = []
        error = "Analysis Error: stopped"
        paths_explored = 0
        paths_completed = 0

    report = create_report_from_result(_Result(), "f.py", "run", 0.2)

    assert report.success is False
    assert report.error_message == "Analysis Error: stopped"


def test_create_report_from_result_exposes_degraded_analysis() -> None:
    class _Result:
        issues: list[object] = []
        degraded_passes = ["solver_unknown_detector_query"]
        paths_explored = 1
        paths_completed = 0

    report = create_report_from_result(_Result(), "f.py", "run", 0.2)

    assert report.success is False
    assert report.partial is True
    assert report.error_message == "Analysis degraded: solver_unknown_detector_query"
