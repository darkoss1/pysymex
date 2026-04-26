from __future__ import annotations

from pathlib import Path
from typing import cast

from pysymex.reporting.html import (
    AnalysisReport,
    IssueReport,
    create_report_from_result,
    generate_html_report,
    save_html_report,
)


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

    report = create_report_from_result(_Result(), "f.py", "run", 0.2)
    assert report.issues[0].issue_type == "TYPE_ERROR"
    assert report.paths_explored == 2
