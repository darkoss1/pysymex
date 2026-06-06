from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import patch

from pysymex.cli.formatters.html import HtmlFormatter
from pysymex.cli.formatters.markdown import MarkdownFormatter
from pysymex.cli.formatters.sarif import SarifFormatter
from pysymex.cli.formatters.text import TextFormatter


@dataclass
class _FailedResult:
    file_path: str = "broken.py"
    error: str = "Syntax Error: invalid syntax"
    issues: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    elapsed_time: float = 0.1
    avg_memory_mb: float = 0.0
    paths_explored: int = 0
    max_depth_reached: int = 0


@dataclass
class _DegradedResult:
    file_path: str = "inconclusive.py"
    error: str | None = None
    degraded_passes: list[str] = field(default_factory=lambda: ["solver_unknown_detector_query"])
    issues: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    elapsed_time: float = 0.1
    avg_memory_mb: float = 0.0
    paths_explored: int = 1
    max_depth_reached: int = 0


def test_ascii_symbolic_report_does_not_claim_failed_scan_is_clean() -> None:
    output = TextFormatter(use_rich=False).format_symbolic([_FailedResult()], 0, 0.1)

    assert "[X] Scan errors:" in output
    assert "Syntax Error: invalid syntax" in output
    assert "[OK] No issues found!" not in output


def test_markdown_symbolic_report_exposes_analysis_failure() -> None:
    output = MarkdownFormatter().format_symbolic([_FailedResult()], 0, 0.1)

    assert "**Analysis Errors:** 1" in output
    assert "No findings reported; analysis did not complete successfully." in output
    assert "broken.py: Syntax Error: invalid syntax" in output
    assert "No issues found." not in output


def test_html_symbolic_report_sets_failure_state_for_analysis_error() -> None:
    with patch(
        "pysymex.cli.formatters.html.generate_html_report", return_value="<html></html>"
    ) as generate:
        output = HtmlFormatter().format_symbolic([_FailedResult()], 0, 0.1)

    report = generate.call_args.args[0]
    assert output == "<html></html>"
    assert report.success is False
    assert report.error_message == "broken.py: Syntax Error: invalid syntax"


def test_symbolic_reports_do_not_claim_degraded_scan_is_clean() -> None:
    result = _DegradedResult()

    ascii_output = TextFormatter(use_rich=False).format_symbolic([result], 0, 0.1)
    markdown_output = MarkdownFormatter().format_symbolic([result], 0, 0.1)
    sarif_output = json.loads(SarifFormatter().format_symbolic([result], 0, 0.1))

    assert "Degraded analyses:" in ascii_output
    assert "[OK] No issues found!" not in ascii_output
    assert "**Degraded Analyses:** 1" in markdown_output
    assert "No issues found." not in markdown_output
    invocation = sarif_output["runs"][0]["invocations"][0]
    assert invocation["executionSuccessful"] is False


def test_html_symbolic_report_sets_failure_state_for_degraded_analysis() -> None:
    with patch(
        "pysymex.cli.formatters.html.generate_html_report", return_value="<html></html>"
    ) as generate:
        HtmlFormatter().format_symbolic([_DegradedResult()], 0, 0.1)

    report = generate.call_args.args[0]
    assert report.success is False
    assert report.partial is True
    assert "Analysis degraded: solver_unknown_detector_query" in report.error_message
