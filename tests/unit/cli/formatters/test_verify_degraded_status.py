from __future__ import annotations

import json
from dataclasses import dataclass, field
from unittest.mock import patch

from pysymex.cli.formatters.html import HtmlFormatter
from pysymex.cli.formatters.markdown import MarkdownFormatter
from pysymex.cli.formatters.sarif import SarifFormatter
from pysymex.cli.formatters.text import TextFormatter


@dataclass
class _DegradedVerifyResult:
    function_name: str = "checked"
    source_file: str = "verify.py"
    paths_explored: int = 1
    paths_completed: int = 0
    issues: list[object] = field(default_factory=list[object])
    contract_issues: list[object] = field(default_factory=list[object])
    arithmetic_issues: list[object] = field(default_factory=list[object])
    termination_proof: object | None = None
    degraded_passes: list[str] = field(default_factory=lambda: ["solver_unknown_detector_query"])


def test_verify_text_and_markdown_reports_do_not_claim_degraded_result_is_verified() -> None:
    result = _DegradedVerifyResult()

    text = TextFormatter(use_rich=False).format_verify([result], 0, 0.1)
    markdown = MarkdownFormatter().format_verify([result], 0, 0.1)

    assert "verification was degraded" in text
    assert "All selected contracts verified." not in text
    assert "verification was degraded" in markdown
    assert "All selected contracts verified." not in markdown


def test_verify_html_and_sarif_reports_mark_degraded_result_incomplete() -> None:
    result = _DegradedVerifyResult()
    with patch(
        "pysymex.cli.formatters.html.generate_html_report", return_value="<html></html>"
    ) as generate:
        HtmlFormatter().format_verify([result], 0, 0.1)

    report = generate.call_args.args[0]
    payload = json.loads(SarifFormatter().format_verify([result], 0, 0.1))
    invocation = payload["runs"][0]["invocations"][0]

    assert report.success is False
    assert report.partial is True
    assert invocation["executionSuccessful"] is False
