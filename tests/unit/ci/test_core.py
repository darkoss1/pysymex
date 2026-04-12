from __future__ import annotations

import io
import json
from pathlib import Path

from pysymex.ci.core import (
    CIRunner,
    GitHubActionsReporter,
    GitLabReporter,
    generate_precommit_config,
    generate_precommit_hook_script,
)
from pysymex.ci.types import CIResult, ExitCode, FailureThreshold
from pysymex.reporting.sarif import Severity, VulnerabilityReport


def _sample_vuln(severity: Severity = Severity.HIGH) -> VulnerabilityReport:
    return VulnerabilityReport(
        vuln_type="command_injection",
        message="user input reaches shell",
        severity=severity,
        file_path="pkg/mod.py",
        line_number=12,
        function_name="run",
        cwe_id=78,
    )


def test_github_actions_reporter_outputs_annotations() -> None:
    out = io.StringIO()
    reporter = GitHubActionsReporter(output=out)
    reporter.error("bad % value", file="a.py", line=3, title="oops")
    reporter.group("Summary")
    reporter.endgroup()

    text = out.getvalue()
    assert "::error file=a.py,line=3,title=oops::bad %25 value" in text
    assert "::group::Summary" in text
    assert "::endgroup::" in text


def test_gitlab_reporter_generates_code_quality_and_sast(tmp_path: Path) -> None:
    code_quality = tmp_path / "gl-code-quality-report.json"
    sast = tmp_path / "gl-sast-report.json"

    reporter = GitLabReporter()
    reporter.generate_code_quality_report([_sample_vuln()], code_quality)
    reporter.generate_sast_report([_sample_vuln()], sast)

    cq_data = json.loads(code_quality.read_text(encoding="utf-8"))
    sast_data = json.loads(sast.read_text(encoding="utf-8"))
    assert cq_data[0]["check_name"] == "command_injection"
    assert sast_data["vulnerabilities"][0]["severity"] == "High"


def test_precommit_templates_include_expected_entries() -> None:
    config = generate_precommit_config()
    hook = generate_precommit_hook_script()
    assert "repo: local" in config
    assert "PySyMex check" in config
    assert "git diff --cached" in hook


def test_ci_runner_counts_issues_and_sets_failure() -> None:
    runner = CIRunner(threshold=FailureThreshold(min_severity=Severity.HIGH))
    result = runner.analyze_and_report(
        files=["a.py"],
        vulnerabilities=[_sample_vuln(Severity.CRITICAL), _sample_vuln(Severity.LOW)],
        issues=[{"type": "type_error"}],
        duration=0.5,
    )

    assert isinstance(result, CIResult)
    assert result.exit_code is ExitCode.CRITICAL_FOUND
    assert result.issues_count == 3
    assert result.message.startswith("Failed")

