from __future__ import annotations

import io
import json
from pathlib import Path

import pytest

from pysymex.ci.github import GitHubActionsReporter
from pysymex.ci.gitlab import GitLabReporter
from pysymex.ci.precommit import generate_precommit_config, generate_precommit_hook_script
from pysymex.ci.runner import CIRunner, run_ci_check
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
    reporter.error("bad % value\nnext", file="pkg,a.py", line=3, title="oops:bad")
    reporter.notice("plain")
    reporter.group("Summary\nDetails")
    reporter.endgroup()

    text = out.getvalue()
    assert "::error file=pkg%2Ca.py,line=3,title=oops%3Abad::bad %25 value%0Anext" in text
    assert "::notice::plain" in text
    assert "::group::Summary%0ADetails" in text
    assert "::endgroup::" in text


def test_github_actions_env_files_are_created_and_multiline_safe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    output_path = tmp_path / "nested" / "github-output.txt"
    summary_path = tmp_path / "nested" / "summary.md"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output_path))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_path))

    reporter = GitHubActionsReporter(output=io.StringIO())
    reporter.set_output("single", "value")
    reporter.set_output("multi", "line1\nline2")
    reporter.write_summary("summary text")

    output_text = output_path.read_text(encoding="utf-8")
    assert "single=value\n" in output_text
    assert "multi<<" in output_text
    assert "line1\nline2" in output_text
    assert summary_path.read_text(encoding="utf-8") == "summary text\n"


def test_gitlab_reporter_generates_code_quality_and_sast(tmp_path: Path) -> None:
    code_quality = tmp_path / "reports" / "gl-code-quality-report.json"
    sast = tmp_path / "reports" / "gl-sast-report.json"

    reporter = GitLabReporter()
    reporter.generate_code_quality_report([_sample_vuln()], code_quality)
    reporter.generate_sast_report([_sample_vuln()], sast)

    cq_data = json.loads(code_quality.read_text(encoding="utf-8"))
    sast_data = json.loads(sast.read_text(encoding="utf-8"))
    assert cq_data[0]["check_name"] == "command_injection"
    assert sast_data["vulnerabilities"][0]["severity"] == "High"


def test_gitlab_reporter_includes_scanner_issues(tmp_path: Path) -> None:
    code_quality = tmp_path / "reports" / "gl-code-quality-report.json"
    sast = tmp_path / "reports" / "gl-sast-report.json"
    issue: dict[str, object] = {
        "kind": "DIVISION_BY_ZERO",
        "message": "division by symbolic zero",
        "file": "pkg/mod.py",
        "line": 8,
    }

    reporter = GitLabReporter()
    reporter.generate_code_quality_report([], issues=[issue], output_path=code_quality)
    reporter.generate_sast_report([], issues=[issue], output_path=sast)

    cq_data = json.loads(code_quality.read_text(encoding="utf-8"))
    sast_data = json.loads(sast.read_text(encoding="utf-8"))
    assert cq_data[0]["check_name"] == "DIVISION_BY_ZERO"
    assert cq_data[0]["location"]["path"] == "pkg/mod.py"
    assert sast_data["vulnerabilities"][0]["severity"] == "High"


def test_precommit_templates_include_expected_entries() -> None:
    config = generate_precommit_config()
    hook = generate_precommit_hook_script()
    assert "repo: local" in config
    assert "pysymex check" in config
    assert '"git", "diff", "--cached"' in hook


def test_ci_runner_counts_issues_and_sets_failure() -> None:
    runner = CIRunner(threshold=FailureThreshold(min_severity=Severity.HIGH))
    result = runner.analyze_and_report(
        files=["a.py"],
        vulnerabilities=[
            _sample_vuln(Severity.CRITICAL),
            _sample_vuln(Severity.LOW),
            _sample_vuln(Severity.INFO),
        ],
        issues=[
            {"type": "type_error"},
            {"type": "style", "severity": "info"},
            {"type": "logic", "severity": "critical"},
        ],
        duration=0.5,
    )

    assert isinstance(result, CIResult)
    assert result.exit_code is ExitCode.CRITICAL_FOUND
    assert result.issues_count == 6
    assert result.critical_count == 2
    assert result.high_count == 1
    assert result.low_count == 1
    assert result.info_count == 2
    assert result.message.startswith("Failed")


def test_ci_runner_reports_scanner_issues_to_github_and_gitlab(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    out = io.StringIO()
    monkeypatch.chdir(tmp_path)
    runner = CIRunner(
        threshold=FailureThreshold(min_severity=Severity.CRITICAL, max_high=-1),
        github_actions=True,
        gitlab_ci=True,
    )
    runner.github_reporter = GitHubActionsReporter(output=out)

    result = runner.analyze_and_report(
        files=["pkg/mod.py"],
        vulnerabilities=[],
        issues=[
            {
                "kind": "TYPE_ERROR",
                "message": "unsupported operand",
                "file": "pkg/mod.py",
                "line": 4,
            }
        ],
    )

    assert result.exit_code is ExitCode.SUCCESS
    assert "::error file=pkg/mod.py,line=4,title=TYPE_ERROR::" in out.getvalue()
    assert Path("gl-code-quality-report.json").exists()
    assert Path("gl-sast-report.json").exists()


def test_ci_runner_creates_sarif_parent_directory(tmp_path: Path) -> None:
    output_path = tmp_path / "nested" / "report.sarif"
    runner = CIRunner(
        threshold=FailureThreshold(min_severity=Severity.CRITICAL),
        sarif_output=str(output_path),
    )

    result = runner.analyze_and_report(files=["a.py"], vulnerabilities=[_sample_vuln()])

    assert output_path.exists()
    assert result.sarif_path == str(output_path)


def test_ci_runner_writes_scanner_issue_sarif_with_location_and_level(tmp_path: Path) -> None:
    output_path = tmp_path / "report.sarif"
    runner = CIRunner(sarif_output=str(output_path))

    runner.analyze_and_report(
        files=["pkg/mod.py"],
        vulnerabilities=[],
        issues=[
            {
                "kind": "DIVISION_BY_ZERO",
                "severity": "high",
                "message": "division by zero",
                "file": "pkg/mod.py",
                "line": 9,
            }
        ],
    )

    data = json.loads(output_path.read_text(encoding="utf-8"))
    sarif_result = data["runs"][0]["results"][0]
    assert sarif_result["level"] == "error"
    assert sarif_result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == (
        "pkg/mod.py"
    )
    assert sarif_result["locations"][0]["physicalLocation"]["region"]["startLine"] == 9


def test_run_ci_check_fails_when_scan_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    import pysymex.scanner as scanner

    def fail_scan(_file_path: str) -> object:
        raise RuntimeError("scanner exploded")

    monkeypatch.setattr(scanner, "scan_file", fail_scan)

    assert run_ci_check(["bad.py"]) == ExitCode.HIGH_FOUND.value


def test_run_ci_check_fails_when_scan_result_has_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pysymex.scanner as scanner

    class FailedScanResult:
        issues: list[dict[str, object]] = []
        error = "parse failed"

    def scan_with_error(_file_path: str) -> FailedScanResult:
        return FailedScanResult()

    monkeypatch.setattr(scanner, "scan_file", scan_with_error)

    assert run_ci_check(["bad.py"]) == ExitCode.HIGH_FOUND.value


def test_run_ci_check_honors_critical_fail_threshold(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pysymex.scanner as scanner

    class ScanResult:
        file_path = "pkg/mod.py"
        issues = [
            {
                "kind": "TYPE_ERROR",
                "message": "unsupported operand",
                "file": "pkg/mod.py",
                "line": 4,
            }
        ]
        error = None

    def scan_with_high_issue(_file_path: str) -> ScanResult:
        return ScanResult()

    monkeypatch.setattr(scanner, "scan_file", scan_with_high_issue)

    assert run_ci_check(["pkg/mod.py"], fail_on=Severity.CRITICAL) == ExitCode.SUCCESS.value


def test_run_ci_check_scans_directory_inputs_recursively(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pysymex.scanner as scanner

    class ScanResult:
        file_path = str(tmp_path / "pkg" / "mod.py")
        issues = [
            {
                "kind": "DIVISION_BY_ZERO",
                "message": "division by symbolic zero",
                "line_number": 7,
            }
        ]
        error = None

    seen_kwargs: dict[str, object] = {}

    def fake_scan_directory(_path: str, **kwargs: object) -> list[ScanResult]:
        seen_kwargs.update(kwargs)
        return [ScanResult()]

    monkeypatch.setattr(scanner, "scan_directory", fake_scan_directory)

    assert run_ci_check([str(tmp_path)]) == ExitCode.HIGH_FOUND.value
    assert seen_kwargs["recursive"] is True
    assert seen_kwargs["verbose"] is False


def test_run_ci_check_reports_scanned_files_for_directory_inputs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import pysymex.ci.runner as runner_module
    import pysymex.scanner as scanner

    scanned_file = str(tmp_path / "pkg" / "mod.py")

    class ScanResult:
        file_path = scanned_file
        issues: list[dict[str, object]] = []
        error = None

    captured_files: list[str] = []

    class CapturingRunner:
        def __init__(self, **_kwargs: object) -> None:
            return None

        def analyze_and_report(
            self,
            files: list[str],
            vulnerabilities: list[VulnerabilityReport],
            issues: list[dict[str, object]] | None = None,
            duration: float = 0.0,
        ) -> CIResult:
            _ = vulnerabilities
            _ = issues
            _ = duration
            captured_files.extend(files)
            return CIResult(exit_code=ExitCode.SUCCESS, files_analyzed=len(files))

    def fake_scan_directory(_path: str, **_kwargs: object) -> list[ScanResult]:
        return [ScanResult()]

    monkeypatch.setattr(scanner, "scan_directory", fake_scan_directory)
    monkeypatch.setattr(runner_module, "CIRunner", CapturingRunner)

    assert run_ci_check([str(tmp_path)]) == ExitCode.SUCCESS.value
    assert captured_files == [scanned_file]
