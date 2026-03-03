"""Tests for CI/CD integration module."""

import json

import pytest

from io import StringIO

from pathlib import Path


from pysymex.ci import (
    ExitCode,
    CIResult,
    FailureThreshold,
    GitHubActionsReporter,
    GitLabReporter,
    CIRunner,
    generate_precommit_config,
    generate_precommit_hook_script,
)

from pysymex.reporting.sarif import Severity, VulnerabilityReport


class TestExitCode:
    """Tests for ExitCode enum."""

    def test_exit_codes(self):
        assert ExitCode.SUCCESS == 0

        assert ExitCode.ISSUES_FOUND == 1

        assert ExitCode.ERROR == 2

        assert ExitCode.CONFIG_ERROR == 3

    def test_severity_codes(self):
        assert ExitCode.CRITICAL_FOUND == 10

        assert ExitCode.HIGH_FOUND == 11

        assert ExitCode.MEDIUM_FOUND == 12


class TestCIResult:
    """Tests for CIResult."""

    def test_create_result(self):
        result = CIResult(
            exit_code=ExitCode.SUCCESS,
            issues_count=0,
        )

        assert result.exit_code == ExitCode.SUCCESS

        assert result.issues_count == 0

    def test_result_with_issues(self):
        result = CIResult(
            exit_code=ExitCode.ISSUES_FOUND,
            issues_count=5,
            critical_count=1,
            high_count=2,
            medium_count=2,
        )

        assert result.issues_count == 5

        assert result.critical_count == 1

    def test_to_dict(self):
        result = CIResult(
            exit_code=ExitCode.SUCCESS,
            issues_count=3,
            critical_count=1,
            high_count=2,
            files_analyzed=10,
            duration_seconds=5.5,
        )

        d = result.to_dict()

        assert d["exit_code"] == 0

        assert d["exit_code_name"] == "SUCCESS"

        assert d["issues_count"] == 3

        assert d["by_severity"]["critical"] == 1

        assert d["files_analyzed"] == 10

    def test_to_json(self):
        result = CIResult(exit_code=ExitCode.SUCCESS)

        json_str = result.to_json()

        parsed = json.loads(json_str)

        assert parsed["exit_code"] == 0


class TestFailureThreshold:
    """Tests for FailureThreshold."""

    def test_default_threshold(self):
        threshold = FailureThreshold()

        assert threshold.min_severity == Severity.HIGH

    def test_should_fail_critical(self):
        threshold = FailureThreshold(
            min_severity=Severity.CRITICAL,
            max_critical=0,
            max_high=-1,
        )

        result_with_critical = CIResult(exit_code=ExitCode.SUCCESS, critical_count=1)

        result_no_critical = CIResult(exit_code=ExitCode.SUCCESS, high_count=5)

        assert threshold.should_fail(result_with_critical)

        assert not threshold.should_fail(result_no_critical)

    def test_should_fail_high(self):
        threshold = FailureThreshold(min_severity=Severity.HIGH)

        result_with_high = CIResult(exit_code=ExitCode.SUCCESS, high_count=1)

        result_only_medium = CIResult(exit_code=ExitCode.SUCCESS, medium_count=10)

        assert threshold.should_fail(result_with_high)

        assert not threshold.should_fail(result_only_medium)

    def test_should_fail_count_threshold(self):
        threshold = FailureThreshold(
            min_severity=Severity.INFO,
            max_critical=0,
            max_high=5,
        )

        result_over = CIResult(exit_code=ExitCode.SUCCESS, high_count=10)

        result_under = CIResult(exit_code=ExitCode.SUCCESS, high_count=3)

        assert threshold.should_fail(result_over)

        assert not threshold.should_fail(result_under)

    def test_get_exit_code(self):
        threshold = FailureThreshold()

        assert (
            threshold.get_exit_code(CIResult(exit_code=ExitCode.SUCCESS, critical_count=1))
            == ExitCode.CRITICAL_FOUND
        )

        assert (
            threshold.get_exit_code(CIResult(exit_code=ExitCode.SUCCESS, high_count=1))
            == ExitCode.HIGH_FOUND
        )

        assert threshold.get_exit_code(CIResult(exit_code=ExitCode.SUCCESS)) == ExitCode.SUCCESS


class TestGitHubActionsReporter:
    """Tests for GitHubActionsReporter."""

    def test_create_reporter(self):
        output = StringIO()

        reporter = GitHubActionsReporter(output=output)

        assert reporter is not None

    def test_error_annotation(self):
        output = StringIO()

        reporter = GitHubActionsReporter(output=output)

        reporter.error(
            "Test error",
            file="app.py",
            line=42,
            title="Error Title",
        )

        result = output.getvalue()

        assert "::error" in result

        assert "file=app.py" in result

        assert "line=42" in result

        assert "Test error" in result

    def test_warning_annotation(self):
        output = StringIO()

        reporter = GitHubActionsReporter(output=output)

        reporter.warning("Test warning", file="test.py")

        result = output.getvalue()

        assert "::warning" in result

    def test_notice_annotation(self):
        output = StringIO()

        reporter = GitHubActionsReporter(output=output)

        reporter.notice("Test notice")

        result = output.getvalue()

        assert "::notice" in result

    def test_group(self):
        output = StringIO()

        reporter = GitHubActionsReporter(output=output)

        reporter.group("Test Group")

        reporter.endgroup()

        result = output.getvalue()

        assert "::group::Test Group" in result

        assert "::endgroup::" in result

    def test_escape_message(self):
        output = StringIO()

        reporter = GitHubActionsReporter(output=output)

        reporter.error("Line1\nLine2\rLine3")

        result = output.getvalue()

        assert "%0A" in result

        assert "%0D" in result

    def test_report_vulnerability(self):
        output = StringIO()

        reporter = GitHubActionsReporter(output=output)

        vuln = VulnerabilityReport(
            vuln_type="Command Injection",
            severity=Severity.CRITICAL,
            cwe_id=78,
            message="Dangerous call",
            file_path="app.py",
            line_number=100,
        )

        reporter.report_vulnerability(vuln)

        result = output.getvalue()

        assert "::error" in result

        assert "Command Injection" in result


class TestGitLabReporter:
    """Tests for GitLabReporter."""

    def test_create_reporter(self):
        reporter = GitLabReporter()

        assert reporter is not None

    def test_generate_code_quality_report(self, tmp_path):
        reporter = GitLabReporter()

        vulns = [
            VulnerabilityReport(
                vuln_type="SQL Injection",
                severity=Severity.HIGH,
                cwe_id=89,
                message="SQL injection in query",
                file_path="db.py",
                line_number=50,
            ),
        ]

        output_path = tmp_path / "gl-code-quality-report.json"

        reporter.generate_code_quality_report(vulns, output_path)

        assert output_path.exists()

        content = json.loads(output_path.read_text())

        assert len(content) == 1

        assert content[0]["severity"] == "critical"

        assert content[0]["location"]["path"] == "db.py"

    def test_generate_sast_report(self, tmp_path):
        reporter = GitLabReporter()

        vulns = [
            VulnerabilityReport(
                vuln_type="Path Traversal",
                severity=Severity.MEDIUM,
                cwe_id=22,
                message="Potential path traversal",
                file_path="files.py",
            ),
        ]

        output_path = tmp_path / "gl-sast-report.json"

        reporter.generate_sast_report(vulns, output_path)

        assert output_path.exists()

        content = json.loads(output_path.read_text())

        assert content["version"] == "15.0.0"

        assert content["scan"]["scanner"]["id"] == "pysymex"

        assert len(content["vulnerabilities"]) == 1


class TestCIRunner:
    """Tests for CIRunner."""

    def test_create_runner(self):
        runner = CIRunner()

        assert runner.threshold is not None

    def test_analyze_and_report_success(self):
        runner = CIRunner()

        result = runner.analyze_and_report(
            files=["test.py"],
            vulnerabilities=[],
            issues=[],
            duration=1.0,
        )

        assert result.exit_code == ExitCode.SUCCESS

        assert result.issues_count == 0

    def test_analyze_and_report_with_vulns(self):
        runner = CIRunner(threshold=FailureThreshold(min_severity=Severity.HIGH))

        vulns = [
            VulnerabilityReport(
                vuln_type="Command Injection",
                severity=Severity.CRITICAL,
                cwe_id=78,
                message="Test",
            ),
        ]

        result = runner.analyze_and_report(
            files=["test.py"],
            vulnerabilities=vulns,
        )

        assert result.exit_code == ExitCode.CRITICAL_FOUND

        assert result.critical_count == 1

    def test_analyze_with_sarif(self, tmp_path):
        sarif_path = tmp_path / "report.sarif"

        runner = CIRunner(sarif_output=str(sarif_path))

        result = runner.analyze_and_report(
            files=["test.py"],
            vulnerabilities=[],
        )

        assert result.sarif_path == str(sarif_path)

        assert sarif_path.exists()


class TestPrecommitIntegration:
    """Tests for pre-commit integration."""

    def test_generate_precommit_config(self):
        config = generate_precommit_config()

        assert "pysymex" in config.lower()

        assert "repos:" in config

        assert "entry:" in config

    def test_generate_precommit_hook_script(self):
        script = generate_precommit_hook_script()

        assert "#!/usr/bin/env python3" in script

        assert "pysymex" in script.lower()

        assert "def main():" in script
