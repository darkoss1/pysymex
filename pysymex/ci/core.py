# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""CI/CD integration logic for pysymex.
Provides integrations for:
- GitHub Actions
- GitLab CI
- Pre-commit hooks
- Exit codes for CI pipelines
"""

from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import TextIO, cast

from pysymex.ci.types import CIResult, ExitCode, FailureThreshold
from pysymex.reporting.sarif import Severity, VulnerabilityReport, generate_sarif


class GitHubActionsReporter:
    """Reports analysis results using GitHub Actions workflow commands.

    Uses GitHub's annotation commands for errors/warnings, sets output
    variables, and writes a Markdown job summary.

    Attributes:
        output: Text stream for workflow commands (defaults to stdout).
    """

    def __init__(self, output: TextIO = sys.stdout) -> None:
        self.output = output

    def set_output(self, name: str, value: str) -> None:
        """Set a GitHub Actions output variable."""
        import os

        github_output_env = os.environ.get("GITHUB_OUTPUT", "")
        github_output = Path(github_output_env) if github_output_env else None
        if github_output and github_output.exists():
            with open(github_output, "a") as f:
                f.write(f"{name}={value}\n")
        else:
            print(f"::set-output name={name}::{value}", file=self.output)

    def error(
        self,
        message: str,
        file: str | None = None,
        line: int | None = None,
        col: int | None = None,
        title: str | None = None,
    ) -> None:
        """Create an error annotation."""
        params = self._build_params(file, line, col, title)
        print(f"::error {params}::{self._escape(message)}", file=self.output)

    def warning(
        self,
        message: str,
        file: str | None = None,
        line: int | None = None,
        col: int | None = None,
        title: str | None = None,
    ) -> None:
        """Create a warning annotation."""
        params = self._build_params(file, line, col, title)
        print(f"::warning {params}::{self._escape(message)}", file=self.output)

    def notice(
        self,
        message: str,
        file: str | None = None,
        line: int | None = None,
        col: int | None = None,
        title: str | None = None,
    ) -> None:
        """Create a notice annotation."""
        params = self._build_params(file, line, col, title)
        print(f"::notice {params}::{self._escape(message)}", file=self.output)

    def group(self, title: str) -> None:
        """Start a collapsible group."""
        print(f"::group::{title}", file=self.output)

    def endgroup(self) -> None:
        """End a collapsible group."""
        print("::endgroup::", file=self.output)

    def write_summary(self, content: str) -> None:
        """Write to the job summary."""
        import os

        summary_env = os.environ.get("GITHUB_STEP_SUMMARY", "")
        summary_file = Path(summary_env) if summary_env else None
        if summary_file and summary_file.exists():
            with open(summary_file, "a") as f:
                f.write(content + "\n")

    def _build_params(
        self,
        file: str | None,
        line: int | None,
        col: int | None,
        title: str | None,
    ) -> str:
        """Build parameter string for workflow commands."""
        parts: list[str] = []
        if file:
            parts.append(f"file={file}")
        if line is not None:
            parts.append(f"line={line}")
        if col is not None:
            parts.append(f"col={col}")
        if title:
            parts.append(f"title={title}")
        return ",".join(parts)

    def _escape(self, message: str) -> str:
        """Escape special characters for workflow commands."""
        return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def report_vulnerability(self, vuln: VulnerabilityReport) -> None:
        """Report a vulnerability as a GitHub annotation."""
        severity = vuln.severity
        cwe_label = f"CWE-{vuln.cwe_id}" if vuln.cwe_id else vuln.vuln_type
        message = f"[{cwe_label}] {vuln.message}"
        if severity in (Severity.CRITICAL, Severity.HIGH):
            self.error(
                message,
                file=vuln.file_path or None,
                line=vuln.line_number or None,
                title=vuln.vuln_type,
            )
        elif severity == Severity.MEDIUM:
            self.warning(
                message,
                file=vuln.file_path or None,
                line=vuln.line_number or None,
                title=vuln.vuln_type,
            )
        else:
            self.notice(
                message,
                file=vuln.file_path or None,
                line=vuln.line_number or None,
                title=vuln.vuln_type,
            )

    def report_result(self, result: CIResult) -> None:
        """Report the overall analysis result."""
        self.set_output("issues_count", str(result.issues_count))
        self.set_output("critical_count", str(result.critical_count))
        self.set_output("high_count", str(result.high_count))
        self.set_output("medium_count", str(result.medium_count))
        self.set_output("exit_code", str(result.exit_code.value))
        if result.sarif_path:
            self.set_output("sarif_path", result.sarif_path)
        summary = self._build_summary(result)
        self.write_summary(summary)

    def _build_summary(self, result: CIResult) -> str:
        """Build a markdown summary for the job."""
        status = "✅ Passed" if result.exit_code == ExitCode.SUCCESS else "❌ Failed"
        lines = [
            "## PySyMex Analysis Results",
            "",
            f"**Status**: {status}",
            f"**Files Analyzed**: {result.files_analyzed}",
            f"**Duration**: {result.duration_seconds:.2f}s",
            "",
            "### Issues by Severity",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| 🔴 Critical | {result.critical_count} |",
            f"| 🟠 High | {result.high_count} |",
            f"| 🟡 Medium | {result.medium_count} |",
            f"| 🔵 Low | {result.low_count} |",
            f"| **Total** | **{result.issues_count}** |",
        ]
        if result.sarif_path:
            lines.extend(
                [
                    "",
                    f"📄 SARIF report: `{result.sarif_path}`",
                ]
            )
        return "\n".join(lines)


class GitLabReporter:
    """Reports analysis results in GitLab CI report formats.

    Generates Code Quality (``gl-code-quality-report.json``) and
    SAST (``gl-sast-report.json``) JSON files.
    """

    def generate_code_quality_report(
        self,
        vulnerabilities: list[VulnerabilityReport],
        output_path: str | Path = "gl-code-quality-report.json",
    ) -> None:
        """Generate GitLab Code Quality report."""
        issues: list[dict[str, object]] = []
        for vuln in vulnerabilities:
            severity_map = {
                Severity.CRITICAL: "blocker",
                Severity.HIGH: "critical",
                Severity.MEDIUM: "major",
                Severity.LOW: "minor",
                Severity.INFO: "info",
            }
            issue = {
                "description": vuln.message,
                "check_name": vuln.vuln_type.replace(" ", ""),
                "fingerprint": self._fingerprint(vuln),
                "severity": severity_map.get(vuln.severity, "minor"),
                "location": {
                    "path": vuln.file_path or "unknown",
                    "lines": {
                        "begin": vuln.line_number or 1,
                    },
                },
            }
            issues.append(cast("dict[str, object]", issue))
        Path(output_path).write_text(
            json.dumps(issues, indent=2),
            encoding="utf-8",
        )

    def generate_sast_report(
        self,
        vulnerabilities: list[VulnerabilityReport],
        output_path: str | Path = "gl-sast-report.json",
    ) -> None:
        """Generate GitLab SAST report."""
        report: dict[str, object] = {
            "version": "15.0.0",
            "vulnerabilities": [],
            "scan": {
                "scanner": {
                    "id": "pysymex",
                    "name": "pysymex",
                    "version": "0.3.0a0",
                    "vendor": {"name": "pysymex"},
                },
                "type": "sast",
                "status": "success",
            },
        }
        vulnerabilities_out = cast("list[dict[str, object]]", report["vulnerabilities"])
        for vuln in vulnerabilities:
            severity_map = {
                Severity.CRITICAL: "Critical",
                Severity.HIGH: "High",
                Severity.MEDIUM: "Medium",
                Severity.LOW: "Low",
                Severity.INFO: "Info",
            }
            identifiers: list[dict[str, str]] = []
            if vuln.cwe_id:
                identifiers.append(
                    {
                        "type": "cwe",
                        "name": f"CWE-{vuln.cwe_id}",
                        "value": str(vuln.cwe_id),
                        "url": f"https://cwe.mitre.org/data/definitions/{vuln.cwe_id}.html",
                    }
                )
            v = {
                "id": self._fingerprint(vuln),
                "category": "sast",
                "name": vuln.vuln_type,
                "message": vuln.message,
                "severity": severity_map.get(vuln.severity, "Unknown"),
                "confidence": "High",
                "scanner": {"id": "pysymex", "name": "pysymex"},
                "location": {
                    "file": vuln.file_path or "unknown",
                    "start_line": vuln.line_number or 1,
                },
                "identifiers": identifiers,
            }
            vulnerabilities_out.append(cast("dict[str, object]", v))
        Path(output_path).write_text(
            json.dumps(report, indent=2),
            encoding="utf-8",
        )

    def _fingerprint(self, vuln: VulnerabilityReport) -> str:
        """Generate a stable fingerprint for a vulnerability."""
        import hashlib

        data = f"{vuln.vuln_type}:{vuln.file_path}:{vuln.line_number}:{vuln.message}"
        return hashlib.sha256(data.encode()).hexdigest()[:32]


def generate_precommit_config() -> str:
    """Generate .pre-commit-config.yaml content."""
    return """# PySyMex pre-commit hook
repos:
  - repo: local
    hooks:
      - id: PySyMex
        name: PySyMex Security Check
        entry: PySyMex check
        language: system
        types: [python]
        pass_filenames: true
        # Fail on high severity issues
        args: ["--fail-on", "high"]
"""


def generate_precommit_hook_script() -> str:
    """Generate a standalone pre-commit hook script."""
    return '''#!/usr/bin/env python3
"""pysymex pre-commit hook.
Install with: cp this_file .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
"""
import subprocess
import sys
def main():
    # Get staged Python files
    result = subprocess.run(
        ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
        capture_output=True,
        text=True,
    )
    files = [f for f in result.stdout.strip().split("\\n") if f.endswith(".py")]
    if not files:
        return 0
    # Run PySyMex
    cmd = ["pysymex", "check", "--fail-on", "high"] + files
    result = subprocess.run(cmd)
    return result.returncode
if __name__ == "__main__":
    sys.exit(main())
'''


class CIRunner:
    """Runs PySyMex in CI mode with configurable thresholds.

    Supports GitHub Actions annotations, GitLab reports, and
    optional SARIF output.

    Attributes:
        threshold: Failure threshold configuration.
        sarif_output: Optional SARIF output path.
        github_actions: Emit GitHub Actions workflow commands.
        gitlab_ci: Generate GitLab report files.
    """

    def __init__(
        self,
        threshold: FailureThreshold | None = None,
        sarif_output: str | None = None,
        github_actions: bool = False,
        gitlab_ci: bool = False,
    ) -> None:
        self.threshold = threshold or FailureThreshold()
        self.sarif_output = sarif_output
        self.github_actions = github_actions
        self.gitlab_ci = gitlab_ci
        self.github_reporter = GitHubActionsReporter() if github_actions else None
        self.gitlab_reporter = GitLabReporter() if gitlab_ci else None

    def analyze_and_report(
        self,
        files: list[str],
        vulnerabilities: list[VulnerabilityReport],
        issues: list[dict[str, object]] | None = None,
        duration: float = 0.0,
    ) -> CIResult:
        """Analyze files and generate CI report."""
        critical = sum(1 for v in vulnerabilities if v.severity == Severity.CRITICAL)
        high = sum(1 for v in vulnerabilities if v.severity == Severity.HIGH)
        medium = sum(1 for v in vulnerabilities if v.severity == Severity.MEDIUM)
        low = sum(1 for v in vulnerabilities if v.severity == Severity.LOW)
        if issues:
            for issue in issues:
                issue_type = str(issue.get("type", ""))
                if "error" in issue_type.lower():
                    high += 1
                else:
                    medium += 1
        total = critical + high + medium + low
        result = CIResult(
            exit_code=ExitCode.SUCCESS,
            issues_count=total,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            files_analyzed=len(files),
            duration_seconds=duration,
        )
        if self.threshold.should_fail(result):
            object.__setattr__(result, "exit_code", self.threshold.get_exit_code(result))
            object.__setattr__(
                result,
                "message",
                f"Failed: {total} issues found ({critical} critical, {high} high)",
            )
        else:
            object.__setattr__(result, "message", f"Passed: {total} issues found")
        if self.sarif_output:
            generate_sarif(
                vulnerabilities=vulnerabilities,
                issues=issues,
                analyzed_files=files,
                output_path=self.sarif_output,
            )
            object.__setattr__(result, "sarif_path", self.sarif_output)
        if self.github_reporter:
            for vuln in vulnerabilities:
                self.github_reporter.report_vulnerability(vuln)
            self.github_reporter.report_result(result)
        if self.gitlab_reporter:
            self.gitlab_reporter.generate_code_quality_report(vulnerabilities)
            self.gitlab_reporter.generate_sast_report(vulnerabilities)
        return result


def run_ci_check(
    files: list[str],
    fail_on: Severity = Severity.HIGH,
    sarif_output: str | None = None,
) -> int:
    """Run PySyMex analysis suitable for CI/CD pipelines.

    Scans the given *files*, evaluates results against *fail_on*
    severity, optionally writes a SARIF report, and emits CI-specific
    annotations when running inside GitHub Actions or GitLab CI.

    Args:
        files: Python files or directories to check.
        fail_on: Minimum severity to cause a non-zero exit.
        sarif_output: Optional path for SARIF output.

    Returns:
        Exit code (``0`` = success).
    """
    import os

    from pysymex.scanner import scan_file as _scan_file

    scan_file = cast("Callable[[str], object]", _scan_file)

    threshold = FailureThreshold(min_severity=fail_on)
    runner = CIRunner(
        threshold=threshold,
        sarif_output=sarif_output,
        github_actions="GITHUB_ACTIONS" in os.environ,
        gitlab_ci="GITLAB_CI" in os.environ,
    )
    all_vulns: list[VulnerabilityReport] = []
    all_issues: list[dict[str, object]] = []
    for file_path in files:
        try:
            scan_result = scan_file(file_path)
            raw_issues = getattr(scan_result, "issues", None)
            if isinstance(raw_issues, list):
                for issue in raw_issues:
                    if isinstance(issue, dict):
                        all_issues.append(cast("dict[str, object]", issue))
        except Exception as e:
            print(f"Error analyzing {file_path}: {e}", file=sys.stderr)
    ci_result = runner.analyze_and_report(
        files=files,
        vulnerabilities=all_vulns,
        issues=all_issues,
    )
    return ci_result.exit_code.value


__all__ = [
    "CIRunner",
    "GitHubActionsReporter",
    "GitLabReporter",
    "generate_precommit_config",
    "generate_precommit_hook_script",
    "run_ci_check",
]
