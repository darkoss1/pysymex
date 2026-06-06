# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""CI runner orchestration."""

from __future__ import annotations

import sys
from collections.abc import Callable
from pathlib import Path
from typing import TypeGuard, cast

from pysymex.ci.github import GitHubActionsReporter
from pysymex.ci.gitlab import GitLabReporter
from pysymex.ci.types import CIResult, ExitCode, FailureThreshold, issue_severity
from pysymex.logger import get_logger
from pysymex.reporting.sarif import Severity, VulnerabilityReport, generate_sarif

logger = get_logger(__name__)


def _is_object_dict_list(value: object) -> TypeGuard[list[dict[object, object]]]:
    """Return whether value is list[dict[object, object]]."""
    if not isinstance(value, list):
        return False
    items = cast("list[object]", value)
    return all(isinstance(item, dict) for item in items)


def _normalize_issue(issue: dict[object, object], file_path: str) -> dict[str, object]:
    """Normalize scanner issue records for CI consumers."""
    normalized: dict[str, object] = {}
    for key, value in issue.items():
        normalized[str(key)] = value
    if not normalized.get("file") and not normalized.get("filename"):
        normalized["file"] = file_path
    if "line" not in normalized and "line_number" in normalized:
        normalized["line"] = normalized["line_number"]
    if normalized.get("severity") is None:
        normalized["severity"] = issue_severity(normalized).name.lower()
    return normalized


def _append_scan_result_issues(
    scan_result: object,
    all_issues: list[dict[str, object]],
    default_file: str,
) -> str:
    """Append normalized issues and scan errors from one scanner result."""
    result_file = str(getattr(scan_result, "file_path", default_file))
    raw_issues = getattr(scan_result, "issues", None)
    if _is_object_dict_list(raw_issues):
        for issue in raw_issues:
            all_issues.append(_normalize_issue(issue, result_file))

    raw_error = getattr(scan_result, "error", None)
    if raw_error:
        all_issues.append(
            {
                "type": "analysis_error",
                "severity": "high",
                "file": result_file,
                "message": str(raw_error),
            }
        )
    degraded_passes = getattr(scan_result, "degraded_passes", [])
    if isinstance(degraded_passes, list) and degraded_passes:
        typed_degraded_passes = cast("list[object]", degraded_passes)
        all_issues.append(
            {
                "type": "analysis_error",
                "severity": "high",
                "file": result_file,
                "message": (
                    f"Analysis degraded: {', '.join(str(item) for item in typed_degraded_passes)}"
                ),
            }
        )
    return result_file


def _analysis_error_messages(issues: list[dict[str, object]] | None) -> list[str]:
    """Extract scan failure diagnostics from CI issues."""
    if not issues:
        return []
    return [
        str(issue.get("message", "Analysis did not complete successfully."))
        for issue in issues
        if str(issue.get("type") or issue.get("kind", "")).lower() == "analysis_error"
    ]


class CIRunner:
    """Runs pysymex in CI mode with configurable thresholds.

    Supports GitHub Actions annotations, GitLab reports, and optional SARIF
    output.

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
        """Initialize the CI Runner.

        Args:
            threshold (FailureThreshold | None): Configuration defining issue severity levels
                that should trigger a non-zero exit code. If None, default thresholds are used.
            sarif_output (str | None): Optional filepath to write a SARIF format report.
            github_actions (bool): Enable GitHub Actions-specific reporter and annotations.
                Defaults to False.
            gitlab_ci (bool): Enable GitLab CI-specific reporter and output files.
                Defaults to False.
        """
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
        info = sum(1 for v in vulnerabilities if v.severity == Severity.INFO)
        if issues:
            for issue in issues:
                severity = issue_severity(issue)
                if severity == Severity.CRITICAL:
                    critical += 1
                elif severity == Severity.HIGH:
                    high += 1
                elif severity == Severity.MEDIUM:
                    medium += 1
                elif severity == Severity.LOW:
                    low += 1
                else:
                    info += 1
        total = critical + high + medium + low + info
        logger.verbose(
            ("CI analysis summary files=%d issues=%d critical=%d high=%d medium=%d low=%d info=%d"),
            len(files),
            total,
            critical,
            high,
            medium,
            low,
            info,
        )
        temp_result = CIResult(
            exit_code=ExitCode.SUCCESS,
            issues_count=total,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            files_analyzed=len(files),
            duration_seconds=duration,
        )

        exit_code = ExitCode.SUCCESS
        message = f"Passed: {total} issues found"
        if self.threshold.should_fail(temp_result):
            exit_code = self.threshold.get_exit_code(temp_result)
            message = f"Failed: {total} issues found ({critical} critical, {high} high)"

        sarif_path = None
        if self.sarif_output:
            analysis_errors = _analysis_error_messages(issues)
            Path(self.sarif_output).parent.mkdir(parents=True, exist_ok=True)
            generate_sarif(
                vulnerabilities=vulnerabilities,
                issues=issues,
                analyzed_files=files,
                output_path=self.sarif_output,
                execution_successful=not analysis_errors,
                analysis_errors=analysis_errors or None,
            )
            sarif_path = self.sarif_output
            logger.info("Wrote CI SARIF report: %s", sarif_path)

        result = CIResult(
            exit_code=exit_code,
            issues_count=total,
            critical_count=critical,
            high_count=high,
            medium_count=medium,
            low_count=low,
            info_count=info,
            files_analyzed=len(files),
            duration_seconds=duration,
            message=message,
            sarif_path=sarif_path,
        )
        if self.github_reporter:
            for vuln in vulnerabilities:
                self.github_reporter.report_vulnerability(vuln)
            for issue in issues or ():
                self.github_reporter.report_issue(issue)
            self.github_reporter.report_result(result)
        if self.gitlab_reporter:
            self.gitlab_reporter.generate_code_quality_report(vulnerabilities, issues=issues)
            self.gitlab_reporter.generate_sast_report(vulnerabilities, issues=issues)
        return result


def run_ci_check(
    files: list[str],
    fail_on: Severity = Severity.HIGH,
    sarif_output: str | None = None,
) -> int:
    """Run pysymex analysis suitable for CI/CD pipelines.

    Scans the given *files*, evaluates results against *fail_on* severity,
    optionally writes a SARIF report, and emits CI-specific annotations when
    running inside GitHub Actions or GitLab CI.

    Args:
        files: Python files or directories to check.
        fail_on: Minimum severity to cause a non-zero exit.
        sarif_output: Optional path for SARIF output.

    Returns:
        Exit code (``0`` = success).
    """
    import os

    from pysymex.scanner import scan_directory as _scan_directory
    from pysymex.scanner import scan_file as _scan_file

    scan_file = cast("Callable[[str], object]", _scan_file)
    scan_directory = cast("Callable[..., list[object]]", _scan_directory)

    threshold = FailureThreshold(
        min_severity=fail_on,
        max_critical=-1,
        max_high=-1,
        max_medium=-1,
        max_low=-1,
        max_info=-1,
    )
    runner = CIRunner(
        threshold=threshold,
        sarif_output=sarif_output,
        github_actions="GITHUB_ACTIONS" in os.environ,
        gitlab_ci="GITLAB_CI" in os.environ,
    )
    all_vulns: list[VulnerabilityReport] = []
    all_issues: list[dict[str, object]] = []
    analyzed_files: list[str] = []
    for file_path in files:
        try:
            logger.verbose("CI scanning file: %s", file_path)
            input_path = Path(file_path)
            if input_path.is_dir():
                scan_results = scan_directory(
                    str(input_path),
                    verbose=False,
                    recursive=True,
                )
                for scan_result in scan_results:
                    analyzed_files.append(
                        _append_scan_result_issues(scan_result, all_issues, file_path)
                    )
            else:
                scan_result = scan_file(file_path)
                analyzed_files.append(
                    _append_scan_result_issues(scan_result, all_issues, file_path)
                )
        except Exception as e:
            logger.warning("Error analyzing %s: %s", file_path, e)
            print(f"Error analyzing {file_path}: {e}", file=sys.stderr)
            analyzed_files.append(file_path)
            all_issues.append(
                {
                    "type": "analysis_error",
                    "severity": "high",
                    "file": file_path,
                    "message": str(e),
                }
            )
    ci_result = runner.analyze_and_report(
        files=analyzed_files,
        vulnerabilities=all_vulns,
        issues=all_issues,
    )
    return ci_result.exit_code.value


__all__ = ["CIRunner", "run_ci_check"]
