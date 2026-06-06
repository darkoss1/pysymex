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

"""GitHub Actions CI reporting."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TextIO
from uuid import uuid4

from pysymex.ci.types import (
    CIResult,
    ExitCode,
    issue_file,
    issue_kind,
    issue_line,
    issue_message,
    issue_severity,
)
from pysymex.logger import get_logger
from pysymex.reporting.sarif import Severity, VulnerabilityReport

logger = get_logger(__name__)


class GitHubActionsReporter:
    """Reports analysis results using GitHub Actions workflow commands.

    Uses GitHub's annotation commands for errors/warnings, sets output
    variables, and writes a Markdown job summary.

    Attributes:
        output: Text stream for workflow commands (defaults to stdout).
    """

    def __init__(self, output: TextIO = sys.stdout) -> None:
        """Initialize the GitHub Actions CI reporter.

        Args:
            output (TextIO): Stream to write workflow annotation commands to.
                Defaults to sys.stdout.
        """
        self.output = output

    def set_output(self, name: str, value: str) -> None:
        """Set a GitHub Actions output variable."""
        import os

        github_output_env = os.environ.get("GITHUB_OUTPUT", "")
        github_output = Path(github_output_env) if github_output_env else None
        if github_output:
            logger.verbose("Writing GitHub Actions output %s to %s", name, github_output)
            github_output.parent.mkdir(parents=True, exist_ok=True)
            with github_output.open("a", encoding="utf-8") as f:
                if "\n" in value or "\r" in value:
                    delimiter = f"pysymex_{uuid4().hex}"
                    f.write(f"{name}<<{delimiter}\n{value}\n{delimiter}\n")
                else:
                    f.write(f"{name}={value}\n")
        else:
            logger.verbose("Skipping GitHub Actions output %s; GITHUB_OUTPUT is unset", name)

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
        print(self._command("error", params, message), file=self.output)

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
        print(self._command("warning", params, message), file=self.output)

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
        print(self._command("notice", params, message), file=self.output)

    def group(self, title: str) -> None:
        """Start a collapsible group."""
        print(f"::group::{self._escape_data(title)}", file=self.output)

    def endgroup(self) -> None:
        """End a collapsible group."""
        print("::endgroup::", file=self.output)

    def write_summary(self, content: str) -> None:
        """Write to the job summary."""
        import os

        summary_env = os.environ.get("GITHUB_STEP_SUMMARY", "")
        summary_file = Path(summary_env) if summary_env else None
        if summary_file:
            logger.verbose("Writing GitHub Actions step summary to %s", summary_file)
            summary_file.parent.mkdir(parents=True, exist_ok=True)
            with summary_file.open("a", encoding="utf-8") as f:
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
            parts.append(f"file={self._escape_property(file)}")
        if line is not None:
            parts.append(f"line={line}")
        if col is not None:
            parts.append(f"col={col}")
        if title:
            parts.append(f"title={self._escape_property(title)}")
        return ",".join(parts)

    def _escape_data(self, message: str) -> str:
        """Escape workflow-command message data."""
        return message.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    def _escape_property(self, value: str) -> str:
        """Escape workflow-command property values."""
        return self._escape_data(value).replace(":", "%3A").replace(",", "%2C")

    def _command(self, name: str, params: str, message: str) -> str:
        """Build a GitHub workflow command."""
        data = self._escape_data(message)
        if params:
            return f"::{name} {params}::{data}"
        return f"::{name}::{data}"

    def report_vulnerability(self, vuln: VulnerabilityReport) -> None:
        """Report a vulnerability as a GitHub annotation."""
        severity = vuln.severity
        logger.verbose(
            "Reporting GitHub Actions vulnerability severity=%s file=%s",
            severity.name,
            vuln.file_path,
        )
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

    def report_issue(self, issue: dict[str, object]) -> None:
        """Report a scanner issue as a GitHub annotation."""
        severity = issue_severity(issue)
        kind = issue_kind(issue)
        message = f"[{kind}] {issue_message(issue)}"
        file_path = issue_file(issue)
        line = issue_line(issue)
        if severity in (Severity.CRITICAL, Severity.HIGH):
            self.error(message, file=file_path, line=line, title=kind)
        elif severity == Severity.MEDIUM:
            self.warning(message, file=file_path, line=line, title=kind)
        else:
            self.notice(message, file=file_path, line=line, title=kind)

    def report_result(self, result: CIResult) -> None:
        """Report the overall analysis result."""
        self.set_output("issues_count", str(result.issues_count))
        self.set_output("critical_count", str(result.critical_count))
        self.set_output("high_count", str(result.high_count))
        self.set_output("medium_count", str(result.medium_count))
        self.set_output("low_count", str(result.low_count))
        self.set_output("info_count", str(result.info_count))
        self.set_output("exit_code", str(result.exit_code.value))
        if result.sarif_path:
            self.set_output("sarif_path", result.sarif_path)
        summary = self._build_summary(result)
        self.write_summary(summary)

    def _build_summary(self, result: CIResult) -> str:
        """Build a markdown summary for the job."""
        status = "Passed" if result.exit_code == ExitCode.SUCCESS else "Failed"
        lines = [
            "## pysymex Analysis Results",
            "",
            f"**Status**: {status}",
            f"**Files Analyzed**: {result.files_analyzed}",
            f"**Duration**: {result.duration_seconds:.2f}s",
            "",
            "### Issues by Severity",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {result.critical_count} |",
            f"| High | {result.high_count} |",
            f"| Medium | {result.medium_count} |",
            f"| Low | {result.low_count} |",
            f"| Info | {result.info_count} |",
            f"| **Total** | **{result.issues_count}** |",
        ]
        if result.sarif_path:
            lines.extend(
                [
                    "",
                    f"SARIF report: `{result.sarif_path}`",
                ]
            )
        return "\n".join(lines)


__all__ = ["GitHubActionsReporter"]
