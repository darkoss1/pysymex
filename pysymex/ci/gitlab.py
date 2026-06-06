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

"""GitLab CI report generation."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

from pysymex.analysis.runtime.cache.keying import hash_bytecode
from pysymex.ci.types import (
    issue_file,
    issue_kind,
    issue_line,
    issue_message,
    issue_severity,
)
from pysymex.reporting.sarif import Severity, VulnerabilityReport


class GitLabReporter:
    """Reports analysis results in GitLab CI report formats.

    Generates Code Quality (``gl-code-quality-report.json``) and SAST
    (``gl-sast-report.json``) JSON files.
    """

    def generate_code_quality_report(
        self,
        vulnerabilities: list[VulnerabilityReport],
        output_path: str | Path = "gl-code-quality-report.json",
        *,
        issues: list[dict[str, object]] | None = None,
    ) -> None:
        """Generate GitLab Code Quality report."""
        report_issues: list[dict[str, object]] = []
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
            report_issues.append(cast("dict[str, object]", issue))
        if issues:
            for scanner_issue in issues:
                severity = issue_severity(scanner_issue)
                severity_map = {
                    Severity.CRITICAL: "blocker",
                    Severity.HIGH: "critical",
                    Severity.MEDIUM: "major",
                    Severity.LOW: "minor",
                    Severity.INFO: "info",
                }
                issue = {
                    "description": issue_message(scanner_issue),
                    "check_name": issue_kind(scanner_issue).replace(" ", ""),
                    "fingerprint": self._issue_fingerprint(scanner_issue),
                    "severity": severity_map.get(severity, "minor"),
                    "location": {
                        "path": issue_file(scanner_issue),
                        "lines": {
                            "begin": issue_line(scanner_issue),
                        },
                    },
                }
                report_issues.append(cast("dict[str, object]", issue))
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(report_issues, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def generate_sast_report(
        self,
        vulnerabilities: list[VulnerabilityReport],
        output_path: str | Path = "gl-sast-report.json",
        *,
        issues: list[dict[str, object]] | None = None,
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
        if issues:
            for scanner_issue in issues:
                severity = issue_severity(scanner_issue)
                severity_map = {
                    Severity.CRITICAL: "Critical",
                    Severity.HIGH: "High",
                    Severity.MEDIUM: "Medium",
                    Severity.LOW: "Low",
                    Severity.INFO: "Info",
                }
                vulnerabilities_out.append(
                    {
                        "id": self._issue_fingerprint(scanner_issue),
                        "category": "sast",
                        "name": issue_kind(scanner_issue),
                        "message": issue_message(scanner_issue),
                        "severity": severity_map.get(severity, "Unknown"),
                        "confidence": "High",
                        "scanner": {"id": "pysymex", "name": "pysymex"},
                        "location": {
                            "file": issue_file(scanner_issue),
                            "start_line": issue_line(scanner_issue),
                        },
                        "identifiers": [],
                    }
                )
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(report, indent=2, sort_keys=True),
            encoding="utf-8",
        )

    def _fingerprint(self, vuln: VulnerabilityReport) -> str:
        """Generate a stable fingerprint for a vulnerability."""
        data = f"{vuln.vuln_type}:{vuln.file_path}:{vuln.line_number}:{vuln.message}"
        return hash_bytecode(data.encode())[:32]

    def _issue_fingerprint(self, issue: dict[str, object]) -> str:
        """Generate a stable fingerprint for a scanner issue."""
        data = f"{issue_kind(issue)}:{issue_file(issue)}:{issue_line(issue)}:{issue_message(issue)}"
        return hash_bytecode(data.encode())[:32]


__all__ = ["GitLabReporter"]
