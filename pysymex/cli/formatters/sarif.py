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

"""SARIF formatter for scan results."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any, cast

from pysymex.cli.formatters.base import Formatter, iter_verify_issue_records
from pysymex.contracts.reports.evidence import contract_evidence_for_issue


class SarifFormatter(Formatter):
    """Outputs scan results in SARIF 2.1.0 format."""

    def format_symbolic(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
        reproduce: bool = False,
        show_stats: bool = False,
    ) -> str:
        """Format symbolic execution scan results in SARIF format.

        Args:
            results (Sequence[Any]): Sequence of symbolic execution results.
            total (int): Total number of issues found.
            duration (float): Execution duration in seconds.
            reproduce (bool): True if reproduction test cases are requested, False otherwise.
                Defaults to False.
            show_stats (bool): True to include performance statistics in the report.
                Defaults to False.

        Returns:
            str: SARIF JSON log output.
        """
        from pysymex.reporting.sarif import SARIFGenerator

        generator = SARIFGenerator()
        all_issues: list[dict[str, object]] = []
        all_files: list[str] = []
        analysis_errors: list[str] = []

        # We need to extract typed scan results similar to scan.py
        for scan_result in results:
            if hasattr(scan_result, "file_path"):
                all_files.append(str(scan_result.file_path))
                raw_error = getattr(scan_result, "error", None)
                if raw_error:
                    analysis_errors.append(f"{scan_result.file_path}: {raw_error}")
                degraded_passes = list(getattr(scan_result, "degraded_passes", []))
                if degraded_passes:
                    analysis_errors.append(
                        f"{scan_result.file_path}: Analysis degraded: {', '.join(degraded_passes)}"
                    )
                if hasattr(scan_result, "issues"):
                    for issue in scan_result.issues:
                        if isinstance(issue, dict):
                            issue_dict = cast("dict[str, Any]", issue)
                            si: dict[str, Any] = issue_dict.copy()
                            si["type"] = issue_dict.get("kind", "UNKNOWN")
                            si["file"] = str(scan_result.file_path)
                            all_issues.append(si)
        return generator.generate(
            issues=all_issues,
            analyzed_files=all_files,
            execution_successful=not analysis_errors,
            analysis_errors=analysis_errors or None,
        ).to_json()

    def format_verify(
        self,
        results: Sequence[Any],
        total: int,
        duration: float,
    ) -> str:
        """Format formal verification results in SARIF format.

        Args:
            results (Sequence[Any]): Sequence of verification results.
            total (int): Total number of verification issues found.
            duration (float): Verification execution duration in seconds.

        Returns:
            str: SARIF JSON log output.
        """
        from pysymex.reporting.sarif import SARIFGenerator

        issues: list[dict[str, object]] = []
        files: list[str] = []
        analysis_errors: list[str] = []
        for result in results:
            file_path = str(getattr(result, "source_file", ""))
            if file_path:
                files.append(file_path)
            degraded_passes = list(getattr(result, "degraded_passes", []))
            if degraded_passes:
                analysis_errors.append(
                    f"{getattr(result, 'function_name', 'unknown')}: "
                    f"Analysis degraded: {', '.join(degraded_passes)}"
                )
            for record in iter_verify_issue_records(result):
                issue: dict[str, object] = {
                    "type": record.issue_type,
                    "message": record.message,
                    "file": record.source_file,
                    "line": record.line_number or 1,
                    "function_name": record.function_name,
                }
                evidence = contract_evidence_for_issue(record.issue)
                if evidence is not None:
                    issue["properties"] = {"contractEvidence": evidence}
                issues.append(issue)

        return (
            SARIFGenerator()
            .generate(
                issues=issues,
                analyzed_files=files,
                execution_successful=not analysis_errors,
                analysis_errors=analysis_errors or None,
            )
            .to_json()
        )
