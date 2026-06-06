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

"""SARIF log generation orchestration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from pysymex.config import VERSION
from pysymex.logger import get_logger
from pysymex.reporting.sarif.types import (
    ReportingDescriptor,
    Run,
    SARIFLog,
    SARIFResult,
    ToolDriver,
    VulnerabilityReport,
)
from pysymex.reporting.sarif.results import issue_to_sarif_result, vulnerability_to_sarif_result
from pysymex.reporting.sarif.rules import SECURITY_RULES

logger = get_logger(__name__)


class SARIFGenerator:
    """Orchestrator for transforming pysymex internal results into SARIF 2.1.0 JSON.

    **Mapping Strategy:**
    Transforms internal engine artifacts into the standard Static Analysis
    Results Interchange Format (SARIF).
    - **Vulnerabilities**: Mapped to SARIF `result` objects with associated rule IDs.
    - **Path Constraints**: Encoded in the `codeFlows` property to allow
      step-by-step path reproduction in SARIF viewers.

    The generated output is compatible with GitHub Advanced Security (GHAS)
    code scanning and other SARIF-aware tools.
    """

    def __init__(
        self,
        tool_name: str = "pysymex",
        tool_version: str = VERSION,
    ) -> None:
        """Initialize the SARIF report generator.

        Args:
            tool_name: The identifier of the tool producing the report. Defaults to "pysymex".
            tool_version: The version string of the tool. Defaults to the current
                project version.
        """
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(
        self,
        vulnerabilities: list[VulnerabilityReport] | None = None,
        issues: list[dict[str, object]] | None = None,
        analyzed_files: list[str] | None = None,
        execution_successful: bool = True,
        analysis_errors: list[str] | None = None,
    ) -> SARIFLog:
        """Generate a SARIF log from analysis results."""
        logger.verbose(
            "Generating SARIF vulnerabilities=%d issues=%d files=%d",
            len(vulnerabilities or ()),
            len(issues or ()),
            len(analyzed_files or ()),
        )
        used_rule_ids: set[str] = set()
        results: list[SARIFResult] = []
        if vulnerabilities:
            for vuln in vulnerabilities:
                result = vulnerability_to_sarif_result(vuln)
                results.append(result)
                used_rule_ids.add(result.rule_id)
        if issues:
            for issue in issues:
                result = issue_to_sarif_result(issue)
                results.append(result)
                used_rule_ids.add(result.rule_id)
        rules: list[ReportingDescriptor] = [
            SECURITY_RULES.get(
                rule_id,
                ReportingDescriptor(
                    id=rule_id,
                    name=rule_id,
                    short_description=f"Issue {rule_id}",
                ),
            )
            for rule_id in sorted(used_rule_ids)
        ]
        artifacts: list[dict[str, object]] = []
        if analyzed_files:
            for file_path in analyzed_files:
                artifacts.append(
                    {
                        "location": {
                            "uri": file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                    }
                )
        invocations: list[dict[str, object]] = [
            {
                "executionSuccessful": execution_successful,
                "endTimeUtc": datetime.now(UTC).isoformat(),
            }
        ]
        if analysis_errors:
            invocations[0]["properties"] = {"analysisErrors": list(analysis_errors)}
        tool = ToolDriver(
            name=self.tool_name,
            version=self.tool_version,
            rules=rules,
        )
        run = Run(
            tool=tool,
            results=results,
            invocations=invocations,
            artifacts=artifacts,
        )
        return SARIFLog(runs=[run])

    def generate_from_result(self, analysis_result: object) -> SARIFLog:
        """Generate SARIF from an AnalysisResult object."""
        issues: list[dict[str, object]] = []
        files: list[str] = []

        issues_val = getattr(analysis_result, "issues", None)
        if issues_val is not None:
            issues = cast("list[dict[str, object]]", issues_val)
        else:
            findings_val = getattr(analysis_result, "findings", None)
            if findings_val is not None:
                issues = cast("list[dict[str, object]]", findings_val)

        file_path_val = getattr(analysis_result, "file_path", None)
        if file_path_val is not None:
            files = [str(file_path_val)]
        else:
            analyzed_files_val = getattr(analysis_result, "analyzed_files", None)
            if analyzed_files_val is not None:
                files = [str(f) for f in cast("list[object]", analyzed_files_val)]

        raw_error = getattr(analysis_result, "error", None)
        analysis_errors = [str(raw_error)] if raw_error else None
        return self.generate(
            issues=issues,
            analyzed_files=files,
            execution_successful=not analysis_errors,
            analysis_errors=analysis_errors,
        )


def generate_sarif(
    vulnerabilities: list[VulnerabilityReport] | None = None,
    issues: list[dict[str, object]] | None = None,
    analyzed_files: list[str] | None = None,
    output_path: str | Path | None = None,
    execution_successful: bool = True,
    analysis_errors: list[str] | None = None,
) -> SARIFLog:
    """Convenience function to generate SARIF output.
    Args:
        vulnerabilities: List of VulnerabilityReport objects
        issues: List of issue dictionaries
        analyzed_files: List of analyzed file paths
        output_path: Optional path to save the SARIF file
        execution_successful: Whether analysis completed successfully
        analysis_errors: Diagnostics explaining an unsuccessful analysis
    Returns:
        The generated SARIFLog object
    """
    generator = SARIFGenerator()
    sarif_log = generator.generate(
        vulnerabilities=vulnerabilities,
        issues=issues,
        analyzed_files=analyzed_files,
        execution_successful=execution_successful,
        analysis_errors=analysis_errors,
    )
    if output_path:
        sarif_log.save(output_path)
        logger.info("Saved SARIF report: %s", output_path)
    return sarif_log


__all__ = ["SARIFGenerator", "generate_sarif"]
