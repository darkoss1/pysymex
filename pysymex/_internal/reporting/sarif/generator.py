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
from typing import TYPE_CHECKING, cast

from pysymex._internal.config.defaults import VERSION
from pysymex._internal.logging.root import get_logger
from pysymex._internal.reporting.sarif.results import (
    issue_to_sarif_result,
    vulnerability_to_sarif_result,
)
from pysymex._internal.reporting.sarif.rules.catalog import SECURITY_RULES
from pysymex._internal.reporting.sarif.types.log import Run, SARIFLog, ToolDriver
from pysymex._internal.reporting.sarif.types.results import ReportingDescriptor, SARIFResult

if TYPE_CHECKING:
    from pysymex._internal.execution.results.result import ExecutionResult
    from pysymex._internal.reporting.sarif.types.base import VulnerabilityReport

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
        invocation_properties: dict[str, object] | None = None,
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
                    },
                )
        invocations: list[dict[str, object]] = [
            {
                "executionSuccessful": execution_successful,
                "endTimeUtc": datetime.now(UTC).isoformat(),
            },
        ]
        properties: dict[str, object] = dict(invocation_properties or {})
        if analysis_errors:
            properties["analysisErrors"] = list(analysis_errors)
        if properties:
            invocations[0]["properties"] = properties
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

    def generate_execution_result(self, result: ExecutionResult) -> SARIFLog:
        """Generate a SARIF log for one symbolic execution result."""
        issues = [_execution_issue_to_sarif_input(issue) for issue in result.issues]
        analyzed_files = [result.source_file] if result.source_file else None
        invocation_properties: dict[str, object] = {
            "pathsExplored": result.paths_explored,
            "pathsCompleted": result.paths_completed,
            "pathsPruned": result.paths_pruned,
            "coverageInstructions": len(result.coverage),
            "totalTimeSeconds": round(result.total_time_seconds, 3),
        }
        if result.degraded_passes:
            invocation_properties["degradedPasses"] = list(result.degraded_passes)

        return self.generate(
            issues=issues,
            analyzed_files=analyzed_files,
            execution_successful=not result.degraded_passes,
            invocation_properties=invocation_properties,
        )


def _execution_issue_to_sarif_input(issue: object) -> dict[str, object]:
    """Convert an execution Issue-like object to the reporting SARIF input schema."""
    issue_dict: dict[str, object] = {}
    to_dict = getattr(issue, "to_dict", None)
    if callable(to_dict):
        raw = to_dict()
        if isinstance(raw, dict):
            for key, value in cast("dict[object, object]", raw).items():
                issue_dict[str(key)] = value

    if not issue_dict:
        kind = getattr(issue, "kind", None)
        kind_name = getattr(kind, "name", kind)
        issue_dict["kind"] = str(kind_name or "UNKNOWN")
        issue_dict["message"] = str(getattr(issue, "message", "Issue"))
        line_number = getattr(issue, "line_number", None)
        if line_number is not None:
            issue_dict["line_number"] = line_number
        filename = getattr(issue, "filename", None)
        if filename is not None:
            issue_dict["filename"] = filename

    issue_dict.setdefault("type", issue_dict.get("kind", "UNKNOWN"))
    return issue_dict
