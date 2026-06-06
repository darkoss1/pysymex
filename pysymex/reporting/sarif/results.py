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

"""SARIF result conversion helpers."""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from pysymex.reporting.sarif.types import (
    CodeFlow,
    LogicalLocation,
    PhysicalLocation,
    SARIFResult,
    VulnerabilityReport,
)
from pysymex.reporting.sarif.rules import vuln_type_to_rule_id
from pysymex.reporting.sarif.severity import severity_to_level, severity_to_security_severity


def _issue_level(issue: dict[str, object], issue_type: str) -> str:
    """Map scanner issue severity fields to SARIF levels."""
    raw_severity = issue.get("severity")
    severity_name = getattr(raw_severity, "name", raw_severity)
    if isinstance(severity_name, str):
        normalized = severity_name.upper().replace("-", "_").replace(" ", "_")
        if normalized in {"CRITICAL", "HIGH", "ERROR", "FATAL"}:
            return "error"
        if normalized in {"LOW", "INFO", "INFORMATIONAL", "NOTE", "HINT"}:
            return "note"
        if normalized in {"MEDIUM", "WARNING", "WARN"}:
            return "warning"

    if "error" in issue_type.lower():
        return "error"
    return "warning"


def vulnerability_to_sarif_result(vuln: VulnerabilityReport) -> SARIFResult:
    """Convert a VulnerabilityReport to a SARIF result."""
    rule_id = vuln_type_to_rule_id(vuln.vuln_type)
    level = severity_to_level(vuln.severity)
    locations: list[PhysicalLocation] = []
    if vuln.file_path and vuln.line_number:
        locations.append(
            PhysicalLocation(
                file_path=vuln.file_path,
                start_line=vuln.line_number,
            )
        )
    logical_locations: list[LogicalLocation] = []
    if vuln.function_name:
        logical_locations.append(
            LogicalLocation(
                name=vuln.function_name,
                kind="function",
            )
        )
    code_flows: list[CodeFlow] = []
    properties: dict[str, object] = {}
    if vuln.owasp_category:
        properties["owasp"] = vuln.owasp_category
    if vuln.triggering_input:
        properties["triggeringInput"] = vuln.triggering_input
    properties["security-severity"] = severity_to_security_severity(vuln.severity)
    return SARIFResult(
        rule_id=rule_id,
        message=vuln.message,
        level=level,
        locations=locations,
        logical_locations=logical_locations,
        code_flows=code_flows,
        properties=properties,
    )


def issue_to_sarif_result(issue: dict[str, object]) -> SARIFResult:
    """Convert an issue dictionary to a SARIF result."""
    raw_type = issue.get("type") or issue.get("kind") or "unknown"
    issue_type = str(raw_type)
    rule_id = vuln_type_to_rule_id(issue_type)
    level = _issue_level(issue, issue_type)
    locations: list[PhysicalLocation] = []
    if "line" in issue or "line_number" in issue:
        line = issue.get("line", issue.get("line_number"))
        try:
            if isinstance(line, bool):
                line_val = 1
            elif isinstance(line, (int, str)):
                line_val = int(line)
            else:
                line_val = 1

            if line_val < 1:
                line_val = 1
            line_int = line_val
        except (ValueError, TypeError):
            line_int = 1

        locations.append(
            PhysicalLocation(
                file_path=str(issue.get("file") or issue.get("filename") or "unknown"),
                start_line=line_int,
            )
        )
    raw_message = issue.get("message", issue.get("description", f"Issue: {issue_type}"))
    message = str(raw_message)
    properties: dict[str, object] = {}
    raw_properties = issue.get("properties")
    if isinstance(raw_properties, Mapping):
        issue_properties = cast("Mapping[object, object]", raw_properties)
        properties.update({str(key): value for key, value in issue_properties.items()})
    if "triggering_input" in issue:
        properties["triggeringInput"] = issue["triggering_input"]
    return SARIFResult(
        rule_id=rule_id,
        message=message,
        level=level,
        locations=locations,
        properties=properties,
    )


__all__ = ["issue_to_sarif_result", "vulnerability_to_sarif_result"]
