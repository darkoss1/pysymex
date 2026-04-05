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

"""SARIF type definitions for pysymex.
SARIF (Static Analysis Results Interchange Format) is an OASIS standard
for expressing static analysis results. This module contains all dataclasses,
enums, and constants used by the SARIF generator.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path


class Severity(Enum):
    """Issue severity levels."""

    CRITICAL = auto()
    HIGH = auto()
    MEDIUM = auto()
    LOW = auto()
    INFO = auto()

    def to_sarif_level(self) -> str:
        """Convert to SARIF result level."""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(self, "warning")


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = (
    "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
)


@dataclass(frozen=True, slots=True)
class VulnerabilityReport:
    """Simple vulnerability report for SARIF output.
    This is a lightweight data class for reporting issues in SARIF format.
    """

    vuln_type: str
    message: str
    severity: Severity = Severity.MEDIUM
    file_path: str | None = None
    line_number: int | None = None
    function_name: str | None = None
    source: str | None = None
    sink: str | None = None
    taint_path: list[str] | None = None
    owasp_category: str | None = None
    cwe_id: int | None = None
    triggering_input: dict[str, object] | None = None


@dataclass(frozen=True, slots=True)
class PhysicalLocation:
    """Physical location in a file."""

    file_path: str
    start_line: int = 1
    start_column: int = 1
    end_line: int | None = None
    end_column: int | None = None

    def to_dict(self) -> dict[str, object]:
        """Convert to SARIF format."""
        region: dict[str, object] = {
            "startLine": self.start_line,
            "startColumn": self.start_column,
        }
        if self.end_line is not None:
            region["endLine"] = self.end_line
        if self.end_column is not None:
            region["endColumn"] = self.end_column
        return {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": self.file_path.replace("\\", "/"),
                    "uriBaseId": "%SRCROOT%",
                },
                "region": region,
            }
        }


@dataclass(frozen=True, slots=True)
class LogicalLocation:
    """Logical location (function, class, etc.)."""

    name: str
    kind: str = "function"
    fully_qualified_name: str | None = None

    def to_dict(self) -> dict[str, object]:
        """Convert to SARIF format."""
        result: dict[str, object] = {
            "name": self.name,
            "kind": self.kind,
        }
        if self.fully_qualified_name:
            result["fullyQualifiedName"] = self.fully_qualified_name
        return result


@dataclass(frozen=True, slots=True)
class CodeFlow:
    """Code flow showing taint propagation."""

    locations: list[PhysicalLocation] = field(default_factory=list[PhysicalLocation])
    message: str = ""

    def to_dict(self) -> dict[str, object]:
        """Convert to SARIF format."""
        thread_flow_locations: list[dict[str, object]] = []
        for i, loc in enumerate(self.locations):
            thread_flow_locations.append(
                {
                    "location": loc.to_dict(),
                    "nestingLevel": 0,
                    "executionOrder": i + 1,
                }
            )
        return {
            "threadFlows": [
                {
                    "locations": thread_flow_locations,
                }
            ],
            "message": {"text": self.message} if self.message else None,
        }


@dataclass(frozen=True, slots=True)
class SARIFResult:
    """A single SARIF result (finding)."""

    rule_id: str
    message: str
    level: str
    locations: list[PhysicalLocation] = field(default_factory=list[PhysicalLocation])
    logical_locations: list[LogicalLocation] = field(default_factory=list[LogicalLocation])
    code_flows: list[CodeFlow] = field(default_factory=list[CodeFlow])
    fixes: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    fingerprints: dict[str, str] = field(default_factory=dict[str, str])
    properties: dict[str, object] = field(default_factory=dict[str, object])

    def to_dict(self) -> dict[str, object]:
        """Convert to SARIF format."""
        result: dict[str, object] = {
            "ruleId": self.rule_id,
            "message": {"text": self.message},
            "level": self.level,
        }
        if self.locations:
            result["locations"] = [loc.to_dict() for loc in self.locations]
        if self.logical_locations:
            result["logicalLocations"] = [loc.to_dict() for loc in self.logical_locations]
        if self.code_flows:
            result["codeFlows"] = [cf.to_dict() for cf in self.code_flows]
        if self.fixes:
            result["fixes"] = self.fixes
        if self.fingerprints:
            result["fingerprints"] = self.fingerprints
        if self.properties:
            result["properties"] = self.properties
        return result


@dataclass(frozen=True, slots=True)
class ReportingDescriptor:
    """A rule descriptor for SARIF."""

    id: str
    name: str
    short_description: str
    full_description: str = ""
    help_uri: str = ""
    default_level: str = "warning"
    properties: dict[str, object] = field(default_factory=dict[str, object])

    def to_dict(self) -> dict[str, object]:
        """Convert to SARIF format."""
        result: dict[str, object] = {
            "id": self.id,
            "name": self.name,
            "shortDescription": {"text": self.short_description},
        }
        if self.full_description:
            result["fullDescription"] = {"text": self.full_description}
        if self.help_uri:
            result["helpUri"] = self.help_uri
        result["defaultConfiguration"] = {"level": self.default_level}
        if self.properties:
            result["properties"] = self.properties
        return result


@dataclass(frozen=True, slots=True)
class ToolDriver:
    """The analysis tool driver."""

    name: str = "pysymex"
    version: str = "0.3.0a0"
    information_uri: str = "https://github.com/darkoss1/pysymex"
    rules: list[ReportingDescriptor] = field(default_factory=list[ReportingDescriptor])

    def to_dict(self) -> dict[str, object]:
        """Convert to SARIF format."""
        return {
            "name": self.name,
            "version": self.version,
            "informationUri": self.information_uri,
            "rules": [r.to_dict() for r in self.rules],
        }


@dataclass(frozen=True, slots=True)
class Run:
    """A single analysis run."""

    tool: ToolDriver
    results: list[SARIFResult] = field(default_factory=list[SARIFResult])
    invocations: list[dict[str, object]] = field(default_factory=list[dict[str, object]])
    artifacts: list[dict[str, object]] = field(default_factory=list[dict[str, object]])

    def to_dict(self) -> dict[str, object]:
        """Convert to SARIF format."""
        return {
            "tool": {"driver": self.tool.to_dict()},
            "results": [r.to_dict() for r in self.results],
            "invocations": self.invocations
            or [
                {
                    "executionSuccessful": True,
                }
            ],
            "artifacts": self.artifacts,
        }


@dataclass(frozen=True, slots=True)
class SARIFLog:
    """The top-level SARIF log object."""

    version: str = SARIF_VERSION
    schema: str = SARIF_SCHEMA
    runs: list[Run] = field(default_factory=list[Run])

    def to_dict(self) -> dict[str, object]:
        """Convert to SARIF format."""
        return {
            "$schema": self.schema,
            "version": self.version,
            "runs": [r.to_dict() for r in self.runs],
        }

    def to_json(self, indent: int = 2) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    def save(self, path: str | Path) -> None:
        """Save to a file."""
        path = Path(path)
        path.write_text(self.to_json(), encoding="utf-8")


__all__ = [
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "CodeFlow",
    "LogicalLocation",
    "PhysicalLocation",
    "ReportingDescriptor",
    "Run",
    "SARIFLog",
    "SARIFResult",
    "Severity",
    "ToolDriver",
    "VulnerabilityReport",
]
