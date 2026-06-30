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

"""SARIF result and rule descriptor types."""

from __future__ import annotations

from dataclasses import dataclass, field

from pysymex._internal.reporting.sarif.types.locations import (
    CodeFlow,
    LogicalLocation,
    PhysicalLocation,
)


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
