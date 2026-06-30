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

"""SARIF location and code-flow types."""

from __future__ import annotations

from dataclasses import dataclass, field


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
            },
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
    """Code flow showing execution path."""

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
                },
            )
        return {
            "threadFlows": [
                {
                    "locations": thread_flow_locations,
                },
            ],
            "message": {"text": self.message} if self.message else None,
        }
