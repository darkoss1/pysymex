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

"""SARIF tool, run, and log types."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from pysymex._internal.reporting.sarif.types.base import SARIF_SCHEMA, SARIF_VERSION
from pysymex._internal.reporting.sarif.types.results import ReportingDescriptor, SARIFResult


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
                },
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
