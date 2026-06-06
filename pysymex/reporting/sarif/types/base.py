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

"""Base SARIF enums and vulnerability input types."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum, auto


class Severity(Enum):
    """SARIF issue severity levels."""

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
    owasp_category: str | None = None
    cwe_id: int | None = None
    triggering_input: dict[str, object] | None = None


__all__ = ["SARIF_SCHEMA", "SARIF_VERSION", "Severity", "VulnerabilityReport"]
