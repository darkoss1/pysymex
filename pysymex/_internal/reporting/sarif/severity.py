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

"""SARIF severity mapping helpers."""

from __future__ import annotations

from pysymex._internal.reporting.sarif.types.base import SarifSeverity


def severity_to_level(severity: SarifSeverity) -> str:
    """Map the internal pysymex SARIF severity enum to standard SARIF notification levels.

    SARIF levels (error, warning, note, none) determine how the result is
    rendered in IDEs and GHAS dashboards.
    """
    mapping = {
        SarifSeverity.CRITICAL: "error",
        SarifSeverity.HIGH: "error",
        SarifSeverity.MEDIUM: "warning",
        SarifSeverity.LOW: "note",
        SarifSeverity.INFO: "none",
    }
    return mapping.get(severity, "warning")


def severity_to_security_severity(severity: SarifSeverity) -> str:
    """Convert to GitHub security severity."""
    mapping = {
        SarifSeverity.CRITICAL: "critical",
        SarifSeverity.HIGH: "high",
        SarifSeverity.MEDIUM: "medium",
        SarifSeverity.LOW: "low",
        SarifSeverity.INFO: "low",
    }
    return mapping.get(severity, "medium")
