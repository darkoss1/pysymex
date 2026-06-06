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

from pysymex.reporting.sarif.types import Severity


def severity_to_level(severity: Severity) -> str:
    """Map the internal pysymex SARIF severity enum to standard SARIF notification levels.

    SARIF levels (error, warning, note, none) determine how the result is
    rendered in IDEs and GHAS dashboards.
    """
    mapping = {
        Severity.CRITICAL: "error",
        Severity.HIGH: "error",
        Severity.MEDIUM: "warning",
        Severity.LOW: "note",
        Severity.INFO: "none",
    }
    return mapping.get(severity, "warning")


def severity_to_security_severity(severity: Severity) -> str:
    """Convert to GitHub security severity."""
    mapping = {
        Severity.CRITICAL: "critical",
        Severity.HIGH: "high",
        Severity.MEDIUM: "medium",
        Severity.LOW: "low",
        Severity.INFO: "low",
    }
    return mapping.get(severity, "medium")


__all__ = ["severity_to_level", "severity_to_security_severity"]
