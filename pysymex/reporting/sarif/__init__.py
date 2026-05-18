# pysymex: Python Symbolic Execution & Formal Verification
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

"""SARIF report generation package."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .core import (
        SARIFGenerator as SARIFGenerator,
        generate_sarif as generate_sarif,
        issue_to_sarif_result as issue_to_sarif_result,
        severity_to_level as severity_to_level,
        vuln_type_to_rule_id as vuln_type_to_rule_id,
        vulnerability_to_sarif_result as vulnerability_to_sarif_result,
        SECURITY_RULES as SECURITY_RULES,
        severity_to_security_severity as severity_to_security_severity,
    )
    from .types import (
        CodeFlow as CodeFlow,
        LogicalLocation as LogicalLocation,
        PhysicalLocation as PhysicalLocation,
        ReportingDescriptor as ReportingDescriptor,
        Run as Run,
        SARIFLog as SARIFLog,
        SARIFResult as SARIFResult,
        Severity as Severity,
        ToolDriver as ToolDriver,
        VulnerabilityReport as VulnerabilityReport,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "SARIFGenerator": (".core", "SARIFGenerator"),
    "generate_sarif": (".core", "generate_sarif"),
    "issue_to_sarif_result": (".core", "issue_to_sarif_result"),
    "vulnerability_to_sarif_result": (".core", "vulnerability_to_sarif_result"),
    "severity_to_level": (".core", "severity_to_level"),
    "severity_to_security_severity": (".core", "severity_to_security_severity"),
    "vuln_type_to_rule_id": (".core", "vuln_type_to_rule_id"),
    "SECURITY_RULES": (".core", "SECURITY_RULES"),
    "SARIFLog": (".types", "SARIFLog"),
    "SARIFResult": (".types", "SARIFResult"),
    "Run": (".types", "Run"),
    "ToolDriver": (".types", "ToolDriver"),
    "ReportingDescriptor": (".types", "ReportingDescriptor"),
    "PhysicalLocation": (".types", "PhysicalLocation"),
    "LogicalLocation": (".types", "LogicalLocation"),
    "CodeFlow": (".types", "CodeFlow"),
    "Severity": (".types", "Severity"),
    "VulnerabilityReport": (".types", "VulnerabilityReport"),
}


def __getattr__(name: str) -> object:
    """Lazy-load SARIF reporting components."""
    if name in _EXPORTS:
        from importlib import import_module

        module_path, attr_name = _EXPORTS[name]
        module = import_module(module_path, __package__)
        return getattr(module, attr_name)

    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "SARIFGenerator",
    "generate_sarif",
    "issue_to_sarif_result",
    "vulnerability_to_sarif_result",
    "severity_to_level",
    "severity_to_security_severity",
    "vuln_type_to_rule_id",
    "SECURITY_RULES",
    "SARIFLog",
    "SARIFResult",
    "Run",
    "ToolDriver",
    "ReportingDescriptor",
    "PhysicalLocation",
    "LogicalLocation",
    "CodeFlow",
    "Severity",
    "VulnerabilityReport",
]
