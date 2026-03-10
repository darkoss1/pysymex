"""SARIF output format for PySyMex — hub re-export module.
SARIF (Static Analysis Results Interchange Format) is an OASIS standard
for expressing static analysis results. This module re-exports all public
symbols from sarif_types and sarif_core for backward compatibility.
"""

from pysymex.reporting.sarif_core import SECURITY_RULES as SECURITY_RULES
from pysymex.reporting.sarif_core import SARIFGenerator as SARIFGenerator
from pysymex.reporting.sarif_core import generate_sarif as generate_sarif
from pysymex.reporting.sarif_core import (
    issue_to_sarif_result as issue_to_sarif_result,
)
from pysymex.reporting.sarif_core import severity_to_level as severity_to_level
from pysymex.reporting.sarif_core import (
    severity_to_security_severity as severity_to_security_severity,
)
from pysymex.reporting.sarif_core import vuln_type_to_rule_id as vuln_type_to_rule_id
from pysymex.reporting.sarif_core import (
    vulnerability_to_sarif_result as vulnerability_to_sarif_result,
)
from pysymex.reporting.sarif_types import SARIF_SCHEMA as SARIF_SCHEMA
from pysymex.reporting.sarif_types import SARIF_VERSION as SARIF_VERSION
from pysymex.reporting.sarif_types import CodeFlow as CodeFlow
from pysymex.reporting.sarif_types import LogicalLocation as LogicalLocation
from pysymex.reporting.sarif_types import PhysicalLocation as PhysicalLocation
from pysymex.reporting.sarif_types import ReportingDescriptor as ReportingDescriptor
from pysymex.reporting.sarif_types import Run as Run
from pysymex.reporting.sarif_types import SARIFLog as SARIFLog
from pysymex.reporting.sarif_types import SARIFResult as SARIFResult
from pysymex.reporting.sarif_types import Severity as Severity
from pysymex.reporting.sarif_types import ToolDriver as ToolDriver
from pysymex.reporting.sarif_types import VulnerabilityReport as VulnerabilityReport

__all__ = [
    "SARIF_SCHEMA",
    "SARIF_VERSION",
    "SECURITY_RULES",
    "CodeFlow",
    "LogicalLocation",
    "PhysicalLocation",
    "ReportingDescriptor",
    "Run",
    "SARIFGenerator",
    "SARIFLog",
    "SARIFResult",
    "Severity",
    "ToolDriver",
    "VulnerabilityReport",
    "generate_sarif",
    "issue_to_sarif_result",
    "severity_to_level",
    "severity_to_security_severity",
    "vuln_type_to_rule_id",
    "vulnerability_to_sarif_result",
]
