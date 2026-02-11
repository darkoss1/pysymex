"""SARIF output format for PySpectre.
SARIF (Static Analysis Results Interchange Format) is an OASIS standard
for expressing static analysis results. This module generates SARIF 2.1.0
output for integration with CI/CD tools and IDEs.
Supports:
- GitHub Code Scanning
- Azure DevOps
- Visual Studio Code SARIF Viewer
- GitLab SAST
"""

from __future__ import annotations
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any


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


@dataclass
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
    triggering_input: dict[str, Any] | None = None


@dataclass
class PhysicalLocation:
    """Physical location in a file."""

    file_path: str
    start_line: int = 1
    start_column: int = 1
    end_line: int | None = None
    end_column: int | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to SARIF format."""
        region: dict[str, Any] = {
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


@dataclass
class LogicalLocation:
    """Logical location (function, class, etc.)."""

    name: str
    kind: str = "function"
    fully_qualified_name: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to SARIF format."""
        result: dict[str, Any] = {
            "name": self.name,
            "kind": self.kind,
        }
        if self.fully_qualified_name:
            result["fullyQualifiedName"] = self.fully_qualified_name
        return result


@dataclass
class CodeFlow:
    """Code flow showing taint propagation."""

    locations: list[PhysicalLocation] = field(default_factory=list)
    message: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Convert to SARIF format."""
        thread_flow_locations = []
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


@dataclass
class SARIFResult:
    """A single SARIF result (finding)."""

    rule_id: str
    message: str
    level: str
    locations: list[PhysicalLocation] = field(default_factory=list)
    logical_locations: list[LogicalLocation] = field(default_factory=list)
    code_flows: list[CodeFlow] = field(default_factory=list)
    fixes: list[dict[str, Any]] = field(default_factory=list)
    fingerprints: dict[str, str] = field(default_factory=dict)
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to SARIF format."""
        result: dict[str, Any] = {
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


@dataclass
class ReportingDescriptor:
    """A rule descriptor for SARIF."""

    id: str
    name: str
    short_description: str
    full_description: str = ""
    help_uri: str = ""
    default_level: str = "warning"
    properties: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to SARIF format."""
        result: dict[str, Any] = {
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


@dataclass
class ToolDriver:
    """The analysis tool driver."""

    name: str = "PySpectre"
    version: str = "0.3.0a0"
    information_uri: str = "https://github.com/darkoss1/pyspecter"
    rules: list[ReportingDescriptor] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to SARIF format."""
        return {
            "name": self.name,
            "version": self.version,
            "informationUri": self.information_uri,
            "rules": [r.to_dict() for r in self.rules],
        }


@dataclass
class Run:
    """A single analysis run."""

    tool: ToolDriver
    results: list[SARIFResult] = field(default_factory=list)
    invocations: list[dict[str, Any]] = field(default_factory=list)
    artifacts: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
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


@dataclass
class SARIFLog:
    """The top-level SARIF log object."""

    version: str = SARIF_VERSION
    schema: str = SARIF_SCHEMA
    runs: list[Run] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
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


def severity_to_level(severity: Severity) -> str:
    """Convert PySpectre severity to SARIF level."""
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


SECURITY_RULES: dict[str, ReportingDescriptor] = {
    "SVM001": ReportingDescriptor(
        id="SVM001",
        name="CommandInjection",
        short_description="Command Injection vulnerability detected",
        full_description=(
            "User-controlled input is passed to a command execution function "
            "without proper sanitization, allowing attackers to execute arbitrary commands."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/78.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "injection", "cwe-78"],
        },
    ),
    "SVM002": ReportingDescriptor(
        id="SVM002",
        name="SQLInjection",
        short_description="SQL Injection vulnerability detected",
        full_description=(
            "User-controlled input is concatenated into SQL queries "
            "without proper parameterization, allowing SQL injection attacks."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/89.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "injection", "cwe-89"],
        },
    ),
    "SVM003": ReportingDescriptor(
        id="SVM003",
        name="PathTraversal",
        short_description="Path Traversal vulnerability detected",
        full_description=(
            "User-controlled input is used in file path operations "
            "without proper validation, allowing access to arbitrary files."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/22.html",
        default_level="error",
        properties={
            "security-severity": "7.5",
            "tags": ["security", "path-traversal", "cwe-22"],
        },
    ),
    "SVM004": ReportingDescriptor(
        id="SVM004",
        name="SSRF",
        short_description="Server-Side Request Forgery detected",
        full_description=(
            "User-controlled input is used to construct URLs for server-side requests, "
            "potentially allowing access to internal resources."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/918.html",
        default_level="error",
        properties={
            "security-severity": "9.0",
            "tags": ["security", "ssrf", "cwe-918"],
        },
    ),
    "SVM005": ReportingDescriptor(
        id="SVM005",
        name="InsecureDeserialization",
        short_description="Insecure Deserialization detected",
        full_description=(
            "Untrusted data is deserialized using unsafe methods, "
            "potentially allowing remote code execution."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/502.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "deserialization", "cwe-502"],
        },
    ),
    "SVM006": ReportingDescriptor(
        id="SVM006",
        name="TemplateInjection",
        short_description="Server-Side Template Injection detected",
        full_description=(
            "User-controlled input is passed to a template engine, "
            "potentially allowing code execution."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/97.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "injection", "cwe-97"],
        },
    ),
    "SVM007": ReportingDescriptor(
        id="SVM007",
        name="HardcodedSecret",
        short_description="Hardcoded secret detected",
        full_description=(
            "A secret or credential appears to be hardcoded in the source code, "
            "which could lead to unauthorized access if the code is exposed."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/798.html",
        default_level="warning",
        properties={
            "security-severity": "7.5",
            "tags": ["security", "secrets", "cwe-798"],
        },
    ),
    "SVM008": ReportingDescriptor(
        id="SVM008",
        name="WeakCryptography",
        short_description="Weak cryptographic algorithm detected",
        full_description=(
            "A weak or deprecated cryptographic algorithm is being used, "
            "which may not provide adequate security."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/327.html",
        default_level="warning",
        properties={
            "security-severity": "5.9",
            "tags": ["security", "crypto", "cwe-327"],
        },
    ),
    "SVM009": ReportingDescriptor(
        id="SVM009",
        name="CodeInjection",
        short_description="Code Injection vulnerability detected",
        full_description=(
            "User-controlled input is passed to code execution functions like eval(), "
            "allowing arbitrary code execution."
        ),
        help_uri="https://cwe.mitre.org/data/definitions/94.html",
        default_level="error",
        properties={
            "security-severity": "9.8",
            "tags": ["security", "injection", "cwe-94"],
        },
    ),
    "SVM010": ReportingDescriptor(
        id="SVM010",
        name="DivisionByZero",
        short_description="Potential division by zero",
        full_description="A division operation may fail due to a zero divisor.",
        help_uri="https://cwe.mitre.org/data/definitions/369.html",
        default_level="warning",
        properties={
            "tags": ["reliability", "cwe-369"],
        },
    ),
    "SVM011": ReportingDescriptor(
        id="SVM011",
        name="AssertionFailure",
        short_description="Assertion may fail",
        full_description="An assertion condition may be false under certain inputs.",
        default_level="warning",
        properties={
            "tags": ["reliability"],
        },
    ),
    "SVM012": ReportingDescriptor(
        id="SVM012",
        name="IndexError",
        short_description="Potential index out of bounds",
        full_description="An array or list access may be out of bounds.",
        help_uri="https://cwe.mitre.org/data/definitions/129.html",
        default_level="warning",
        properties={
            "tags": ["reliability", "cwe-129"],
        },
    ),
    "SVM013": ReportingDescriptor(
        id="SVM013",
        name="UnusedVariable",
        short_description="Unused variable detected",
        full_description="A variable is assigned a value but never used.",
        default_level="note",
        properties={
            "tags": ["maintainability"],
        },
    ),
    "SVM014": ReportingDescriptor(
        id="SVM014",
        name="KeyError",
        short_description="Potential KeyError",
        full_description="A dictionary access may fail due to a missing key.",
        default_level="warning",
        properties={
            "tags": ["reliability"],
        },
    ),
}


def vuln_type_to_rule_id(vuln_type: str) -> str:
    """Map vulnerability type to SARIF rule ID."""
    v = str(vuln_type).lower().replace(" ", "_")
    mapping = {
        "command_injection": "SVM001",
        "sql_injection": "SVM002",
        "path_traversal": "SVM003",
        "potential_path_traversal": "SVM003",
        "server_side_request_forgery_(ssrf)": "SVM004",
        "insecure_deserialization": "SVM005",
        "potentially_unsafe_deserialization": "SVM005",
        "server_side_template_injection": "SVM006",
        "hardcoded_secret": "SVM007",
        "weak_cryptography": "SVM008",
        "code_injection": "SVM009",
        "division_by_zero": "SVM010",
        "assertion_error": "SVM011",
        "index_error": "SVM012",
        "unused_variable": "SVM013",
        "key_error": "SVM014",
    }
    return mapping.get(v, "SVM999")


def vulnerability_to_sarif_result(vuln: VulnerabilityReport) -> SARIFResult:
    """Convert a VulnerabilityReport to a SARIF result."""
    rule_id = vuln_type_to_rule_id(vuln.vuln_type)
    level = severity_to_level(vuln.severity)
    locations = []
    if vuln.file_path and vuln.line_number:
        locations.append(
            PhysicalLocation(
                file_path=vuln.file_path,
                start_line=vuln.line_number,
            )
        )
    logical_locations = []
    if vuln.function_name:
        logical_locations.append(
            LogicalLocation(
                name=vuln.function_name,
                kind="function",
            )
        )
    code_flows = []
    if vuln.taint_path:
        flow_locations = []
        for step in vuln.taint_path:
            if ":" in step:
                parts = step.rsplit(":", 1)
                try:
                    line = int(parts[1])
                    flow_locations.append(
                        PhysicalLocation(
                            file_path=parts[0],
                            start_line=line,
                        )
                    )
                except ValueError:
                    pass
        if flow_locations:
            code_flows.append(
                CodeFlow(
                    locations=flow_locations,
                    message=f"Taint flows from {vuln.source} to {vuln.sink}",
                )
            )
    properties: dict[str, Any] = {}
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


def issue_to_sarif_result(issue: dict[str, Any]) -> SARIFResult:
    """Convert an issue dictionary to a SARIF result."""
    issue_type = issue.get("type") or issue.get("kind") or "unknown"
    rule_id = vuln_type_to_rule_id(issue_type)
    level = "warning"
    if "error" in issue_type.lower():
        level = "error"
    locations = []
    if "line" in issue:
        line = issue.get("line")
        try:
            if isinstance(line, bool):
                line = 1
            line_int = int(line) if line is not None else 1
            if line_int < 1:
                line_int = 1
        except (ValueError, TypeError):
            line_int = 1

        locations.append(
            PhysicalLocation(
                file_path=issue.get("file", "unknown"),
                start_line=line_int,
            )
        )
    message = issue.get("message", issue.get("description", f"Issue: {issue_type}"))
    properties: dict[str, Any] = {}
    if "triggering_input" in issue:
        properties["triggeringInput"] = issue["triggering_input"]
    return SARIFResult(
        rule_id=rule_id,
        message=message,
        level=level,
        locations=locations,
        properties=properties,
    )


class SARIFGenerator:
    """Generates SARIF reports from PySpectre analysis results."""

    def __init__(
        self,
        tool_name: str = "PySpectre",
        tool_version: str = "1.0.0",
    ):
        self.tool_name = tool_name
        self.tool_version = tool_version

    def generate(
        self,
        vulnerabilities: list[VulnerabilityReport] | None = None,
        issues: list[dict[str, Any]] | None = None,
        analyzed_files: list[str] | None = None,
    ) -> SARIFLog:
        """Generate a SARIF log from analysis results."""
        used_rule_ids: set[str] = set()
        results: list[SARIFResult] = []
        if vulnerabilities:
            for vuln in vulnerabilities:
                result = vulnerability_to_sarif_result(vuln)
                results.append(result)
                used_rule_ids.add(result.rule_id)
        if issues:
            for issue in issues:
                result = issue_to_sarif_result(issue)
                results.append(result)
                used_rule_ids.add(result.rule_id)
        rules = [
            SECURITY_RULES.get(
                rule_id,
                ReportingDescriptor(
                    id=rule_id,
                    name=rule_id,
                    short_description=f"Issue {rule_id}",
                ),
            )
            for rule_id in sorted(used_rule_ids)
        ]
        artifacts = []
        if analyzed_files:
            for file_path in analyzed_files:
                artifacts.append(
                    {
                        "location": {
                            "uri": file_path.replace("\\", "/"),
                            "uriBaseId": "%SRCROOT%",
                        },
                    }
                )
        invocations = [
            {
                "executionSuccessful": True,
                "endTimeUtc": datetime.now(UTC).isoformat(),
            }
        ]
        tool = ToolDriver(
            name=self.tool_name,
            version=self.tool_version,
            rules=rules,
        )
        run = Run(
            tool=tool,
            results=results,
            invocations=invocations,
            artifacts=artifacts,
        )
        return SARIFLog(runs=[run])

    def generate_from_result(self, analysis_result: Any) -> SARIFLog:
        """Generate SARIF from an AnalysisResult object."""
        issues = []
        files = []
        if hasattr(analysis_result, "issues"):
            issues = analysis_result.issues
        elif hasattr(analysis_result, "findings"):
            issues = analysis_result.findings
        if hasattr(analysis_result, "file_path"):
            files = [str(analysis_result.file_path)]
        elif hasattr(analysis_result, "analyzed_files"):
            files = [str(f) for f in analysis_result.analyzed_files]
        return self.generate(issues=issues, analyzed_files=files)


def generate_sarif(
    vulnerabilities: list[VulnerabilityReport] | None = None,
    issues: list[dict[str, Any]] | None = None,
    analyzed_files: list[str] | None = None,
    output_path: str | Path | None = None,
) -> SARIFLog:
    """Convenience function to generate SARIF output.
    Args:
        vulnerabilities: List of VulnerabilityReport objects
        issues: List of issue dictionaries
        analyzed_files: List of analyzed file paths
        output_path: Optional path to save the SARIF file
    Returns:
        The generated SARIFLog object
    """
    generator = SARIFGenerator()
    sarif_log = generator.generate(
        vulnerabilities=vulnerabilities,
        issues=issues,
        analyzed_files=analyzed_files,
    )
    if output_path:
        sarif_log.save(output_path)
    return sarif_log


__all__ = [
    "SARIF_VERSION",
    "SARIF_SCHEMA",
    "PhysicalLocation",
    "LogicalLocation",
    "CodeFlow",
    "SARIFResult",
    "ReportingDescriptor",
    "ToolDriver",
    "Run",
    "SARIFLog",
    "SARIFGenerator",
    "generate_sarif",
    "SECURITY_RULES",
    "severity_to_level",
    "vulnerability_to_sarif_result",
    "issue_to_sarif_result",
]
