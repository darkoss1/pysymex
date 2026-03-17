"""Tests for SARIF output (reporting/sarif_core.py + sarif_types.py)."""
from __future__ import annotations
import pytest
from pysymex.reporting.sarif_types import (
    Severity,
    VulnerabilityReport,
    PhysicalLocation,
    LogicalLocation,
    CodeFlow,
    SARIFResult,
    ReportingDescriptor,
    ToolDriver,
    Run,
    SARIFLog,
)
from pysymex.reporting.sarif_core import (
    severity_to_level,
    severity_to_security_severity,
    vuln_type_to_rule_id,
    SARIFGenerator,
    generate_sarif,
)


# -- Types --

class TestSeverity:
    def test_enum_exists(self):
        assert Severity is not None
        assert len(Severity) >= 1

    def test_has_critical(self):
        names = [m.name for m in Severity]
        assert any(n.upper() in ("CRITICAL", "HIGH", "ERROR") for n in names)


class TestVulnerabilityReport:
    def test_creation(self):
        members = list(Severity)
        vr = VulnerabilityReport(
            vuln_type="sql_injection",
            severity=members[0],
            message="test",
            file_path="test.py",
            line_number=1,
        )
        assert vr.vuln_type == "sql_injection"


class TestPhysicalLocation:
    def test_creation(self):
        loc = PhysicalLocation(file_path="test.py", start_line=1)
        assert loc.file_path == "test.py"


class TestLogicalLocation:
    def test_creation(self):
        loc = LogicalLocation(name="foo")
        assert loc.name == "foo"


class TestSARIFResult:
    def test_creation(self):
        r = SARIFResult(rule_id="TEST001", message="test", level="error")
        assert r.rule_id == "TEST001"


class TestReportingDescriptor:
    def test_creation(self):
        rd = ReportingDescriptor(id="TEST001", name="test_rule", short_description="A test rule")
        assert rd.id == "TEST001"


class TestSARIFLog:
    def test_creation(self):
        log = SARIFLog()
        assert log is not None


# -- Core functions --

class TestSeverityToLevel:
    def test_callable(self):
        assert callable(severity_to_level)

    def test_returns_string(self):
        members = list(Severity)
        result = severity_to_level(members[0])
        assert isinstance(result, str)


class TestSeverityToSecuritySeverity:
    def test_callable(self):
        assert callable(severity_to_security_severity)

    def test_returns_string(self):
        members = list(Severity)
        result = severity_to_security_severity(members[0])
        assert isinstance(result, str)


class TestVulnTypeToRuleId:
    def test_callable(self):
        assert callable(vuln_type_to_rule_id)

    def test_known_type(self):
        result = vuln_type_to_rule_id("sql_injection")
        assert isinstance(result, str)
        assert len(result) > 0

    def test_unknown_type(self):
        result = vuln_type_to_rule_id("unknown_xyz")
        assert isinstance(result, str)


class TestSARIFGenerator:
    def test_creation(self):
        gen = SARIFGenerator()
        assert gen is not None

    def test_has_generate(self):
        assert (hasattr(SARIFGenerator, 'generate') or
                hasattr(SARIFGenerator, 'to_sarif'))


class TestGenerateSarif:
    def test_callable(self):
        assert callable(generate_sarif)
