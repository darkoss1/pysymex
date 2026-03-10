"""Tests for SARIF output format."""

import json

from pysymex.reporting.sarif import (
    SARIF_SCHEMA,
    SARIF_VERSION,
    SECURITY_RULES,
    CodeFlow,
    LogicalLocation,
    PhysicalLocation,
    ReportingDescriptor,
    Run,
    SARIFGenerator,
    SARIFLog,
    SARIFResult,
    Severity,
    ToolDriver,
    VulnerabilityReport,
    generate_sarif,
    issue_to_sarif_result,
    severity_to_level,
    vulnerability_to_sarif_result,
)

# =============================================================================
# Constants Tests
# =============================================================================


class TestConstants:
    """Tests for SARIF constants."""

    def test_sarif_version(self):
        assert SARIF_VERSION == "2.1.0"

    def test_sarif_schema(self):
        assert "sarif-schema-2.1.0" in SARIF_SCHEMA


# =============================================================================
# PhysicalLocation Tests
# =============================================================================


class TestPhysicalLocation:
    """Tests for PhysicalLocation."""

    def test_create_location(self):
        loc = PhysicalLocation(
            file_path="src/app.py",
            start_line=10,
            start_column=5,
        )

        assert loc.file_path == "src/app.py"
        assert loc.start_line == 10
        assert loc.start_column == 5

    def test_to_dict(self):
        loc = PhysicalLocation(
            file_path="src/app.py",
            start_line=10,
            end_line=15,
        )

        d = loc.to_dict()

        assert "physicalLocation" in d
        assert d["physicalLocation"]["artifactLocation"]["uri"] == "src/app.py"
        assert d["physicalLocation"]["region"]["startLine"] == 10
        assert d["physicalLocation"]["region"]["endLine"] == 15

    def test_path_normalization(self):
        loc = PhysicalLocation(file_path="src\\app.py", start_line=1)
        d = loc.to_dict()

        # Backslashes should be converted to forward slashes
        assert "\\" not in d["physicalLocation"]["artifactLocation"]["uri"]


# =============================================================================
# LogicalLocation Tests
# =============================================================================


class TestLogicalLocation:
    """Tests for LogicalLocation."""

    def test_create_location(self):
        loc = LogicalLocation(name="process_data", kind="function")

        assert loc.name == "process_data"
        assert loc.kind == "function"

    def test_to_dict(self):
        loc = LogicalLocation(
            name="MyClass.my_method",
            kind="function",
            fully_qualified_name="mymodule.MyClass.my_method",
        )

        d = loc.to_dict()

        assert d["name"] == "MyClass.my_method"
        assert d["kind"] == "function"
        assert d["fullyQualifiedName"] == "mymodule.MyClass.my_method"


# =============================================================================
# CodeFlow Tests
# =============================================================================


class TestCodeFlow:
    """Tests for CodeFlow."""

    def test_create_flow(self):
        flow = CodeFlow(
            locations=[
                PhysicalLocation("src/a.py", 10),
                PhysicalLocation("src/b.py", 20),
            ],
            message="Data flows from a.py to b.py",
        )

        assert len(flow.locations) == 2
        assert flow.message == "Data flows from a.py to b.py"

    def test_to_dict(self):
        flow = CodeFlow(
            locations=[
                PhysicalLocation("src/a.py", 10),
                PhysicalLocation("src/b.py", 20),
            ],
        )

        d = flow.to_dict()

        assert "threadFlows" in d
        assert len(d["threadFlows"]) == 1
        assert len(d["threadFlows"][0]["locations"]) == 2


# =============================================================================
# SARIFResult Tests
# =============================================================================


class TestSARIFResult:
    """Tests for SARIFResult."""

    def test_create_result(self):
        result = SARIFResult(
            rule_id="SVM001",
            message="Command injection detected",
            level="error",
        )

        assert result.rule_id == "SVM001"
        assert result.level == "error"

    def test_to_dict_minimal(self):
        result = SARIFResult(
            rule_id="SVM001",
            message="Test message",
            level="warning",
        )

        d = result.to_dict()

        assert d["ruleId"] == "SVM001"
        assert d["message"]["text"] == "Test message"
        assert d["level"] == "warning"

    def test_to_dict_with_locations(self):
        result = SARIFResult(
            rule_id="SVM002",
            message="SQL injection",
            level="error",
            locations=[PhysicalLocation("app.py", 42)],
            logical_locations=[LogicalLocation("query", "function")],
        )

        d = result.to_dict()

        assert len(d["locations"]) == 1
        assert len(d["logicalLocations"]) == 1


# =============================================================================
# ReportingDescriptor Tests
# =============================================================================


class TestReportingDescriptor:
    """Tests for ReportingDescriptor."""

    def test_create_rule(self):
        rule = ReportingDescriptor(
            id="SVM001",
            name="CommandInjection",
            short_description="Command injection vulnerability",
        )

        assert rule.id == "SVM001"
        assert rule.name == "CommandInjection"

    def test_to_dict(self):
        rule = ReportingDescriptor(
            id="SVM001",
            name="CommandInjection",
            short_description="Command injection vulnerability",
            full_description="Detailed description...",
            help_uri="https://example.com/help",
            default_level="error",
        )

        d = rule.to_dict()

        assert d["id"] == "SVM001"
        assert d["name"] == "CommandInjection"
        assert d["shortDescription"]["text"] == "Command injection vulnerability"
        assert d["fullDescription"]["text"] == "Detailed description..."
        assert d["helpUri"] == "https://example.com/help"
        assert d["defaultConfiguration"]["level"] == "error"


# =============================================================================
# ToolDriver Tests
# =============================================================================


class TestToolDriver:
    """Tests for ToolDriver."""

    def test_create_driver(self):
        driver = ToolDriver(name="pysymex", version="1.0.0")

        assert driver.name == "pysymex"
        assert driver.version == "1.0.0"

    def test_to_dict(self):
        driver = ToolDriver(
            name="pysymex",
            version="1.0.0",
            rules=[
                ReportingDescriptor("R1", "Rule1", "First rule"),
            ],
        )

        d = driver.to_dict()

        assert d["name"] == "pysymex"
        assert d["version"] == "1.0.0"
        assert len(d["rules"]) == 1


# =============================================================================
# Run Tests
# =============================================================================


class TestRun:
    """Tests for Run."""

    def test_create_run(self):
        tool = ToolDriver()
        run = Run(tool=tool)

        assert run.tool is tool
        assert run.results == []

    def test_to_dict(self):
        tool = ToolDriver()
        run = Run(
            tool=tool,
            results=[
                SARIFResult("R1", "Test", "warning"),
            ],
        )

        d = run.to_dict()

        assert "tool" in d
        assert len(d["results"]) == 1


# =============================================================================
# SARIFLog Tests
# =============================================================================


class TestSARIFLog:
    """Tests for SARIFLog."""

    def test_create_log(self):
        log = SARIFLog()

        assert log.version == SARIF_VERSION
        assert log.runs == []

    def test_to_dict(self):
        tool = ToolDriver()
        run = Run(tool=tool)
        log = SARIFLog(runs=[run])

        d = log.to_dict()

        assert d["$schema"] == SARIF_SCHEMA
        assert d["version"] == SARIF_VERSION
        assert len(d["runs"]) == 1

    def test_to_json(self):
        tool = ToolDriver()
        run = Run(tool=tool)
        log = SARIFLog(runs=[run])

        json_str = log.to_json()

        # Should be valid JSON
        parsed = json.loads(json_str)
        assert parsed["version"] == SARIF_VERSION

    def test_save(self, tmp_path):
        tool = ToolDriver()
        run = Run(tool=tool)
        log = SARIFLog(runs=[run])

        output_path = tmp_path / "report.sarif"
        log.save(output_path)

        assert output_path.exists()
        content = json.loads(output_path.read_text())
        assert content["version"] == SARIF_VERSION


# =============================================================================
# Conversion Functions Tests
# =============================================================================


class TestConversionFunctions:
    """Tests for conversion functions."""

    def test_severity_to_level(self):
        assert severity_to_level(Severity.CRITICAL) == "error"
        assert severity_to_level(Severity.HIGH) == "error"
        assert severity_to_level(Severity.MEDIUM) == "warning"
        assert severity_to_level(Severity.LOW) == "note"
        assert severity_to_level(Severity.INFO) == "none"

    def test_vulnerability_to_sarif_result(self):
        vuln = VulnerabilityReport(
            vuln_type="Command Injection",
            severity=Severity.CRITICAL,
            cwe_id=78,
            message="Tainted input in os.system",
            file_path="app.py",
            line_number=42,
            function_name="execute",
        )

        result = vulnerability_to_sarif_result(vuln)

        assert result.rule_id == "SVM001"
        assert result.level == "error"
        assert "os.system" in result.message
        assert len(result.locations) == 1
        assert len(result.logical_locations) == 1

    def test_issue_to_sarif_result(self):
        issue = {
            "type": "division_by_zero",
            "message": "Potential division by zero",
            "file": "math_utils.py",
            "line": 25,
        }

        result = issue_to_sarif_result(issue)

        assert result.rule_id == "SVM010"
        assert "division by zero" in result.message


# =============================================================================
# Security Rules Tests
# =============================================================================


class TestSecurityRules:
    """Tests for predefined security rules."""

    def test_rules_exist(self):
        assert "SVM001" in SECURITY_RULES  # Command Injection
        assert "SVM002" in SECURITY_RULES  # SQL Injection
        assert "SVM003" in SECURITY_RULES  # Path Traversal
        assert "SVM004" in SECURITY_RULES  # SSRF

    def test_rule_properties(self):
        rule = SECURITY_RULES["SVM001"]

        assert rule.id == "SVM001"
        assert rule.name == "CommandInjection"
        assert rule.default_level == "error"
        assert "security" in rule.properties.get("tags", [])


# =============================================================================
# SARIFGenerator Tests
# =============================================================================


class TestSARIFGenerator:
    """Tests for SARIFGenerator."""

    def test_create_generator(self):
        generator = SARIFGenerator()

        assert generator.tool_name == "pysymex"

    def test_generate_empty(self):
        generator = SARIFGenerator()
        log = generator.generate()

        assert len(log.runs) == 1
        assert log.runs[0].results == []

    def test_generate_with_vulnerabilities(self):
        generator = SARIFGenerator()

        vulns = [
            VulnerabilityReport(
                vuln_type="Command Injection",
                severity=Severity.CRITICAL,
                cwe_id=78,
                message="Test vulnerability",
            ),
        ]

        log = generator.generate(vulnerabilities=vulns)

        assert len(log.runs[0].results) == 1
        assert log.runs[0].results[0].rule_id == "SVM001"

    def test_generate_with_issues(self):
        generator = SARIFGenerator()

        issues = [
            {"type": "division_by_zero", "message": "Test issue"},
        ]

        log = generator.generate(issues=issues)

        assert len(log.runs[0].results) == 1

    def test_generate_with_files(self):
        generator = SARIFGenerator()

        log = generator.generate(analyzed_files=["app.py", "utils.py"])

        assert len(log.runs[0].artifacts) == 2


# =============================================================================
# generate_sarif Function Tests
# =============================================================================


class TestGenerateSarif:
    """Tests for generate_sarif convenience function."""

    def test_generate_basic(self):
        log = generate_sarif()

        assert isinstance(log, SARIFLog)
        assert log.version == SARIF_VERSION

    def test_generate_with_output(self, tmp_path):
        output_path = tmp_path / "output.sarif"

        log = generate_sarif(output_path=output_path)

        assert output_path.exists()
        content = json.loads(output_path.read_text())
        assert content["version"] == SARIF_VERSION
