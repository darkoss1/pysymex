from __future__ import annotations

from pathlib import Path

from pysymex.reporting.sarif.core import (
    SARIFGenerator,
    generate_sarif,
    issue_to_sarif_result,
    severity_to_level,
    severity_to_security_severity,
    vulnerability_to_sarif_result,
    vuln_type_to_rule_id,
)
from pysymex.reporting.sarif.types import Severity, VulnerabilityReport


def test_severity_mapping_functions() -> None:
    assert severity_to_level(Severity.CRITICAL) == "error"
    assert severity_to_security_severity(Severity.MEDIUM) == "medium"


def test_vuln_type_to_rule_id_known_and_unknown() -> None:
    assert vuln_type_to_rule_id("command_injection") == "SVM001"
    assert vuln_type_to_rule_id("something_new") == "SVM999"


def test_vulnerability_and_issue_conversion_to_sarif_results() -> None:
    vuln = VulnerabilityReport(
        vuln_type="command_injection",
        message="bad",
        severity=Severity.HIGH,
        file_path="a.py",
        line_number=3,
        function_name="run",
        source="src",
        sink="sink",
        taint_path=["a.py:2", "a.py:3"],
    )
    v_result = vulnerability_to_sarif_result(vuln)
    i_result = issue_to_sarif_result({"kind": "TYPE_ERROR", "line": "5", "file": "b.py"})

    assert v_result.rule_id == "SVM001"
    assert len(v_result.code_flows) == 1
    assert i_result.locations[0].start_line == 5


def test_sarif_generator_and_generate_sarif_save(tmp_path: Path) -> None:
    generator = SARIFGenerator(tool_name="pysymex-test", tool_version="1.2.3")
    log = generator.generate(
        vulnerabilities=[VulnerabilityReport("command_injection", "m", Severity.HIGH)],
        issues=[{"kind": "TYPE_ERROR", "line": 1, "file": "f.py"}],
        analyzed_files=["f.py"],
    )
    assert log.runs[0].tool.name == "pysymex-test"
    assert len(log.runs[0].results) == 2

    out = tmp_path / "out.sarif"
    generated = generate_sarif(issues=[{"kind": "X", "line": 1}], output_path=out)
    assert generated.runs
    assert out.exists()

