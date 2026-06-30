from __future__ import annotations

from pathlib import Path

from pysymex._internal.reporting.sarif.generator import SARIFGenerator
from pysymex._internal.reporting.sarif.results import issue_to_sarif_result
from pysymex._internal.reporting.sarif.severity import (
    severity_to_level,
    severity_to_security_severity,
)
from pysymex._internal.reporting.sarif.types.base import SarifSeverity


def test_severity_mapping_functions() -> None:
    assert severity_to_level(SarifSeverity.CRITICAL) == "error"
    assert severity_to_security_severity(SarifSeverity.MEDIUM) == "medium"


def test_vuln_type_to_rule_id_unknown() -> None:
    from pysymex._internal.reporting.sarif.rules.catalog import vuln_type_to_rule_id

    assert vuln_type_to_rule_id("something_new") == "SVM999"


def test_issue_conversion_to_sarif_result() -> None:
    i_result = issue_to_sarif_result({"kind": "TYPE_ERROR", "line": "5", "file": "b.py"})
    assert i_result.locations[0].start_line == 5


def test_sarif_generator_and_save(tmp_path: Path) -> None:
    generator = SARIFGenerator(tool_name="pysymex-test", tool_version="1.2.3")
    log = generator.generate(
        vulnerabilities=[],
        issues=[{"kind": "TYPE_ERROR", "line": 1, "file": "f.py"}],
        analyzed_files=["f.py"],
    )
    assert log.runs[0].tool.name == "pysymex-test"
    assert len(log.runs[0].results) == 1

    out = tmp_path / "out.sarif"
    generated = SARIFGenerator().generate(issues=[{"kind": "X", "line": 1}])
    generated.save(out)
    assert generated.runs
    assert out.exists()


def test_sarif_generator_records_analysis_failure_evidence() -> None:
    log = SARIFGenerator().generate(
        issues=[],
        analyzed_files=["broken.py"],
        execution_successful=False,
        analysis_errors=["Syntax Error: invalid syntax"],
    )
    invocation = log.runs[0].invocations[0]

    assert invocation["executionSuccessful"] is False
    assert invocation["properties"] == {"analysisErrors": ["Syntax Error: invalid syntax"]}
