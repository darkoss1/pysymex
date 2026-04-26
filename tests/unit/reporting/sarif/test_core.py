from __future__ import annotations

from pathlib import Path

from pysymex.reporting.sarif.core import (
    SARIFGenerator,
    generate_sarif,
    issue_to_sarif_result,
    severity_to_level,
    severity_to_security_severity,
)
from pysymex.reporting.sarif.types import Severity


def test_severity_mapping_functions() -> None:
    assert severity_to_level(Severity.CRITICAL) == "error"
    assert severity_to_security_severity(Severity.MEDIUM) == "medium"


def test_vuln_type_to_rule_id_unknown() -> None:
    from pysymex.reporting.sarif.core import vuln_type_to_rule_id
    assert vuln_type_to_rule_id("something_new") == "SVM999"


def test_issue_conversion_to_sarif_result() -> None:
    i_result = issue_to_sarif_result({"kind": "TYPE_ERROR", "line": "5", "file": "b.py"})
    assert i_result.locations[0].start_line == 5


def test_sarif_generator_and_generate_sarif_save(tmp_path: Path) -> None:
    generator = SARIFGenerator(tool_name="pysymex-test", tool_version="1.2.3")
    log = generator.generate(
        vulnerabilities=[],
        issues=[{"kind": "TYPE_ERROR", "line": 1, "file": "f.py"}],
        analyzed_files=["f.py"],
    )
    assert log.runs[0].tool.name == "pysymex-test"
    assert len(log.runs[0].results) == 1

    out = tmp_path / "out.sarif"
    generated = generate_sarif(issues=[{"kind": "X", "line": 1}], output_path=out)
    assert generated.runs
    assert out.exists()
