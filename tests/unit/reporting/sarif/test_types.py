from __future__ import annotations

from pathlib import Path
from typing import cast

from pysymex.reporting.sarif.types import (
    CodeFlow,
    LogicalLocation,
    PhysicalLocation,
    Run,
    SARIFLog,
    SARIFResult,
    Severity,
    ToolDriver,
)


def test_severity_to_sarif_level() -> None:
    assert Severity.CRITICAL.to_sarif_level() == "error"
    assert Severity.LOW.to_sarif_level() == "note"


def test_location_and_codeflow_to_dict() -> None:
    loc = PhysicalLocation(file_path="a\\b.py", start_line=7)
    flow = CodeFlow(locations=[loc], message="flow")
    data = flow.to_dict()
    thread_flows = cast("list[dict[str, object]]", data["threadFlows"])
    locations = cast("list[dict[str, object]]", thread_flows[0]["locations"])
    location = cast("dict[str, object]", locations[0]["location"])
    physical = cast("dict[str, object]", location["physicalLocation"])
    artifact = cast("dict[str, object]", physical["artifactLocation"])
    assert artifact["uri"] == "a/b.py"


def test_sarif_log_json_and_save(tmp_path: Path) -> None:
    result = SARIFResult(rule_id="R1", message="m", level="warning")
    run = Run(tool=ToolDriver(), results=[result], artifacts=[])
    log = SARIFLog(runs=[run])

    payload = log.to_json()
    out = tmp_path / "report.sarif"
    log.save(out)

    assert "\"runs\"" in payload
    assert out.exists()


def test_logical_location_to_dict() -> None:
    ll = LogicalLocation(name="f", fully_qualified_name="pkg.f")
    data = ll.to_dict()
    assert data["name"] == "f"
    assert data["fullyQualifiedName"] == "pkg.f"

