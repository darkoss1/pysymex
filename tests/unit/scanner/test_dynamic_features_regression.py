"""Regression tests for dynamic feature experiment coverage."""

from __future__ import annotations

from pathlib import Path
import sys

import pytest

from pysymex.scanner.core import scan_file


def _line_set(issues: list[dict[str, object]]) -> set[int]:
    """Return line numbers present in scan issues."""
    lines: set[int] = set()
    for issue in issues:
        line_obj = issue.get("line")
        if isinstance(line_obj, int):
            lines.add(line_obj)
    return lines


@pytest.mark.xfail(
    strict=True,
    reason="missing regression fixture: test_experiments/dynamic_features.py",
)
def test_dynamic_features_scan_reports_execution_backed_findings() -> None:
    """Dynamic features regression preserves findings produced by scanner execution."""
    result = scan_file(Path("test_experiments") / "dynamic_features.py", verbose=False)
    lines = _line_set(result.issues)
    expected_lines = {7, 14, 22, 29, 53}
    if sys.version_info >= (3, 12):
        expected_lines.add(36)
    assert expected_lines.issubset(lines)
