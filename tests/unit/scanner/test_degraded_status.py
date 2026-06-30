from __future__ import annotations

from pathlib import Path

import pytest

from pysymex._internal.execution.results.result import ExecutionResult
from pysymex._internal.scanner.file import scan_file


def test_scan_file_preserves_execution_degradation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "target.py"
    target.write_text("def target(value: int) -> int:\n    return value\n", encoding="utf-8")

    def degraded_execution(*args: object, **kwargs: object) -> ExecutionResult:
        _ = args
        _ = kwargs
        return ExecutionResult(degraded_passes=["solver_unknown_detector_query"])

    monkeypatch.setattr(
        "pysymex._internal.execution.executors.core.SymbolicExecutor.execute_code",
        degraded_execution,
    )

    result = scan_file(target, use_sandbox=False, trace_enabled=False)

    assert result.error is None
    assert result.degraded_passes == ["solver_unknown_detector_query"]


def test_scan_file_reports_unsupported_numeric_abstraction(tmp_path: Path) -> None:
    target = tmp_path / "matrix_operator.py"
    target.write_text(
        "def target(left: object, right: object) -> object:\n    return left @ right\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, trace_enabled=False)

    assert result.error is None
    assert "unsupported_numeric_abstraction" in result.degraded_passes


def test_scan_file_definite_string_type_error_is_not_numeric_degradation(
    tmp_path: Path,
) -> None:
    target = tmp_path / "string_type_error.py"
    target.write_text(
        "def target(x: int) -> object:\n"
        "    if x == 0:\n"
        "        result = x + 'bad'\n"
        "    else:\n"
        "        result = x + 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, trace_enabled=False)

    assert result.error is None
    assert any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert "unsupported_numeric_abstraction" not in result.degraded_passes
