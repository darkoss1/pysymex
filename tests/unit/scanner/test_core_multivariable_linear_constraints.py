"""Scanner regressions for multi-variable linear path constraints."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.guards import RuntimeObjectGuards
from pysymex._internal.scanner.file import scan_file
from pysymex._internal.scanner.types import ScanResult


def _scan_source(tmp_path: Path, filename: str, source: str) -> ScanResult:
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")
    return scan_file(target, use_sandbox=False, no_cache=True)


def test_scan_reports_feasible_multivariable_linear_division(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "multivariable_linear_bug.py",
        "def target(x: int, y: int) -> int:\n"
        "    if 3 * x + 2 * y == 31 and x - y == 2:\n"
        "        return 1 // (x - 7)\n"
        "    return 1\n",
    )

    issues = [issue for issue in result.issues if issue.get("kind") == "DIVISION_BY_ZERO"]
    assert result.error is None
    assert len(issues) == 1
    counterexample = issues[0].get("counterexample")
    assert RuntimeObjectGuards.dict(counterexample)
    assert counterexample.get("x") == 7
    assert counterexample.get("y") == 5


def test_scan_prunes_contradictory_multivariable_linear_path(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "multivariable_linear_safe.py",
        "def target(x: int, y: int) -> int:\n"
        "    if 3 * x + 2 * y == 31 and x - y == 2 and x == 100:\n"
        "        return 1 // 0\n"
        "    return 1\n",
    )

    assert result.error is None
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_cpython_multivariable_linear_oracle() -> None:
    def target(x: int, y: int) -> int:
        if 3 * x + 2 * y == 31 and x - y == 2:
            return 1 // (x - 7)
        return 1

    try:
        target(7, 5)
    except ZeroDivisionError:
        pass
    else:
        raise AssertionError("the feasible witness must divide by zero")

    assert target(100, 98) == 1
