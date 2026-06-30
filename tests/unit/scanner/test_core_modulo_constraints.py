"""Scanner regressions for simple modulo path constraints."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.guards import RuntimeObjectGuards
from pysymex._internal.scanner.file import scan_file
from pysymex._internal.scanner.types import ScanResult


def _scan_source(tmp_path: Path, filename: str, source: str) -> ScanResult:
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")
    return scan_file(target, use_sandbox=False, no_cache=True)


def test_scan_reports_feasible_conjoined_modulo_division(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "modulo_constraints_bug.py",
        "def target(x: int, y: int) -> int:\n"
        "    if x % 7 == 3 and y % 5 == 4 and x + y == 19:\n"
        "        return 1 // (x - 10)\n"
        "    return 1\n",
    )

    issues = [issue for issue in result.issues if issue.get("kind") == "DIVISION_BY_ZERO"]
    assert result.error is None
    assert len(issues) == 1
    counterexample = issues[0].get("counterexample")
    assert RuntimeObjectGuards.dict(counterexample)
    assert counterexample.get("x") == 10
    assert counterexample.get("y") == 9


def test_scan_prunes_contradictory_modulo_constraints(tmp_path: Path) -> None:
    result = _scan_source(
        tmp_path,
        "modulo_constraints_safe.py",
        "def target(x: int) -> int:\n"
        "    if x % 2 == 0 and x % 2 == 1:\n"
        "        return 1 // 0\n"
        "    return 1\n",
    )

    assert result.error is None
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_cpython_conjoined_modulo_oracle() -> None:
    def target(x: int, y: int) -> int:
        if x % 7 == 3 and y % 5 == 4 and x + y == 19:
            return 1 // (x - 10)
        return 1

    try:
        target(10, 9)
    except ZeroDivisionError:
        pass
    else:
        raise AssertionError("the modulo witness must divide by zero")

    assert target(17, 2) == 1
