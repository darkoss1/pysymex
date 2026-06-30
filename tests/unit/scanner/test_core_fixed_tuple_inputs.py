"""Scanner regressions for fixed tuple input shape and index bounds."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest

from pysymex._internal.scanner.file import scan_file
from pysymex._internal.scanner.types import ScanResult


def _scan_tuple_source(tmp_path: Path, filename: str, indexed_position: int) -> ScanResult:
    target = tmp_path / filename
    target.write_text(
        "def target(values: tuple[int, int]) -> int:\n"
        "    if values[0] + values[1] == 9:\n"
        f"        return values[{indexed_position}]\n"
        "    return 1\n",
        encoding="utf-8",
    )
    return scan_file(target, use_sandbox=False, no_cache=True)


def test_scan_reports_fixed_tuple_out_of_bounds_without_degradation(tmp_path: Path) -> None:
    result = _scan_tuple_source(tmp_path, "tuple_oob.py", 2)

    assert result.error is None
    assert "unsupported_subscript_abstraction" not in result.degraded_passes
    assert any(issue.get("kind") == "INDEX_ERROR" for issue in result.issues)


def test_scan_keeps_fixed_tuple_guarded_access_clean(tmp_path: Path) -> None:
    result = _scan_tuple_source(tmp_path, "tuple_safe.py", 1)

    assert result.error is None
    assert "unsupported_subscript_abstraction" not in result.degraded_passes
    assert not any(issue.get("kind") == "INDEX_ERROR" for issue in result.issues)


def test_cpython_fixed_tuple_index_oracle() -> None:
    def target(values: tuple[int, int], index: int) -> int:
        return values[index]

    concrete_target = cast("Callable[[tuple[int, int], int], int]", target)
    assert concrete_target((4, 5), 1) == 5
    with pytest.raises(IndexError):
        concrete_target((4, 5), 2)
