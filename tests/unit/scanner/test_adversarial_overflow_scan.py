"""Scanner regressions for opt-in bounded overflow detection."""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path
from typing import cast

from pysymex._internal.scanner.file import scan_file


def _scan_source(
    tmp_path: Path,
    filename: str,
    source: str,
    *,
    detect_overflow: bool = False,
    auto_tune: bool = False,
):
    target = tmp_path / filename
    target.write_text(source, encoding="utf-8")
    return scan_file(
        target,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        timeout=8,
        detect_overflow=detect_overflow,
        auto_tune=auto_tune,
    )


def _load_target(source: str) -> Callable[[int, int, int], int]:
    namespace: dict[str, object] = {}
    exec(compile(source, "<adversarial-overflow-scan>", "exec"), namespace)
    return cast("Callable[[int, int, int], int]", namespace["target"])


BOUNDED_OVERFLOW_TARGET = """
def target(left: int, right: int, guard: int) -> int:
    if guard > 0 and left > 0 and right > 0:
        return left + right
    return 0
"""


BOUNDED_OVERFLOW_SAFE_CONTROL = """
def target(left: int, right: int, guard: int) -> int:
    if guard > 0 and left > 0 and right > 0:
        safe_left = 10
        safe_right = 20
        return safe_left + safe_right
    return 0
"""


def test_scan_file_default_policy_does_not_report_python_int_overflow(
    tmp_path: Path,
) -> None:
    result = _scan_source(tmp_path, "bounded_overflow_default.py", BOUNDED_OVERFLOW_TARGET)

    assert result.error is None
    assert not result.degraded_passes
    assert not any(issue.get("kind") == "OVERFLOW" for issue in result.issues)
    assert result.paths_explored <= 10


def test_scan_file_detect_overflow_reports_bounded_overflow(
    tmp_path: Path,
) -> None:
    result = _scan_source(
        tmp_path,
        "bounded_overflow_enabled.py",
        BOUNDED_OVERFLOW_TARGET,
        detect_overflow=True,
        auto_tune=True,
    )

    assert result.error is None
    assert not result.degraded_passes
    assert any(issue.get("kind") == "OVERFLOW" for issue in result.issues)
    assert result.paths_explored <= 10


def test_scan_file_detect_overflow_safe_control_stays_clean(
    tmp_path: Path,
) -> None:
    result = _scan_source(
        tmp_path,
        "bounded_overflow_safe_control.py",
        BOUNDED_OVERFLOW_SAFE_CONTROL,
        detect_overflow=True,
    )

    assert result.error is None
    assert not result.degraded_passes
    assert not result.issues
    assert result.paths_explored <= 10


def test_cpython_oracle_uses_unbounded_python_ints() -> None:
    target = _load_target(BOUNDED_OVERFLOW_TARGET)

    assert target(2**63 - 1, 1, 1) == 2**63
