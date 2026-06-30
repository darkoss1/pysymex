"""Scanner regressions for modeled exception control flow."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _scan_source(tmp_path: Path, filename: str, source: str):
    path = tmp_path / filename
    path.write_text(source, encoding="utf-8")
    return scan_file(
        path,
        use_sandbox=False,
        no_cache=True,
        max_paths=80,
        max_depth=4000,
        max_iterations=40000,
        timeout=10,
        enable_fp_filtering=True,
    )


def test_uncaught_int_value_error_does_not_continue_to_downstream_bugs(
    tmp_path: Path,
) -> None:
    result = _scan_source(
        tmp_path,
        "uncaught_int_no_continuation.py",
        """
def target(flag: int) -> int:
    if flag == 0:
        value = int("not-an-int")
        return 100 // (value - value)
    return 1
""",
    )

    kinds = {issue.get("kind") for issue in result.issues}
    assert "VALUE_ERROR" in kinds
    assert "DIVISION_BY_ZERO" not in kinds
    assert "TYPE_ERROR" not in kinds


def test_caught_int_value_error_does_not_continue_past_raising_call(
    tmp_path: Path,
) -> None:
    result = _scan_source(
        tmp_path,
        "caught_int_no_success_continuation.py",
        """
def target(flag: int) -> int:
    if flag == 0:
        try:
            value = int("not-an-int")
        except ValueError:
            return 7
        return 100 // (value - value)
    return 1
""",
    )

    assert not any(
        issue.get("kind") in {"VALUE_ERROR", "DIVISION_BY_ZERO", "TYPE_ERROR"}
        for issue in result.issues
    )


def test_imported_builtin_int_value_error_does_not_leave_preflight_division(
    tmp_path: Path,
) -> None:
    result = _scan_source(
        tmp_path,
        "imported_builtin_int_no_preflight_continuation.py",
        """
from builtins import int as builtin_int

def target(flag: int) -> int:
    if flag == 0:
        value = builtin_int("not-an-int")
        return 100 // (value - value)
    return 1
""",
    )

    kinds = {issue.get("kind") for issue in result.issues}
    assert "VALUE_ERROR" in kinds
    assert "DIVISION_BY_ZERO" not in kinds
    assert "TYPE_ERROR" not in kinds


def test_uncaught_bytes_fromhex_value_error_does_not_continue_to_division(
    tmp_path: Path,
) -> None:
    result = _scan_source(
        tmp_path,
        "uncaught_fromhex_no_continuation.py",
        """
def target(flag: int) -> int:
    if flag == 0:
        payload = bytes.fromhex("zz")
        return len(payload) // len(payload)
    return 1
""",
    )

    kinds = {issue.get("kind") for issue in result.issues}
    assert "VALUE_ERROR" in kinds
    assert "DIVISION_BY_ZERO" not in kinds
    assert "TYPE_ERROR" not in kinds


def test_caught_bytes_fromhex_value_error_routes_to_handler_without_issue(
    tmp_path: Path,
) -> None:
    result = _scan_source(
        tmp_path,
        "caught_fromhex_handler.py",
        """
def target(flag: int) -> int:
    if flag == 0:
        try:
            payload = bytes.fromhex("zz")
        except ValueError:
            return 9
        return len(payload) // len(payload)
    return 1
""",
    )

    assert not any(
        issue.get("kind") in {"VALUE_ERROR", "DIVISION_BY_ZERO", "TYPE_ERROR"}
        for issue in result.issues
    )
