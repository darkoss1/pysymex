"""Scanner regressions for direct constructors over exact literal iterables."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_list_bytes_constructor_preserves_nonzero_item(tmp_path: Path) -> None:
    target = tmp_path / "list_bytes_constructor_nonzero.py"
    target.write_text(
        "def target() -> int:\n    values = list(b'\\x01')\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_bytes_constructor_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "list_bytes_constructor_zero.py"
    target.write_text(
        "def target() -> int:\n    values = list(b'\\x00')\n    return 10 // values[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_list_string_constructor_preserves_truthy_value(tmp_path: Path) -> None:
    target = tmp_path / "list_string_constructor_truthy.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list('a')\n"
        "    if not values:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_list_string_constructor_preserves_falsy_empty(tmp_path: Path) -> None:
    target = tmp_path / "list_string_constructor_empty.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = list('')\n"
        "    if values:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_tuple_string_constructor_preserves_truthy_value(tmp_path: Path) -> None:
    target = tmp_path / "tuple_string_constructor_truthy.py"
    target.write_text(
        "def target() -> int:\n"
        "    values = tuple('a')\n"
        "    if not values:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
