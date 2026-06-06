"""Scanner regressions for dict.fromkeys() precision."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_dict_fromkeys_preserves_nonzero_value(tmp_path: Path) -> None:
    target = tmp_path / "fromkeys_value_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = dict.fromkeys([1], 2)\n    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_fromkeys_reports_zero_value_bug(tmp_path: Path) -> None:
    target = tmp_path / "fromkeys_value_zero.py"
    target.write_text(
        "def target() -> int:\n    data = dict.fromkeys([1], 0)\n    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_dict_fromkeys_preserves_zero_key(tmp_path: Path) -> None:
    target = tmp_path / "fromkeys_zero_key.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = dict.fromkeys([0], 1)\n"
        "    keys = list(data.keys())\n"
        "    return 10 // keys[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_empty_dict_fromkeys_is_falsy(tmp_path: Path) -> None:
    target = tmp_path / "fromkeys_empty_falsy.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = dict.fromkeys([])\n"
        "    if data:\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_dict_fromkeys_non_iterable_reports_type_error(tmp_path: Path) -> None:
    target = tmp_path / "fromkeys_non_iterable.py"
    target.write_text(
        "def target() -> object:\n    return dict.fromkeys(1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "TYPE_ERROR")
