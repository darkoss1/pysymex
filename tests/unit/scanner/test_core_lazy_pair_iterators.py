"""Scanner regressions for enumerate and zip iterator state."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_second_next_on_enumerate_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "enumerate_second_next.py"
    target.write_text(
        "def target() -> object:\n"
        "    iterator = enumerate([1])\n"
        "    next(iterator)\n"
        "    return next(iterator)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_second_next_on_zip_reports_stop_iteration(tmp_path: Path) -> None:
    target = tmp_path / "zip_second_next.py"
    target.write_text(
        "def target() -> object:\n"
        "    iterator = zip([1], [2])\n"
        "    next(iterator)\n"
        "    return next(iterator)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "UNHANDLED_EXCEPTION")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_list_enumerate_bytes_preserves_nonzero_item(tmp_path: Path) -> None:
    target = tmp_path / "enumerate_bytes_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    pairs = list(enumerate(b'\\x01'))\n"
        "    return 10 // pairs[0][1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_list_enumerate_bytes_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "enumerate_bytes_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    pairs = list(enumerate(b'\\x00'))\n"
        "    return 10 // pairs[0][1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_list_zip_bytes_preserves_nonzero_item(tmp_path: Path) -> None:
    target = tmp_path / "zip_bytes_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    pairs = list(zip(b'\\x01', [1]))\n"
        "    return 10 // pairs[0][0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_list_zip_bytes_reports_zero_item_bug(tmp_path: Path) -> None:
    target = tmp_path / "zip_bytes_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    pairs = list(zip(b'\\x00', [1]))\n"
        "    return 10 // pairs[0][0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
