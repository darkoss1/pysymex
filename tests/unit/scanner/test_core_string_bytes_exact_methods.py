"""Scanner regressions for exact string and bytes method results."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_str_split_preserves_truthy_head(tmp_path: Path) -> None:
    target = tmp_path / "str_split_truthy.py"
    target.write_text(
        "def target() -> int:\n    part = 'a,b'.split(',')[0]\n    return 10 // len(part)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_str_split_reports_empty_head_division(tmp_path: Path) -> None:
    target = tmp_path / "str_split_empty.py"
    target.write_text(
        "def target() -> int:\n    part = ',b'.split(',')[0]\n    return 10 // len(part)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_str_replace_preserves_nonempty_result(tmp_path: Path) -> None:
    target = tmp_path / "str_replace_nonempty.py"
    target.write_text(
        "def target() -> str:\n    text = 'a'.replace('a', 'b')\n    return text[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_str_replace_reports_empty_result_index(tmp_path: Path) -> None:
    target = tmp_path / "str_replace_empty.py"
    target.write_text(
        "def target() -> str:\n    text = 'a'.replace('a', '')\n    return text[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_str_replace_count_preserves_nonempty_result(tmp_path: Path) -> None:
    target = tmp_path / "str_replace_count_nonempty.py"
    target.write_text(
        "def target() -> str:\n    text = 'aa'.replace('a', '', 1)\n    return text[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_split_preserves_nonzero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_split_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    part = b'\\x01,\\x02'.split(b',')[0]\n"
        "    return 10 // part[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_split_reports_zero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_split_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    part = b'\\x00,\\x02'.split(b',')[0]\n"
        "    return 10 // part[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_split_maxsplit_preserves_nonzero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_split_maxsplit_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    part = b'\\x01,\\x00'.split(b',', 1)[0]\n"
        "    return 10 // part[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_replace_preserves_nonzero_result(tmp_path: Path) -> None:
    target = tmp_path / "bytes_replace_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b'\\x00'.replace(b'\\x00', b'\\x01')\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_replace_reports_zero_result(tmp_path: Path) -> None:
    target = tmp_path / "bytes_replace_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b'\\x01'.replace(b'\\x01', b'\\x00')\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_replace_count_preserves_nonzero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytes_replace_count_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b'\\x00\\x00'.replace(b'\\x00', b'\\x01', 1)\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_replace_count_reports_zero_tail(tmp_path: Path) -> None:
    target = tmp_path / "bytes_replace_count_tail_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b'\\x00\\x00'.replace(b'\\x00', b'\\x01', 1)\n"
        "    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_strip_preserves_nonzero_result(tmp_path: Path) -> None:
    target = tmp_path / "bytes_strip_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b'\\x00\\x01\\x00'.strip(b'\\x00')\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_strip_reports_empty_result_index(tmp_path: Path) -> None:
    target = tmp_path / "bytes_strip_empty.py"
    target.write_text(
        "def target() -> int:\n    data = b'\\x00'.strip(b'\\x00')\n    return data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_removeprefix_preserves_nonzero_result(tmp_path: Path) -> None:
    target = tmp_path / "bytes_removeprefix_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b'\\x00\\x01'.removeprefix(b'\\x00')\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_removeprefix_reports_empty_result_index(tmp_path: Path) -> None:
    target = tmp_path / "bytes_removeprefix_empty.py"
    target.write_text(
        "def target() -> int:\n    data = b'\\x00'.removeprefix(b'\\x00')\n    return data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_startswith_false_skips_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_startswith_false.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b'\\x01'\n"
        "    if data.startswith(b'\\x02'):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_endswith_false_skips_bug_branch(tmp_path: Path) -> None:
    target = tmp_path / "bytes_endswith_false.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b'\\x01'\n"
        "    if data.endswith(b'\\x02'):\n"
        "        return 10 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_endswith_empty_suffix_preserves_true_branch(
    tmp_path: Path,
) -> None:
    target = tmp_path / "bytes_endswith_empty_true.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = b''\n"
        "    if data.endswith(b''):\n"
        "        return data[0]\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")
