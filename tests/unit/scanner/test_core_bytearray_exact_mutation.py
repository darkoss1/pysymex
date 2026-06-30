"""Scanner regressions for exact bytearray construction and append mutation."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_bytearray_append_preserves_nonzero_tail(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_append_nonzero_tail.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01')\n"
        "    data.append(1)\n"
        "    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_append_reports_zero_tail(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_append_zero_tail.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01')\n"
        "    data.append(0)\n"
        "    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_append_preserves_original_head(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_append_preserve_head.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01')\n"
        "    data.append(0)\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_extend_preserves_nonzero_tail(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_extend_nonzero_tail.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01')\n"
        "    data.extend(b'\\x02')\n"
        "    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_extend_reports_zero_tail(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_extend_zero_tail.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01')\n"
        "    data.extend(b'\\x00')\n"
        "    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_insert_reports_zero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_insert_zero_head.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01')\n"
        "    data.insert(0, 0)\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_insert_preserves_shifted_nonzero(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_insert_shifted_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01')\n"
        "    data.insert(0, 0)\n"
        "    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_pop_preserves_nonzero_return(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_pop_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray(b'\\x01')\n    return 10 // data.pop()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_pop_reports_zero_return(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_pop_zero.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray(b'\\x00')\n    return 10 // data.pop()\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_remove_deletes_zero_keeps_nonzero(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_remove_zero_keeps_nonzero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x00\\x01')\n"
        "    data.remove(0)\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_remove_reports_remaining_zero(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_remove_one_keeps_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01\\x00')\n"
        "    data.remove(1)\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_remove_reports_missing_value(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_remove_missing.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray(b'\\x01')\n    data.remove(2)\n    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "VALUE_ERROR")


def test_scan_file_bytearray_copy_reports_zero_payload(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_copy_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    copied = bytearray(b'\\x00').copy()\n"
        "    return 10 // copied[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_copy_is_independent_after_clear(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_copy_independent.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01')\n"
        "    copied = data.copy()\n"
        "    data.clear()\n"
        "    return 10 // copied[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_reverse_reports_zero_head(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_reverse_zero_head.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01\\x00')\n"
        "    data.reverse()\n"
        "    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_reverse_preserves_nonzero_tail(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_reverse_nonzero_tail.py"
    target.write_text(
        "def target() -> int:\n"
        "    data = bytearray(b'\\x01\\x00')\n"
        "    data.reverse()\n"
        "    return 10 // data[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_decode_preserves_nonempty_string(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_decode_nonempty.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray(b'A')\n    return 10 // len(data.decode())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_bytearray_decode_reports_empty_string_length(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_decode_empty.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray()\n    return 10 // len(data.decode())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "ATTRIBUTE_ERROR")


def test_scan_file_bytearray_hex_preserves_nonempty_string(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_hex_nonempty.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray(b'\\x01')\n    return 10 // len(data.hex())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")


def test_scan_file_bytearray_hex_reports_empty_string_length(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_hex_empty.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray()\n    return 10 // len(data.hex())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "ATTRIBUTE_ERROR")


def test_scan_file_bytearray_integer_constructor_reports_zero_byte(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_integer_zero.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray(1)\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytearray_bytes_constructor_reports_zero_byte(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_bytes_zero.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray(b'\\x00')\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
