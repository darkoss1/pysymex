"""Scanner regressions for exact binary constructor payloads."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_bytes_constructor_preserves_nonzero_source(tmp_path: Path) -> None:
    target = tmp_path / "bytes_constructor_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = bytes(b'\\x01')\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytes_constructor_reports_zero_source(tmp_path: Path) -> None:
    target = tmp_path / "bytes_constructor_zero.py"
    target.write_text(
        "def target() -> int:\n    data = bytes(b'\\x00')\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_constructor_decode_empty_is_precise(tmp_path: Path) -> None:
    target = tmp_path / "bytes_constructor_decode_empty.py"
    target.write_text(
        "def target() -> int:\n    data = bytes()\n    return len(data.decode())\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "ATTRIBUTE_ERROR")
    assert not _has_issue_kind(result, "target", "TYPE_ERROR")
    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_constructor_preserves_encoded_nonzero(tmp_path: Path) -> None:
    target = tmp_path / "bytes_constructor_encoded_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = bytes('A', 'ascii')\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_bytearray_constructor_preserves_encoded_nonzero(tmp_path: Path) -> None:
    target = tmp_path / "bytearray_constructor_encoded_nonzero.py"
    target.write_text(
        "def target() -> int:\n    data = bytearray('A', 'ascii')\n    return 10 // data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert not _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_binary_constructors_report_encoded_zero(tmp_path: Path) -> None:
    target = tmp_path / "binary_constructor_encoded_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    left = bytes('\\x00', 'latin1')[0]\n"
        "    right = bytearray('\\x00', 'latin1')[0]\n"
        "    return 10 // (left + right)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_bytes_constructor_encoding_errors_can_empty_result(tmp_path: Path) -> None:
    target = tmp_path / "bytes_constructor_ignore_empty.py"
    target.write_text(
        "def target() -> int:\n    data = bytes('é', 'ascii', 'ignore')\n    return data[0]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "INDEX_ERROR")


def test_scan_file_binary_constructors_report_invalid_codec_argument_types(
    tmp_path: Path,
) -> None:
    target = tmp_path / "binary_constructor_invalid_codec_types.py"
    target.write_text(
        "def bytes_bad_encoding() -> int:\n"
        "    return len(bytes('A', 1))\n"
        "\n"
        "def bytes_bad_errors() -> int:\n"
        "    return len(bytes('A', 'ascii', 1))\n"
        "\n"
        "def bytearray_bad_encoding() -> int:\n"
        "    return len(bytearray('A', 1))\n"
        "\n"
        "def bytearray_bad_errors() -> int:\n"
        "    return len(bytearray('A', 'ascii', 1))\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "bytes_bad_encoding", "TYPE_ERROR")
    assert _has_issue_kind(result, "bytes_bad_errors", "TYPE_ERROR")
    assert _has_issue_kind(result, "bytearray_bad_encoding", "TYPE_ERROR")
    assert _has_issue_kind(result, "bytearray_bad_errors", "TYPE_ERROR")
