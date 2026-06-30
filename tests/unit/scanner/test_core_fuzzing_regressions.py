"""Scanner regressions promoted from fuzzing-generated precision gaps."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_explores_symbolic_str_startswith_and_endswith(tmp_path: Path) -> None:
    target = tmp_path / "symbolic_str_affix_branches.py"
    target.write_text(
        "def startswith_target(s: str) -> int:\n"
        "    if s.startswith('abc'):\n"
        "        return 1 // 0\n"
        "    return 1\n"
        "\n"
        "def endswith_target(s: str) -> int:\n"
        "    if s.endswith('xyz'):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "startswith_target", "DIVISION_BY_ZERO")
    assert _has_issue_kind(result, "endswith_target", "DIVISION_BY_ZERO")


def test_scan_file_explores_symbolic_bytes_slice_equality(tmp_path: Path) -> None:
    target = tmp_path / "symbolic_bytes_slice_equality.py"
    target.write_text(
        "def target(b: bytes) -> int:\n"
        "    if b[:3] == b'abc':\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")


def test_scan_file_reports_concrete_math_type_errors(tmp_path: Path) -> None:
    target = tmp_path / "math_type_errors.py"
    target.write_text(
        "import math\n"
        "\n"
        "def sqrt_bad() -> float:\n"
        "    return math.sqrt('bad')\n"
        "\n"
        "def ceil_bad() -> int:\n"
        "    return math.ceil('bad')\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "sqrt_bad", "TYPE_ERROR")
    assert _has_issue_kind(result, "ceil_bad", "TYPE_ERROR")
