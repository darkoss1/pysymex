"""Scanner regressions for bounded structural pattern matching."""

from __future__ import annotations

from pathlib import Path

from pysymex.scanner.file import scan_file


def _issue_kinds_on_target_line(result: object, line: int) -> set[object]:
    issues = getattr(result, "issues")
    return {issue.get("kind") for issue in issues if issue.get("line") == line}


def test_scan_file_preserves_literal_tuple_pattern_zero_value(tmp_path: Path) -> None:
    target = tmp_path / "tuple_pattern_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    payload = ('fallback', 0)\n"
        "    match payload:\n"
        "        case ('fallback', value):\n"
        "            return 10 // value\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _issue_kinds_on_target_line(result, 5) == {"DIVISION_BY_ZERO"}


def test_scan_file_preserves_or_tuple_pattern_zero_value(tmp_path: Path) -> None:
    target = tmp_path / "or_tuple_pattern_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    payload = ('fallback', 0)\n"
        "    match payload:\n"
        "        case ('zero', value) | ('fallback', value):\n"
        "            return 10 // value\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _issue_kinds_on_target_line(result, 5) == {"DIVISION_BY_ZERO"}


def test_scan_file_retains_mapping_pattern_capture_type(tmp_path: Path) -> None:
    target = tmp_path / "mapping_pattern_zero.py"
    target.write_text(
        "def target() -> int:\n"
        "    payload = {'rate': 0}\n"
        "    match payload:\n"
        "        case {'rate': rate}:\n"
        "            return 10 // rate\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _issue_kinds_on_target_line(result, 5) == {"DIVISION_BY_ZERO"}


def test_scan_file_retains_class_pattern_capture_type(tmp_path: Path) -> None:
    target = tmp_path / "class_pattern_zero.py"
    target.write_text(
        "class Token:\n"
        "    __match_args__ = ('value',)\n"
        "    def __init__(self, value: int) -> None:\n"
        "        self.value = value\n\n"
        "def target() -> int:\n"
        "    token = Token(0)\n"
        "    match token:\n"
        "        case Token(value):\n"
        "            return 10 // value\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _issue_kinds_on_target_line(result, 10) == {"DIVISION_BY_ZERO"}
