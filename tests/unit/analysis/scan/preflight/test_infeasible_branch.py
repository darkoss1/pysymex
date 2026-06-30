from __future__ import annotations

from pathlib import Path

import pytest

from pysymex._internal.core.outcome import IssueKind
from pysymex._internal.scanner.file import scan_file


def _issue_kinds(path: Path) -> set[IssueKind]:
    result = scan_file(
        path,
        use_sandbox=False,
        no_cache=True,
    )
    assert result.error is None
    kinds: set[IssueKind] = set()
    for issue in result.issues:
        kind = issue["kind"]
        kinds.add(kind if isinstance(kind, IssueKind) else IssueKind[str(kind)])
    return kinds


def test_scan_file_skips_bin_count_false_positive(tmp_path: Path) -> None:
    target = tmp_path / "bin_count_zero_false_positive.py"
    target.write_text(
        "def target(a: int, b: int, c: int) -> int:\n"
        "    mixed = ((a ^ b) + (c & 15)) & 15\n"
        "    if mixed != 0 and bin(mixed).count('1') == 0:\n"
        "        return 100 // 0\n"
        "    return mixed\n",
        encoding="utf-8",
    )
    assert _issue_kinds(target) == set()


def test_scan_file_skips_string_rfind_false_positive(tmp_path: Path) -> None:
    target = tmp_path / "string_rfind_suffix_false_positive.py"
    target.write_text(
        "def target(text: str, salt: int) -> int:\n"
        "    index = text.rfind('a')\n"
        "    if text.endswith('a') and index == -1:\n"
        "        return 100 // 0\n"
        "    return index + salt\n",
        encoding="utf-8",
    )
    assert _issue_kinds(target) == set()


@pytest.mark.slow
def test_scan_file_preserves_string_rfind_true_positive(tmp_path: Path) -> None:
    target = tmp_path / "string_rfind_missing_division.py"
    target.write_text(
        "def target(text: str, salt: int) -> int:\n"
        "    index = text.rfind('a')\n"
        "    if index == -1 and (salt & 1) == 0:\n"
        "        return 100 // (index + 1)\n"
        "    return salt + index\n",
        encoding="utf-8",
    )
    assert IssueKind.DIVISION_BY_ZERO in _issue_kinds(target)


def test_scan_file_skips_context_exit_bool_exception_false_positive(tmp_path: Path) -> None:
    target = tmp_path / "context_exit_bool_exception_false_positive.py"
    target.write_text(
        "class ExitTruth:\n"
        "    def __init__(self, value: int, flag: int) -> None:\n"
        "        self.value = value\n"
        "        self.flag = flag\n"
        "    def __bool__(self) -> bool:\n"
        "        if self.flag == 1 and self.value == 0:\n"
        "            raise LookupError('exit truth failed')\n"
        "        return True\n"
        "class Manager:\n"
        "    def __init__(self, value: int, flag: int) -> None:\n"
        "        self.value = value\n"
        "        self.flag = flag\n"
        "    def __enter__(self) -> int:\n"
        "        return self.value\n"
        "    def __exit__(self, exc_type: object, exc: object, tb: object) -> ExitTruth:\n"
        "        return ExitTruth(self.value, self.flag)\n"
        "def target(a: int, b: int, c: int) -> int:\n"
        "    values = [a - b, b - c]\n"
        "    denominator = 3\n"
        "    try:\n"
        "        with Manager(values[0], c):\n"
        "            raise ValueError('body')\n"
        "    except LookupError:\n"
        "        denominator = values[0] + 1\n"
        "    if a == b and c == 1 and denominator == 0:\n"
        "        return 300 // denominator\n"
        "    if denominator != 0:\n"
        "        return 300 // denominator\n"
        "    return values[1]\n",
        encoding="utf-8",
    )
    assert _issue_kinds(target) == set()
