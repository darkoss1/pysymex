from __future__ import annotations

from pathlib import Path

from pysymex.analysis.scan.preflight.infeasible_branch import (
    collect_infeasible_branch_division_suppressions,
)
from pysymex.analysis.detectors import IssueKind
from pysymex.scanner.file import scan_file


def _issue_kinds(path: Path) -> set[IssueKind]:
    result = scan_file(
        path,
        use_sandbox=False,
        deterministic_mode=True,
        random_seed=0,
        no_cache=True,
    )
    assert result.error is None
    kinds: set[IssueKind] = set()
    for issue in result.issues:
        kind = issue["kind"]
        kinds.add(kind if isinstance(kind, IssueKind) else IssueKind[str(kind)])
    return kinds


def test_collect_infeasible_branch_suppressions_for_bin_count_contradiction() -> None:
    source = (
        "def target(a: int, b: int, c: int) -> int:\n"
        "    mixed = ((a ^ b) + (c & 15)) & 15\n"
        "    if mixed != 0 and bin(mixed).count('1') == 0:\n"
        "        return 100 // 0\n"
        "    return mixed\n"
    )
    assert collect_infeasible_branch_division_suppressions(source) == frozenset({4})


def test_collect_infeasible_branch_suppressions_for_endswith_rfind_contradiction() -> None:
    source = (
        "def target(text: str, salt: int) -> int:\n"
        "    index = text.rfind('a')\n"
        "    if text.endswith('a') and index == -1:\n"
        "        return 100 // 0\n"
        "    return index\n"
    )
    assert collect_infeasible_branch_division_suppressions(source) == frozenset({4})


def test_collect_infeasible_branch_suppressions_for_symmetric_comparisons() -> None:
    source = (
        "def target(a: int, b: int, c: int, text: str) -> int:\n"
        "    mixed = ((a ^ b) + (c & 15)) & 15\n"
        "    index = text.rfind('7')\n"
        "    if 0 != mixed and 0 == bin(mixed).count('1'):\n"
        "        return 100 // 0\n"
        "    if text.endswith('7') and -1 == index:\n"
        "        return 200 // 0\n"
        "    return mixed + index\n"
    )
    assert collect_infeasible_branch_division_suppressions(source) == frozenset({5, 7})


def test_collect_infeasible_branch_suppressions_rejects_repeated_calls() -> None:
    source = (
        "counter = 0\n"
        "def flip() -> int:\n"
        "    global counter\n"
        "    counter += 1\n"
        "    return 1 if counter == 1 else 0\n"
        "def target() -> int:\n"
        "    if flip() != 0 and bin(flip()).count('1') == 0:\n"
        "        return 100 // 0\n"
        "    return 1\n"
    )
    assert collect_infeasible_branch_division_suppressions(source) == frozenset()


def test_collect_infeasible_branch_suppressions_rejects_rebound_rfind_index() -> None:
    source = (
        "def target(text: str) -> int:\n"
        "    index = text.rfind('a')\n"
        "    index = -1\n"
        "    if text.endswith('a') and index == -1:\n"
        "        return 100 // 0\n"
        "    return 1\n"
    )
    assert collect_infeasible_branch_division_suppressions(source) == frozenset()


def test_collect_infeasible_branch_suppressions_skips_nested_scopes() -> None:
    source = (
        "def target(a: int) -> int:\n"
        "    mixed = a & 15\n"
        "    if mixed != 0 and bin(mixed).count('1') == 0:\n"
        "        def nested() -> int:\n"
        "            return 100 // 0\n"
        "    return mixed\n"
    )
    assert collect_infeasible_branch_division_suppressions(source) == frozenset()


def test_collect_infeasible_branch_suppressions_traverses_compound_statements() -> None:
    source = (
        "async def target(text: str) -> int:\n"
        "    async with manager():\n"
        "        index = text.rfind('a')\n"
        "        if text.endswith('a') and index == -1:\n"
        "            return 100 // 0\n"
        "    match text:\n"
        "        case 'x':\n"
        "            mixed = len(text) & 15\n"
        "            if mixed != 0 and bin(mixed).count('1') == 0:\n"
        "                return 200 // 0\n"
        "    return 1\n"
    )
    assert collect_infeasible_branch_division_suppressions(source) == frozenset({5, 10})


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


def test_collect_infeasible_branch_suppressions_preserves_bin_count_true_positive() -> None:
    source = (
        "def target(a: int, b: int, c: int) -> int:\n"
        "    mixed = ((a ^ b) + (c & 15)) & 15\n"
        "    if bin(mixed).count('1') == 0:\n"
        "        return 100 // mixed\n"
        "    return mixed + 1\n"
    )
    assert collect_infeasible_branch_division_suppressions(source) == frozenset()


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
