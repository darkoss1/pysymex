"""Tests for scanner syntactic fallback diagnostics."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.analysis.scan.preflight.bytearray.core import find_bytearray_modulo_index
from pysymex._internal.analysis.scan.preflight.equality.zero.core import (
    find_equality_guarded_zero_division,
)
from pysymex._internal.analysis.scan.preflight.guarded.index.core import find_guarded_index_offset
from pysymex._internal.analysis.scan.preflight.masked.zero.core import find_masked_zero_division
from pysymex._internal.analysis.scan.preflight.self.canceling.zero import (
    find_self_canceling_zero_division,
)
from pysymex._internal.scanner.file import scan_file


def test_bytearray_modulo_index_diagnostic_reports_unguarded_oversized_modulo() -> None:
    """The bytearray fallback reports simple modulo ranges wider than the concrete buffer."""
    issues = find_bytearray_modulo_index(
        "def target(x: int) -> int:\n"
        "    table = bytearray([1, 2, 3, 4])\n"
        "    idx = x % 13\n"
        "    return table[idx]\n"
    )

    assert len(issues) == 1
    assert issues[0]["kind"] == "INDEX_ERROR"
    assert issues[0]["function_name"] == "target"


def test_bytearray_modulo_index_diagnostic_ignores_guarded_modulo_index() -> None:
    """An explicit upper-bound guard prevents the syntactic fallback report."""
    issues = find_bytearray_modulo_index(
        "def target(x: int) -> int:\n"
        "    table = bytearray([1, 2, 3, 4])\n"
        "    idx = x % 13\n"
        "    if idx < 4:\n"
        "        return table[idx]\n"
        "    return 0\n"
    )

    assert issues == []


def test_guarded_index_offset_reports_off_by_offset_access() -> None:
    """A guard for ``index < len(data)-1`` does not protect ``data[index+2]``."""
    issues = find_guarded_index_offset(
        "def target(index: int) -> int:\n"
        "    data = [1, 2, 3]\n"
        "    if 0 <= index < len(data) - 1:\n"
        "        return data[index + 2]\n"
        "    return 0\n"
    )

    assert len(issues) == 1
    assert issues[0]["kind"] == "INDEX_ERROR"
    assert issues[0]["function_name"] == "target"


def test_guarded_index_offset_tracks_dict_alias_sequence_length() -> None:
    """Dictionary aliases to known sequences keep enough length information."""
    issues = find_guarded_index_offset(
        "def target(index: int) -> int:\n"
        "    cells = [1, 2, 3]\n"
        "    shared = {'cells': cells}\n"
        "    if 0 <= index < len(shared['cells']) - 1:\n"
        "        return shared['cells'][index + 2]\n"
        "    return 0\n"
    )

    assert len(issues) == 1
    assert issues[0]["kind"] == "INDEX_ERROR"


def test_guarded_index_offset_ignores_access_within_guard_margin() -> None:
    """The same guard protects ``data[index+1]`` for a sequence of length three."""
    issues = find_guarded_index_offset(
        "def target(index: int) -> int:\n"
        "    data = [1, 2, 3]\n"
        "    if 0 <= index < len(data) - 1:\n"
        "        return data[index + 1]\n"
        "    return 0\n"
    )

    assert issues == []


def test_masked_zero_division_diagnostic_reports_guarded_zero_divisor() -> None:
    """The masked-zero fallback reports division inside a proven zero branch."""
    issues = find_masked_zero_division(
        "def target(x: int) -> int:\n"
        "    masked = x & 7\n"
        "    if masked == 0:\n"
        "        return 10 // masked\n"
        "    return 1\n"
    )

    assert len(issues) == 1
    assert issues[0]["kind"] == "DIVISION_BY_ZERO"
    assert issues[0]["function_name"] == "target"


def test_masked_zero_division_diagnostic_ignores_reassigned_divisor() -> None:
    """Reassigning the guarded variable before division clears the syntactic zero fact."""
    issues = find_masked_zero_division(
        "def target(x: int) -> int:\n"
        "    masked = x & 7\n"
        "    if masked == 0:\n"
        "        masked = 1\n"
        "        return 10 // masked\n"
        "    return 1\n"
    )

    assert issues == []


def test_equality_guarded_zero_division_reports_short_circuit_divisor() -> None:
    """An active equality guard proves subtraction of the guarded names is zero."""
    issues = find_equality_guarded_zero_division(
        "def target(a: int, b: int, c: int) -> int:\n"
        "    if a > 0 and c == b:\n"
        "        return 100 // (c - b)\n"
        "    return 1\n"
    )

    assert len(issues) == 1
    assert issues[0]["kind"] == "DIVISION_BY_ZERO"
    assert issues[0]["function_name"] == "target"
    assert "equality-guarded zero" in str(issues[0]["message"])


def test_equality_guarded_zero_division_ignores_reassigned_name() -> None:
    """Reassigning a guarded operand before division invalidates the equality fact."""
    issues = find_equality_guarded_zero_division(
        "def target(b: int, c: int) -> int:\n"
        "    if c == b:\n"
        "        c = b + 1\n"
        "        return 100 // (c - b)\n"
        "    return 1\n"
    )

    assert issues == []


def test_scan_file_emits_equality_guarded_zero_diagnostic(tmp_path: Path) -> None:
    """The scanner surfaces equality-guarded divisor diagnostics before execution."""
    target = tmp_path / "equality_zero.py"
    target.write_text(
        "def target(b: int, c: int) -> int:\n"
        "    if c == b:\n"
        "        return 100 // (c - b)\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, max_paths=20, timeout=2)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 3
        for issue in result.issues
    )


def test_self_canceling_zero_division_reports_dict_alias_subtraction() -> None:
    """Equivalent dictionary values subtracted through different keys are zero."""
    issues = find_self_canceling_zero_division(
        "def target(x: int) -> int:\n"
        "    divisor = 1\n"
        "    if x == 7:\n"
        "        aliases = {'left': x + 3, 'right': x + 3}\n"
        "        divisor = aliases['left'] - aliases['right']\n"
        "    return 10 // divisor\n"
    )

    assert len(issues) == 1
    assert issues[0]["kind"] == "DIVISION_BY_ZERO"
    assert issues[0]["function_name"] == "target"


def test_self_canceling_zero_division_ignores_reassigned_divisor() -> None:
    """A later concrete non-zero assignment clears a prior self-canceling fact."""
    issues = find_self_canceling_zero_division(
        "def target(x: int) -> int:\n"
        "    divisor = x - x\n"
        "    divisor = 1\n"
        "    return 10 // divisor\n"
    )

    assert issues == []


def test_runtime_trigger_dominates_same_site_syntactic_zero_diagnostic(
    tmp_path: Path,
) -> None:
    """A modeled runtime bug should replace the same-site no-trigger fallback."""
    target = tmp_path / "self_canceling_duplicate.py"
    target.write_text(
        "def target(x: int) -> int:\n    if x > 10:\n        return 1 // (x - x)\n    return x\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)
    matching = [
        issue
        for issue in result.issues
        if issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("line") == 3
    ]

    assert len(matching) == 1
    assert matching[0].get("counterexample")
