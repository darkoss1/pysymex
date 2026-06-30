"""Scanner regressions for symbolic list mutation and read-after-write semantics."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_symbolic_list_mutation_bug(tmp_path: Path) -> None:
    target = tmp_path / "039_assert_symbolic_list_mutation_bug.py"
    target.write_text(
        "def case(xs: list[int]) -> int:\n"
        "    assert True\n"
        "    if len(xs) >= 1:\n"
        "        xs[0] = xs[0] + 1\n"
        "        if xs[0] == 5:\n"
        "            assert False\n"
        "    return len(xs)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert _has_issue_kind(result, "case", "ASSERTION_ERROR")


def test_scan_file_symbolic_list_mutation_safe(tmp_path: Path) -> None:
    target = tmp_path / "040_assert_symbolic_list_mutation_safe.py"
    target.write_text(
        "def case(xs: list[int]) -> int:\n"
        "    assert True\n"
        "    if len(xs) >= 1:\n"
        "        old = xs[0]\n"
        "        xs[0] = old + 1\n"
        "        assert xs[0] == old + 1\n"
        "    return len(xs)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "case", "ASSERTION_ERROR")


def test_scan_file_symbolic_list_append_raw_int(tmp_path: Path) -> None:
    target = tmp_path / "041_assert_symbolic_list_append_raw_int.py"
    target.write_text(
        "def case(xs: list[int]) -> int:\n"
        "    assert True\n"
        "    old_len = len(xs)\n"
        "    xs.append(5)\n"
        "    assert xs[old_len] == 5\n"
        "    return len(xs)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "case", "ASSERTION_ERROR")
