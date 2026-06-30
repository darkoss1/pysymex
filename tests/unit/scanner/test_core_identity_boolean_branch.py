from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(issue.get("kind") == kind for issue in issues)


def test_scan_file_reports_division_after_true_identity_branch(tmp_path: Path) -> None:
    target = tmp_path / "true_identity_branch.py"
    target.write_text(
        "def target() -> int:\n"
        "    flag = True\n"
        "    if flag is True:\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "DIVISION_BY_ZERO")


def test_scan_file_does_not_treat_int_one_as_true_singleton(tmp_path: Path) -> None:
    target = tmp_path / "int_one_identity_branch.py"
    target.write_text(
        "def target() -> int:\n"
        "    flag = 1\n"
        "    if flag is True:\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "DIVISION_BY_ZERO")


def test_scan_file_reports_division_after_match_true_singleton(tmp_path: Path) -> None:
    target = tmp_path / "match_true_singleton.py"
    target.write_text(
        "def target(mode: int) -> int:\n"
        "    subject = (mode, True, 1)\n"
        "    match subject:\n"
        "        case (1, True, _):\n"
        "            return 1 // 0\n"
        "        case _:\n"
        "            return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 5
        for issue in result.issues
    )


def test_scan_file_preserves_repeated_symbolic_id_equality(tmp_path: Path) -> None:
    target = tmp_path / "repeated_id_safe.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    if id(value) != id(value):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert not _has_issue_kind(result, "DIVISION_BY_ZERO")


def test_scan_file_reaches_equal_symbolic_id_branch(tmp_path: Path) -> None:
    target = tmp_path / "repeated_id_bug.py"
    target.write_text(
        "def target(value: int) -> int:\n"
        "    if id(value) == id(value):\n"
        "        return 1 // 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, no_cache=True)

    assert _has_issue_kind(result, "DIVISION_BY_ZERO")
