"""Tests for scanner handling of annotated local classes."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_missing_attribute_on_annotated_local_class(
    tmp_path: Path,
) -> None:
    target = tmp_path / "annotated_object_attribute.py"
    target.write_text(
        "class Account:\n"
        "    def __init__(self, balance: int) -> None:\n"
        "        self.balance = balance\n\n"
        "def target(account: Account) -> int:\n"
        "    return account.limit\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 6
        for issue in result.issues
    )


def test_scan_file_uses_constructor_attribute_on_annotated_local_class(
    tmp_path: Path,
) -> None:
    target = tmp_path / "annotated_object_constructor_attr.py"
    target.write_text(
        "class Account:\n"
        "    def __init__(self, balance: int) -> None:\n"
        "        self.balance = balance\n\n"
        "def target(account: Account) -> int:\n"
        "    return 10 // account.balance\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 6
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)
