"""Scanner regressions for mutable container alias propagation."""

from __future__ import annotations

from pathlib import Path

from pysymex.config import is_object_dict
from pysymex.scanner.types import IssueRecord
from pysymex.scanner.file import scan_file


def _counterexample_value(issue: IssueRecord, name: str) -> object:
    counterexample = issue.get("counterexample")
    if not is_object_dict(counterexample):
        return None
    return counterexample.get(name)


def test_scan_file_detects_helper_mutated_dict_alias(tmp_path: Path) -> None:
    """Mutating a dict parameter should refresh caller aliases of the same object."""
    target = tmp_path / "helper_dict_alias_bug.py"
    target.write_text(
        "def mutate_limit(cfg: dict[str, int], value: int) -> None:\n"
        "    cfg['limit'] = value\n"
        "\n"
        "def target(override_value: int) -> int:\n"
        "    cfg = {'limit': 1}\n"
        "    backup = cfg\n"
        "    mutate_limit(cfg, override_value)\n"
        "    return 100 // backup['limit']\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 8
        and _counterexample_value(issue, "override_value") == 0
        for issue in result.issues
    )


def test_scan_file_respects_guard_after_helper_mutated_dict_alias(tmp_path: Path) -> None:
    """A guard through the alias should prevent a false division report."""
    target = tmp_path / "helper_dict_alias_safe.py"
    target.write_text(
        "def mutate_limit(cfg: dict[str, int], value: int) -> None:\n"
        "    cfg['limit'] = value\n"
        "\n"
        "def target(override_value: int) -> int:\n"
        "    cfg = {'limit': 1}\n"
        "    backup = cfg\n"
        "    mutate_limit(cfg, override_value)\n"
        "    if backup['limit'] == 0:\n"
        "        return 0\n"
        "    return 100 // backup['limit']\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 10
        for issue in result.issues
    )


def test_scan_file_keeps_dict_constructor_copy_independent(tmp_path: Path) -> None:
    """Deleting from dict(table) must not delete the original table key."""
    target = tmp_path / "dict_constructor_copy.py"
    target.write_text(
        "def target() -> int:\n"
        "    table = {'k': 1}\n"
        "    alias = dict(table)\n"
        "    del alias['k']\n"
        "    return table['k']\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "KEY_ERROR"
        and issue.get("function_name") == "target"
        and issue.get("line") == 5
        for issue in result.issues
    )
