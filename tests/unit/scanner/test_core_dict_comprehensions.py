from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import cast

from pysymex._internal.scanner.file import scan_file


def _assert_no_issue_kinds(result: object, forbidden: set[str]) -> None:
    issues = getattr(result, "issues", [])
    assert not any(_issue_kind(issue) in forbidden for issue in issues)


def _issue_kind(issue: object) -> object:
    if isinstance(issue, dict):
        issue_map = cast("Mapping[str, object]", issue)
        return issue_map.get("kind")
    raw_kind = getattr(issue, "kind", None)
    return getattr(raw_kind, "name", raw_kind)


def test_scan_file_dict_comprehension_retains_concrete_integer_keys(tmp_path: Path) -> None:
    target = tmp_path / "dict_comprehension_lookup.py"
    target.write_text(
        "def target() -> int:\n"
        "    mapping = {x: x + 1 for x in [1, 2]}\n"
        "    result = mapping[2]\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    _assert_no_issue_kinds(
        result,
        {"KEY_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR", "NAME_ERROR", "UNBOUND_VARIABLE"},
    )
