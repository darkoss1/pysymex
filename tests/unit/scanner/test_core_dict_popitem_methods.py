"""Scanner regressions for dict.popitem() mutation and exception precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def _has_issue_kind(result: object, function_name: str, kind: str) -> bool:
    issues = getattr(result, "issues")
    return any(
        issue.get("kind") == kind and issue.get("function_name") == function_name
        for issue in issues
    )


def test_scan_file_dict_popitem_nonempty_does_not_report_key_error(tmp_path: Path) -> None:
    target = tmp_path / "dict_popitem_nonempty.py"
    target.write_text(
        "def target(x: int) -> int:\n"
        "    data = {'k': x}\n"
        "    _key, value = data.popitem()\n"
        "    return value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not _has_issue_kind(result, "target", "KEY_ERROR")


def test_scan_file_alias_dict_popitem_after_drain_reports_key_error_and_division(
    tmp_path: Path,
) -> None:
    target = tmp_path / "alias_dict_popitem_after_drain.py"
    target.write_text(
        "def target(x: int, y: int) -> int:\n"
        "    data = {'left': x, 'right': y}\n"
        "    alias = data\n"
        "\n"
        "    def drain(mode: int) -> int:\n"
        "        if mode == 0:\n"
        "            alias.clear()\n"
        "        else:\n"
        "            alias.pop('left', None)\n"
        "            alias.pop('right', None)\n"
        "        return len(alias)\n"
        "\n"
        "    remaining = drain((x ^ y) & 1)\n"
        "    if x == y and remaining == 0:\n"
        "        return 100 // (x - y)\n"
        "\n"
        "    _key, value = data.popitem()\n"
        "    return value + remaining\n",
        encoding="utf-8",
    )

    result = scan_file(
        target,
        use_sandbox=False,
        max_paths=400,
        timeout=20,
    )

    assert _has_issue_kind(result, "target", "DIVISION_BY_ZERO")
    assert _has_issue_kind(result, "target", "KEY_ERROR")
