from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_parse_qs_get_default_list_is_list_shaped(tmp_path: Path) -> None:
    target = tmp_path / "parse_qs_get_default_list_safe.py"
    target.write_text(
        "from urllib.parse import parse_qs\n\n"
        "def target(query: str) -> int:\n"
        "    params = parse_qs(query, keep_blank_values=True)\n"
        "    token = params.get('token', ['safe'])[0]\n"
        "    if token != '' and token != '0':\n"
        "        return 10 // len(token)\n"
        "    return len(token)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "NULL_DEREFERENCE", "INDEX_ERROR"}
        for issue in result.issues
    )
