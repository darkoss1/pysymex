"""Scanner regressions for stdlib itertools protocol precision."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_itertools_chain_literals_without_type_error(tmp_path: Path) -> None:
    target = tmp_path / "itertools_chain_literals.py"
    target.write_text(
        "def target() -> int:\n"
        "    from itertools import chain\n"
        "\n"
        "    total = 0\n"
        "    for item in chain([1], [2, 3]):\n"
        "        total += item\n"
        "    result = total\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert "unmodeled_call_abstraction" not in result.degraded_passes
