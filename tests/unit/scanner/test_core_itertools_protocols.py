"""Scanner regressions for stdlib itertools protocol precision."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pysymex
from pysymex.scanner.file import scan_file


def test_analyze_code_itertools_chain_literals_without_type_error() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "from itertools import chain\n"
            "\n"
            "total = 0\n"
            "for item in chain([1], [2, 3]):\n"
            "    total += item\n"
            "result = total\n",
            max_paths=35,
            max_depth=100,
            max_iterations=2200,
            timeout=2.0,
        )
    )

    assert not any(
        getattr(issue.kind, "name", issue.kind) == "TYPE_ERROR" for issue in result.issues
    )
    assert "unmodeled_call_abstraction" not in result.degraded_passes


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
