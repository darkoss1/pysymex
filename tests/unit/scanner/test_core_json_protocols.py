"""Scanner regressions for stdlib JSON model precision."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pysymex
from pysymex.scanner.file import scan_file


def test_analyze_code_json_loads_literal_lookup_without_null_dereference() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            'import json\n\nresult = json.loads("{\\"x\\": 2}")["x"]\n',
            max_paths=35,
            max_depth=100,
            max_iterations=2200,
            timeout=2.0,
        )
    )

    assert not any(
        getattr(issue.kind, "name", issue.kind)
        in {"NULL_DEREFERENCE", "KEY_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR"}
        for issue in result.issues
    )
    assert "unsupported_subscript_abstraction" not in result.degraded_passes


def test_scan_file_json_loads_literal_lookup_without_null_dereference(tmp_path: Path) -> None:
    target = tmp_path / "json_loads_literal_lookup.py"
    target.write_text(
        "def target() -> int:\n"
        "    import json\n"
        "\n"
        '    result = json.loads("{\\"x\\": 2}")["x"]\n'
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"NULL_DEREFERENCE", "KEY_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR"}
        for issue in result.issues
    )
    assert "unsupported_subscript_abstraction" not in result.degraded_passes
