"""Scanner regression for heap-backed collections.Counter behavior."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_preserves_counter_queries_defaults_and_mutation(tmp_path: Path) -> None:
    target = tmp_path / "counter_values.py"
    target.write_text(
        "from collections import Counter\n"
        "\n"
        "def target() -> int:\n"
        "    counts = Counter('aba')\n"
        "    counts.update('bc')\n"
        "    top = counts.most_common(1)\n"
        "    return counts['a'] + counts['b'] + counts['missing'] + top[0][1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert result.error is None
    assert not any(
        issue.get("kind") in {"KEY_ERROR", "INDEX_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR"}
        for issue in result.issues
    )
    assert not any("Counter" in name for name in result.degraded_passes)
