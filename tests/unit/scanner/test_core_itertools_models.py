"""Scanner regressions for exact finite itertools models."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_preserves_combinations_and_islice_values(tmp_path: Path) -> None:
    target = tmp_path / "itertools_values.py"
    target.write_text(
        "from itertools import combinations, islice\n"
        "\n"
        "def target() -> int:\n"
        "    pairs = list(combinations([1, 2, 3], 2))\n"
        "    head = list(islice([10, 20, 30], 2))\n"
        "    return pairs[2][1] + head[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert result.error is None
    assert not any(
        issue.get("kind") in {"INDEX_ERROR", "TYPE_ERROR", "ATTRIBUTE_ERROR"}
        for issue in result.issues
    )
    assert "itertools.combinations" not in result.degraded_passes
    assert "itertools.islice" not in result.degraded_passes
