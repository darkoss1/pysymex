"""Scanner regressions for extended statistics models."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_preserves_concrete_statistics_results(tmp_path: Path) -> None:
    target = tmp_path / "statistics_values.py"
    target.write_text(
        "import statistics\n"
        "\n"
        "def target() -> int:\n"
        "    center = int(statistics.fmean([2, 4, 6]))\n"
        "    popular = statistics.mode([1, 2, 2])\n"
        "    spread = int(statistics.pvariance([2, 4, 6]))\n"
        "    return 24 // (center + popular + spread)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert result.error is None
    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR", "VALUE_ERROR"}
        for issue in result.issues
    )
    assert not any(name.startswith("statistics.") for name in result.degraded_passes)
