"""Scanner regressions for broadly used pure math functions."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_preserves_concrete_extended_math_results(tmp_path: Path) -> None:
    target = tmp_path / "extended_math_values.py"
    target.write_text(
        "import math\n"
        "\n"
        "def target() -> int:\n"
        "    choices = math.comb(5, 2)\n"
        "    product = math.prod([2, 3])\n"
        "    distance = int(math.dist((0, 0), (3, 4)))\n"
        "    return 300 // (choices * product) + distance\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert result.error is None
    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR", "VALUE_ERROR"}
        for issue in result.issues
    )
    assert not any(name.startswith("math.") for name in result.degraded_passes)
