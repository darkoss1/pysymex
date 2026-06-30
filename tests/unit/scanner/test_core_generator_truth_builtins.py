from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_generator_any_zero_division_with_bitwise_guard(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_any_zero_division.py"
    target.write_text(
        "from __future__ import annotations\n\n"
        "def target(a: int, b: int, c: int) -> int:\n"
        "    cells = [a - b, b - c, c - a]\n"
        "    alias = cells\n\n"
        "    def snapshot(seed: int) -> tuple[int, int, int]:\n"
        "        if (seed & 1) == 0:\n"
        "            alias[1] = alias[1] + seed - seed\n"
        "        else:\n"
        "            alias[2] = alias[2] - (seed & 1) + (seed & 1)\n"
        "        return (alias[0], alias[1], alias[2])\n\n"
        "    values = snapshot((a ^ b ^ c) & 3)\n"
        "    if any(item == 0 for item in values) and a == b and (c & 1) == 1:\n"
        "        return 90 // values[0]\n"
        "    return values[0] + values[1] + values[2]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, trace_enabled=False, timeout=30)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)


def test_scan_file_suppresses_generator_all_nonzero_false_positive(
    tmp_path: Path,
) -> None:
    target = tmp_path / "generator_all_nonzero_false_positive.py"
    target.write_text(
        "from __future__ import annotations\n\n"
        "def target(a: int, b: int, c: int) -> int:\n"
        "    values = (a - b, b - c, c - a)\n"
        "    if all(item != 0 for item in values) and a == b:\n"
        "        return 90 // values[0]\n"
        "    return values[0] + values[1] + values[2]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False, trace_enabled=False, timeout=30)

    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
