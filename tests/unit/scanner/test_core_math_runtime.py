"""Tests for scanner runtime handling of mathematical models."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reports_math_sqrt_domain_value_error(tmp_path: Path) -> None:
    """Math domain models should report feasible errors without guarded false positives."""
    target = tmp_path / "math_sqrt_domain.py"
    target.write_text(
        "import math\n"
        "\n"
        "def sink(x: int) -> float:\n"
        "    if x > 0:\n"
        "        x = -x\n"
        "    return math.sqrt(x)\n"
        "\n"
        "def control(x: int) -> float:\n"
        "    if x < 0:\n"
        "        x = -x\n"
        "    return math.sqrt(x)\n"
        "\n"
        "def log_sink(x: int) -> float:\n"
        "    if x > 0:\n"
        "        x = -x\n"
        "    return math.log(x)\n"
        "\n"
        "def log_control(x: int) -> float:\n"
        "    if x <= 0:\n"
        "        x = 1\n"
        "    return math.log(x)\n"
        "\n"
        "def log_base_sink(x: int, base: int) -> float:\n"
        "    if x <= 0:\n"
        "        x = 1\n"
        "    return math.log(x, base)\n"
        "\n"
        "def log_base_control(x: int, base: int) -> float:\n"
        "    if x <= 0:\n"
        "        x = 1\n"
        "    if base <= 1:\n"
        "        base = 2\n"
        "    return math.log(x, base)\n"
        "\n"
        "def exp_sink(x: int) -> float:\n"
        "    if x < 710:\n"
        "        x = 710\n"
        "    return math.exp(x)\n"
        "\n"
        "def exp_control(x: int) -> float:\n"
        "    if x > 709:\n"
        "        x = 709\n"
        "    return math.exp(x)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and issue.get("function_name") == "sink"
        and issue.get("line") == 6
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "VALUE_ERROR"
        and issue.get("function_name") == "control"
        and issue.get("line") == 11
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and issue.get("function_name") == "log_sink"
        and issue.get("line") == 16
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "VALUE_ERROR"
        and issue.get("function_name") == "log_control"
        and issue.get("line") == 21
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and issue.get("function_name") == "log_base_sink"
        and issue.get("line") == 26
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "log_base_sink"
        and issue.get("line") == 26
        for issue in result.issues
    )
    assert not any(
        issue.get("function_name") == "log_base_control"
        and issue.get("line") == 33
        and issue.get("kind") in {"VALUE_ERROR", "DIVISION_BY_ZERO"}
        for issue in result.issues
    )
    assert any(
        issue.get("kind") == "OVERFLOW"
        and issue.get("function_name") == "exp_sink"
        and issue.get("line") == 38
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "OVERFLOW"
        and issue.get("function_name") == "exp_control"
        and issue.get("line") == 44
        for issue in result.issues
    )
