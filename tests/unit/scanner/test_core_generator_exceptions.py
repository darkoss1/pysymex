"""Scanner regressions for generator exception propagation."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_routes_next_generator_predicate_exception_to_handler(
    tmp_path: Path,
) -> None:
    target = tmp_path / "next_generator_predicate_exception.py"
    target.write_text(
        "def _gate(value: int, flag: int) -> int:\n"
        "    if flag == 1 and value == 0:\n"
        "        raise LookupError('masked zero')\n"
        "    return value + 1\n"
        "\n"
        "def target(a: int, b: int, c: int) -> int:\n"
        "    values = [a - b, b - c]\n"
        "    denominator = 3\n"
        "    try:\n"
        "        denominator = next((_gate(item, c) for item in values), 5)\n"
        "    except LookupError:\n"
        "        denominator = values[0]\n"
        "    if a == b and c == 1:\n"
        "        return 180 // denominator\n"
        "    return denominator + values[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)


def test_scan_file_keeps_safe_next_generator_predicate_exception_handler(
    tmp_path: Path,
) -> None:
    target = tmp_path / "next_generator_predicate_exception_safe.py"
    target.write_text(
        "def _gate(value: int, flag: int) -> int:\n"
        "    if flag == 1 and value == 0:\n"
        "        raise LookupError('masked zero')\n"
        "    return value + 1\n"
        "\n"
        "def target(a: int, b: int, c: int) -> int:\n"
        "    values = [a - b, b - c]\n"
        "    denominator = 3\n"
        "    try:\n"
        "        denominator = next((_gate(item, c) for item in values), 5)\n"
        "    except LookupError:\n"
        "        denominator = values[0] + 1\n"
        "    if a == b and c == 1 and denominator == 0:\n"
        "        return 180 // denominator\n"
        "    if denominator != 0:\n"
        "        return 180 // denominator\n"
        "    return values[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)


def test_scan_file_routes_nested_generator_predicate_exception_to_handler(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nested_generator_predicate_exception.py"
    target.write_text(
        "def _gate(value: int, flag: int) -> bool:\n"
        "    if flag == 1 and value == 0:\n"
        "        raise LookupError('masked zero')\n"
        "    return value == 0\n"
        "\n"
        "def _wrap(value: int, flag: int, salt: int) -> bool:\n"
        "    return _gate(value, flag) or salt == 7\n"
        "\n"
        "def target(a: int, b: int, c: int) -> int:\n"
        "    values = [a - b, b - c]\n"
        "    denominator = 5\n"
        "    try:\n"
        "        if any(_wrap(item, c, b) for item in values):\n"
        "            denominator = 1\n"
        "    except LookupError:\n"
        "        denominator = values[0]\n"
        "    if a == b and c == 1:\n"
        "        return 240 // denominator\n"
        "    return denominator + values[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)


def test_scan_file_keeps_safe_nested_generator_predicate_exception_handler(
    tmp_path: Path,
) -> None:
    target = tmp_path / "nested_generator_predicate_exception_safe.py"
    target.write_text(
        "def _gate(value: int, flag: int) -> bool:\n"
        "    if flag == 1 and value == 0:\n"
        "        raise LookupError('masked zero')\n"
        "    return value == 0\n"
        "\n"
        "def _wrap(value: int, flag: int, salt: int) -> bool:\n"
        "    return _gate(value, flag) or salt == 7\n"
        "\n"
        "def target(a: int, b: int, c: int) -> int:\n"
        "    values = [a - b, b - c]\n"
        "    denominator = 5\n"
        "    try:\n"
        "        if any(_wrap(item, c, b) for item in values):\n"
        "            denominator = 1\n"
        "    except LookupError:\n"
        "        denominator = values[0] + 1\n"
        "    if a == b and c == 1 and denominator == 0:\n"
        "        return 240 // denominator\n"
        "    if denominator != 0:\n"
        "        return 240 // denominator\n"
        "    return values[1]\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unsupported_generator" not in result.degraded_passes
    assert not any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert not any(issue.get("kind") == "UNHANDLED_EXCEPTION" for issue in result.issues)
