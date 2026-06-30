"""Scanner regressions for source-defined standard-library IntEnum members."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_preserves_literal_int_enum_member_zero_denominator(tmp_path: Path) -> None:
    target = tmp_path / "int_enum_zero_denominator.py"
    target.write_text(
        "from enum import IntEnum\n"
        "\n"
        "class Priority(IntEnum):\n"
        "    HIGH = 10\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    return value // (Priority.HIGH - 10)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO"
        and issue.get("function_name") == "target"
        and issue.get("line") == 7
        for issue in result.issues
    )
    assert not any(
        issue.get("kind") == "TYPE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_preserves_literal_qualified_int_enum_nonzero_denominator(
    tmp_path: Path,
) -> None:
    target = tmp_path / "int_enum_nonzero_denominator.py"
    target.write_text(
        "import enum\n"
        "\n"
        "class Priority(enum.IntEnum):\n"
        "    HIGH = 10\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    return value // (Priority.HIGH - 9)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "TYPE_ERROR"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_reports_invalid_literal_enum_construction(tmp_path: Path) -> None:
    target = tmp_path / "enum_invalid_value.py"
    target.write_text(
        "from enum import Enum\n"
        "\n"
        "class Direction(Enum):\n"
        "    NORTH = 1\n"
        "    EAST = 2\n"
        "\n"
        "def target(value: int) -> None:\n"
        "    Direction(value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "VALUE_ERROR"
        and issue.get("function_name") == "target"
        and "not a valid Direction" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_allows_guarded_literal_enum_construction(tmp_path: Path) -> None:
    target = tmp_path / "enum_guarded_value.py"
    target.write_text(
        "from enum import Enum\n"
        "\n"
        "class Direction(Enum):\n"
        "    NORTH = 1\n"
        "    EAST = 2\n"
        "\n"
        "def target(value: int) -> None:\n"
        "    if value == 1:\n"
        "        Direction(value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "VALUE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_respects_caught_literal_enum_value_error(tmp_path: Path) -> None:
    target = tmp_path / "enum_caught_value_error.py"
    target.write_text(
        "from enum import Enum\n"
        "\n"
        "class Direction(Enum):\n"
        "    NORTH = 1\n"
        "    EAST = 2\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    try:\n"
        "        Direction(value)\n"
        "    except ValueError:\n"
        "        return 0\n"
        "    return 1\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") == "VALUE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )
