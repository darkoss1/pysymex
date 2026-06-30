"""Scanner regressions for bounded typed ``NamedTuple`` classes."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


def test_scan_file_reads_annotation_only_named_tuple_fields(tmp_path: Path) -> None:
    target = tmp_path / "typed_named_tuple_zero.py"
    target.write_text(
        "from typing import NamedTuple\n"
        "\n"
        "class Point(NamedTuple):\n"
        "    x: int\n"
        "    y: int\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    point = Point(value, value)\n"
        "    return 10 // (point.x - point.y)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_allows_nonzero_annotation_only_named_tuple_expression(tmp_path: Path) -> None:
    target = tmp_path / "typed_named_tuple_nonzero.py"
    target.write_text(
        "import typing\n"
        "\n"
        "class Point(typing.NamedTuple):\n"
        "    x: int\n"
        "    y: int\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    point = Point(value, value)\n"
        "    return 10 // (point.x - point.y + 1)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"DIVISION_BY_ZERO", "ATTRIBUTE_ERROR"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_rejects_named_tuple_field_mutation(tmp_path: Path) -> None:
    target = tmp_path / "typed_named_tuple_mutation.py"
    target.write_text(
        "from typing import NamedTuple\n"
        "\n"
        "class Point(NamedTuple):\n"
        "    x: int\n"
        "\n"
        "def target(value: int) -> None:\n"
        "    point = Point(value)\n"
        "    point.x = value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_rejects_named_tuple_field_deletion(tmp_path: Path) -> None:
    target = tmp_path / "typed_named_tuple_delete.py"
    target.write_text(
        "from typing import NamedTuple\n"
        "\n"
        "class Point(NamedTuple):\n"
        "    x: int\n"
        "\n"
        "def target(value: int) -> None:\n"
        "    point = Point(value)\n"
        "    del point.x\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_rejects_invalid_named_tuple_constructor_arity(tmp_path: Path) -> None:
    target = tmp_path / "typed_named_tuple_missing_argument.py"
    target.write_text(
        "from typing import NamedTuple\n"
        "\n"
        "class Point(NamedTuple):\n"
        "    x: int\n"
        "    y: int\n"
        "\n"
        "def target(value: int) -> Point:\n"
        "    return Point(value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and "missing required argument 'y'" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_rejects_unexpected_named_tuple_keyword(tmp_path: Path) -> None:
    target = tmp_path / "typed_named_tuple_bad_keyword.py"
    target.write_text(
        "from typing import NamedTuple\n"
        "\n"
        "class Point(NamedTuple):\n"
        "    x: int\n"
        "\n"
        "def target(value: int) -> Point:\n"
        "    return Point(z=value)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(
        issue.get("kind") == "TYPE_ERROR"
        and issue.get("function_name") == "target"
        and "unexpected keyword argument 'z'" in str(issue.get("message"))
        for issue in result.issues
    )


def test_scan_file_reads_literal_namedtuple_factory_fields(tmp_path: Path) -> None:
    target = tmp_path / "literal_namedtuple_factory_zero.py"
    target.write_text(
        "from collections import namedtuple\n"
        "\n"
        "Point = namedtuple('Point', ['x', 'y'])\n"
        "\n"
        "def target(value: int) -> int:\n"
        "    point = Point(value, value)\n"
        "    return 10 // (point.x - point.y)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert any(
        issue.get("kind") == "DIVISION_BY_ZERO" and issue.get("function_name") == "target"
        for issue in result.issues
    )
    assert not any(issue.get("kind") == "ATTRIBUTE_ERROR" for issue in result.issues)


def test_scan_file_rejects_literal_namedtuple_field_mutation(tmp_path: Path) -> None:
    target = tmp_path / "literal_namedtuple_factory_mutation.py"
    target.write_text(
        "import collections\n"
        "\n"
        "Point = collections.namedtuple('Point', ('x',))\n"
        "\n"
        "def target(value: int) -> None:\n"
        "    point = Point(value)\n"
        "    point.x = value\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert "unmodeled_call_abstraction" not in result.degraded_passes
    assert any(
        issue.get("kind") == "ATTRIBUTE_ERROR" and issue.get("function_name") == "target"
        for issue in result.issues
    )
