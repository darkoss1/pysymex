"""Scanner regressions for generator protocol edge cases."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pysymex
from pysymex.scanner.file import scan_file


def test_modeled_generator_import_has_no_cycle() -> None:
    from pysymex.execution.opcodes.common.generators import ModeledGenerator

    assert ModeledGenerator.__name__ == "ModeledGenerator"


def test_scan_file_unpacks_literal_generator_without_type_error(tmp_path: Path) -> None:
    target = tmp_path / "literal_generator_unpack.py"
    target.write_text(
        "def target() -> int:\n"
        "    def gen():\n"
        "        yield 1\n"
        "        yield 2\n"
        "\n"
        "    left, right = gen()\n"
        "    return left + right\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert "unsupported_generator" not in result.degraded_passes


def test_analyze_code_yield_from_literal_list_without_type_error() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "def make_items():\n"
            "    yield from [2, 3]\n"
            "\n"
            "total = 0\n"
            "for item in make_items():\n"
            "    total += item\n"
            "result = total\n",
            max_paths=35,
            max_depth=90,
            max_iterations=1800,
            timeout=2.0,
        )
    )

    assert not any(
        getattr(issue.kind, "name", issue.kind) == "TYPE_ERROR" for issue in result.issues
    )
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_yield_from_literal_list_without_type_error(tmp_path: Path) -> None:
    target = tmp_path / "yield_from_literal_list.py"
    target.write_text(
        "def target() -> int:\n"
        "    def make_items():\n"
        "        yield from [2, 3]\n"
        "\n"
        "    total = 0\n"
        "    for item in make_items():\n"
        "        total += item\n"
        "    result = total\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("kind") == "TYPE_ERROR" for issue in result.issues)
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_preserves_generator_return_stopiteration_value(tmp_path: Path) -> None:
    target = tmp_path / "generator_return_value.py"
    target.write_text(
        "def target() -> int:\n"
        "    def gen():\n"
        "        yield 1\n"
        "        return 4\n"
        "\n"
        "    generator = gen()\n"
        "    first = next(generator)\n"
        "    try:\n"
        "        next(generator)\n"
        "    except StopIteration as exc:\n"
        "        result = first + exc.value\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"} for issue in result.issues
    )
    assert "unsupported_generator" not in result.degraded_passes


def test_scan_file_generator_close_degrades_without_attribute_error(tmp_path: Path) -> None:
    target = tmp_path / "generator_close.py"
    target.write_text(
        "def target() -> int:\n"
        "    events = []\n"
        "\n"
        "    def gen():\n"
        "        try:\n"
        "            yield 1\n"
        "        finally:\n"
        "            events.append('closed')\n"
        "\n"
        "    generator = gen()\n"
        "    first = next(generator)\n"
        "    generator.close()\n"
        "    return first + len(events)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"} for issue in result.issues
    )
    assert "unsupported_generator" in result.degraded_passes


def test_scan_file_generator_throw_degrades_without_attribute_error(tmp_path: Path) -> None:
    target = tmp_path / "generator_throw.py"
    target.write_text(
        "def target() -> int:\n"
        "    def gen():\n"
        "        try:\n"
        "            yield 1\n"
        "        except ValueError:\n"
        "            yield 3\n"
        "\n"
        "    generator = gen()\n"
        "    first = next(generator)\n"
        "    second = generator.throw(ValueError)\n"
        "    return first + second\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR"} for issue in result.issues
    )
    assert "unsupported_generator" in result.degraded_passes
