"""Tests for pathlib scanner behavior."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import cast

import pysymex
from pysymex.scanner.file import scan_file


def _issue_kind(issue: object) -> object:
    if isinstance(issue, dict):
        issue_map = cast("Mapping[str, object]", issue)
        return issue_map.get("kind")
    raw_kind = getattr(issue, "kind", None)
    return getattr(raw_kind, "name", raw_kind)


def test_analyze_code_models_pathlib_alias_pure_path_suffix() -> None:
    result = asyncio.run(
        pysymex.analyze_code(
            "import pathlib as pl\n\nresult = pl.PurePath('a/b.txt').suffix\n",
            max_paths=35,
            max_depth=100,
            max_iterations=2200,
            timeout=2.0,
        )
    )

    assert not any(
        _issue_kind(issue) in {"ATTRIBUTE_ERROR", "TYPE_ERROR", "NULL_DEREFERENCE", "NAME_ERROR"}
        for issue in result.issues
    )


def test_scan_file_models_pathlib_alias_pure_path_suffix(tmp_path: Path) -> None:
    target = tmp_path / "pathlib_alias_suffix.py"
    target.write_text(
        "def target() -> str:\n"
        "    import pathlib as pl\n"
        "\n"
        "    result = pl.PurePath('a/b.txt').suffix\n"
        "    return result\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(
        issue.get("kind") in {"ATTRIBUTE_ERROR", "TYPE_ERROR", "NULL_DEREFERENCE", "NAME_ERROR"}
        and issue.get("function_name") == "target"
        for issue in result.issues
    )


def test_scan_file_models_pure_posix_path_suffixes_without_runtime_noise(
    tmp_path: Path,
) -> None:
    target = tmp_path / "pathlib_property_candidate.py"
    target.write_text(
        "import ast\n"
        "from pathlib import PurePosixPath\n"
        "from typing import cast\n"
        "\n"
        "def warmup(source: str) -> object:\n"
        "    data = cast('object', ast.literal_eval(source))\n"
        "    if isinstance(data, list):\n"
        "        return data[3]\n"
        "    return 0\n"
        "\n"
        "def target(path: str) -> str:\n"
        "    suffixes = PurePosixPath(path).suffixes\n"
        "    if path.endswith('.tar.gz'):\n"
        "        return suffixes[2]\n"
        "    return ''\n"
        "\n"
        "def guarded(path: str) -> str:\n"
        "    suffixes = PurePosixPath(path).suffixes\n"
        "    if len(suffixes) > 2:\n"
        "        return suffixes[2]\n"
        "    return ''\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert result.error is None
    assert not any(issue.get("kind") == "RUNTIME_ERROR" for issue in result.issues)
    assert not any(
        issue.get("kind") in {"TYPE_ERROR", "ATTRIBUTE_ERROR"}
        and issue.get("function_name") == "guarded"
        for issue in result.issues
    )


def test_scan_file_allows_guarded_literal_eval_list_index(tmp_path: Path) -> None:
    target = tmp_path / "literal_eval_guarded.py"
    target.write_text(
        "import ast\n"
        "from typing import cast\n\n"
        "def target(source: str) -> object:\n"
        "    data = cast('object', ast.literal_eval(source))\n"
        "    if isinstance(data, list):\n"
        "        values = cast('list[object]', data)\n"
        "        if len(values) > 3:\n"
        "            return values[3]\n"
        "    return 0\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert not any(issue.get("function_name") == "target" for issue in result.issues)
