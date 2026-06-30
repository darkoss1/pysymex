"""Tests for pathlib scanner behavior."""

from __future__ import annotations

from pathlib import Path

from pysymex._internal.scanner.file import scan_file


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


def test_scan_file_reports_exact_pure_posix_suffixes_length_division(tmp_path: Path) -> None:
    target = tmp_path / "pathlib_suffixes_tar_division.py"
    target.write_text(
        "from pathlib import PurePosixPath\n\n"
        "def target(path: str) -> int:\n"
        "    suffixes = PurePosixPath(path).suffixes\n"
        "    if path == 'archive.tar.gz' and suffixes[-2:] == ['.tar', '.gz']:\n"
        "        return 100 // (len(suffixes) - 2)\n"
        "    return len(suffixes)\n",
        encoding="utf-8",
    )

    result = scan_file(target, use_sandbox=False)

    assert any(issue.get("kind") == "DIVISION_BY_ZERO" for issue in result.issues)
    assert "unsupported_slice_abstraction" not in result.degraded_passes
