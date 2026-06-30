"""Tests for pysymex._internal.pathing helpers."""

from __future__ import annotations

import os
from pathlib import Path

from pysymex._internal.pathing import normalize_input_path


def test_normalize_input_path_resolves_current_dir_windows_prefix(tmp_path: Path) -> None:
    """normalize_input_path resolves .\\-prefixed relative paths to existing files."""
    original_cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        target = tmp_path / "example.py"
        target.write_text("x = 1\n", encoding="utf-8")
        resolved = normalize_input_path(".\\example.py")
        assert resolved.resolve() == target.resolve()
    finally:
        os.chdir(original_cwd)


def test_normalize_input_path_keeps_path_instances(tmp_path: Path) -> None:
    """normalize_input_path preserves Path input values without lossy conversion."""
    target = tmp_path / "module.py"
    resolved = normalize_input_path(target)
    assert resolved == target


def test_normalize_input_path_converts_backslash_segments(tmp_path: Path) -> None:
    """normalize_input_path converts backslash separators for existing nested paths."""
    nested = tmp_path / "examples"
    nested.mkdir()
    target = nested / "insane_bugpack.py"
    target.write_text("x = 2\n", encoding="utf-8")
    input_value = str(target.relative_to(tmp_path)).replace("/", "\\")
    original_cwd = Path.cwd()
    try:
        os.chdir(tmp_path)
        resolved = normalize_input_path(input_value)
        assert resolved.resolve() == target.resolve()
    finally:
        os.chdir(original_cwd)


def test_ensure_pysymex_gitignore_creates_in_root(tmp_path: Path) -> None:
    """ensure_pysymex_gitignore generates .gitignore in the root .pysymex directory."""
    from pysymex._internal.pathing import ensure_pysymex_gitignore

    pysymex_dir = tmp_path / ".pysymex"
    pysymex_dir.mkdir()

    # Call on the .pysymex directory itself
    ensure_pysymex_gitignore(pysymex_dir)

    gitignore_path = pysymex_dir / ".gitignore"
    assert gitignore_path.exists()
    assert gitignore_path.read_text(encoding="utf-8") == "*\n"


def test_ensure_pysymex_gitignore_only_in_pysymex_root(tmp_path: Path) -> None:
    """ensure_pysymex_gitignore places .gitignore in .pysymex root, not in subdirectories."""
    from pysymex._internal.pathing import ensure_pysymex_gitignore

    pysymex_dir = tmp_path / ".pysymex"
    repro_dir = pysymex_dir / "reproduction"
    repro_dir.mkdir(parents=True)

    # Call on the subdirectory
    ensure_pysymex_gitignore(repro_dir)

    # Check that gitignore is in .pysymex and not in reproduction
    root_gitignore = pysymex_dir / ".gitignore"
    sub_gitignore = repro_dir / ".gitignore"

    assert root_gitignore.exists()
    assert root_gitignore.read_text(encoding="utf-8") == "*\n"
    assert not sub_gitignore.exists()


def test_ensure_pysymex_gitignore_does_not_overwrite(tmp_path: Path) -> None:
    """ensure_pysymex_gitignore does not overwrite an already existing .gitignore."""
    from pysymex._internal.pathing import ensure_pysymex_gitignore

    pysymex_dir = tmp_path / ".pysymex"
    pysymex_dir.mkdir()

    gitignore_path = pysymex_dir / ".gitignore"
    gitignore_path.write_text("existing_content\n", encoding="utf-8")

    ensure_pysymex_gitignore(pysymex_dir)

    assert gitignore_path.read_text(encoding="utf-8") == "existing_content\n"
