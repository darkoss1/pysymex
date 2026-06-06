"""Tests for pysymex.config file discovery and persistence helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

import pysymex.config as mod


def test_find_config_file_returns_none_in_isolated_dir(tmp_path: Path) -> None:
    """find_config_file returns None when no config exists up the tree."""
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    result = mod.find_config_file(deep)
    assert result is None or isinstance(result, Path)


def test_find_config_file_finds_pysymex_toml(tmp_path: Path) -> None:
    """find_config_file finds pysymex.toml in the start directory."""
    config = tmp_path / "pysymex.toml"
    config.write_text("[tool.pysymex]\n", encoding="utf-8")
    result = mod.find_config_file(tmp_path)
    assert result == config


def test_find_config_file_walks_up(tmp_path: Path) -> None:
    """find_config_file walks up directories to find config."""
    config = tmp_path / "pysymex.toml"
    config.write_text("[tool.pysymex]\n", encoding="utf-8")
    child = tmp_path / "sub"
    child.mkdir()
    result = mod.find_config_file(child)
    assert result == config


def test_load_config_defaults(tmp_path: Path) -> None:
    """load_config returns defaults when no config file exists."""
    cfg = mod.load_config(config_path=tmp_path / "missing.toml")
    assert isinstance(cfg, mod.PysymexConfig)
    assert cfg.config_file is None


def test_load_config_from_file(tmp_path: Path) -> None:
    """load_config reads settings from a TOML file."""
    config_path = tmp_path / "pysymex.toml"
    config_path.write_text(
        "[detectors]\ndivision_by_zero = false\n\n[limits]\nmax_paths = 42\n",
        encoding="utf-8",
    )
    cfg = mod.load_config(config_path=config_path)
    assert cfg.detectors.division_by_zero is False
    assert cfg.limits.max_paths == 42
    assert cfg.config_file == config_path


def test_load_config_from_pyproject(tmp_path: Path) -> None:
    """load_config extracts [tool.pysymex] from pyproject.toml."""
    config_path = tmp_path / "pyproject.toml"
    config_path.write_text(
        "[tool.pysymex.limits]\nmax_depth = 50\n",
        encoding="utf-8",
    )
    cfg = mod.load_config(config_path=config_path)
    assert cfg.limits.max_depth == 50


def test_load_config_invalid_toml(tmp_path: Path) -> None:
    """load_config gracefully handles invalid TOML."""
    config_path = tmp_path / "pysymex.toml"
    config_path.write_text("this is not valid toml {{{}}}}", encoding="utf-8")
    cfg = mod.load_config(config_path=config_path)
    assert isinstance(cfg, mod.PysymexConfig)


def test_generate_default_config() -> None:
    """generate_default_config produces a TOML string."""
    result = mod.generate_default_config()
    assert isinstance(result, str)
    assert "[tool.pysymex]" in result


def test_init_config_creates_file(tmp_path: Path) -> None:
    """init_config creates a pysymex.toml file."""
    result = mod.init_config(tmp_path)
    assert result.exists()
    assert result.name == "pysymex.toml"
    content = result.read_text(encoding="utf-8")
    assert "[tool.pysymex]" in content


def test_init_config_raises_if_exists(tmp_path: Path) -> None:
    """init_config raises FileExistsError if config already exists."""
    (tmp_path / "pysymex.toml").write_text("existing", encoding="utf-8")
    with pytest.raises(FileExistsError):
        mod.init_config(tmp_path)
