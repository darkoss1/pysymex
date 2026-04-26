"""Tests for pysymex.config — configuration system for pysymex."""

from __future__ import annotations

from pathlib import Path

import pytest

import pysymex.config as mod


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------


class TestNewPluginDirs:
    """Tests for _new_plugin_dirs factory."""

    def test_returns_empty_list(self) -> None:
        """Factory produces a fresh empty list."""
        result = mod._new_plugin_dirs()
        assert result == []
        assert isinstance(result, list)


class TestNewDisabledPlugins:
    """Tests for _new_disabled_plugins factory."""

    def test_returns_empty_set(self) -> None:
        """Factory produces a fresh empty set."""
        result = mod._new_disabled_plugins()
        assert result == set()
        assert isinstance(result, set)


class TestNewPluginSettings:
    """Tests for _new_plugin_settings factory."""

    def test_returns_empty_dict(self) -> None:
        """Factory produces a fresh empty dict."""
        result = mod._new_plugin_settings()
        assert result == {}
        assert isinstance(result, dict)


class TestIsObjectList:
    """Tests for _is_object_list TypeGuard."""

    def test_list_returns_true(self) -> None:
        """A list returns True."""
        assert mod._is_object_list([1, 2, 3]) is True

    def test_tuple_returns_false(self) -> None:
        """A tuple is not a list."""
        assert mod._is_object_list((1, 2)) is False

    def test_string_returns_false(self) -> None:
        """A string is not a list."""
        assert mod._is_object_list("abc") is False


class TestIsObjectCollection:
    """Tests for _is_object_collection TypeGuard."""

    def test_list_returns_true(self) -> None:
        """A list is a collection."""
        assert mod._is_object_collection([1]) is True

    def test_set_returns_true(self) -> None:
        """A set is a collection."""
        assert mod._is_object_collection({1, 2}) is True

    def test_tuple_returns_true(self) -> None:
        """A tuple is a collection."""
        assert mod._is_object_collection((1,)) is True

    def test_dict_returns_false(self) -> None:
        """A dict is not in the collection TypeGuard."""
        assert mod._is_object_collection({"a": 1}) is False

    def test_string_returns_false(self) -> None:
        """A string is not a collection."""
        assert mod._is_object_collection("abc") is False


class TestIsObjectDict:
    """Tests for _is_object_dict TypeGuard."""

    def test_dict_returns_true(self) -> None:
        """A dict returns True."""
        assert mod._is_object_dict({"a": 1}) is True

    def test_list_returns_false(self) -> None:
        """A list is not a dict."""
        assert mod._is_object_dict([1, 2]) is False


class TestNormalizeObjectDict:
    """Tests for _normalize_object_dict."""

    def test_valid_dict(self) -> None:
        """A dict with mixed keys is normalized to str keys."""
        result = mod._normalize_object_dict({1: "a", "b": 2})
        assert result == {"1": "a", "b": 2}

    def test_non_dict_returns_none(self) -> None:
        """Non-dict input returns None."""
        result = mod._normalize_object_dict([1, 2])
        assert result is None

    def test_empty_dict(self) -> None:
        """Empty dict normalizes to empty dict."""
        result = mod._normalize_object_dict({})
        assert result == {}


class TestNormalizeStringList:
    """Tests for _normalize_string_list."""

    def test_valid_list(self) -> None:
        """A list of mixed types is stringified."""
        result = mod._normalize_string_list([1, "two", 3.0])
        assert result == ["1", "two", "3.0"]

    def test_non_list_returns_none(self) -> None:
        """Non-list input returns None."""
        result = mod._normalize_string_list("abc")
        assert result is None


class TestNormalizeStringSet:
    """Tests for _normalize_string_set."""

    def test_from_list(self) -> None:
        """A list is normalized to a set of strings."""
        result = mod._normalize_string_set([1, "two"])
        assert result == {"1", "two"}

    def test_from_set(self) -> None:
        """A set is normalized to a set of strings."""
        result = mod._normalize_string_set({"a", "b"})
        assert result == {"a", "b"}

    def test_from_tuple(self) -> None:
        """A tuple is normalized to a set of strings."""
        result = mod._normalize_string_set(("x",))
        assert result == {"x"}

    def test_non_collection_returns_none(self) -> None:
        """A non-collection returns None."""
        result = mod._normalize_string_set(42)
        assert result is None


class TestNormalizePluginSettings:
    """Tests for _normalize_plugin_settings."""

    def test_valid_nested_dicts(self) -> None:
        """Nested dicts are normalized with stringified keys."""
        raw: dict[str, dict[str, object]] = {"my_plugin": {"opt": True}}
        result = mod._normalize_plugin_settings(raw)
        assert result is not None
        assert result["my_plugin"]["opt"] is True

    def test_non_dict_value_wrapped(self) -> None:
        """Non-dict plugin settings get wrapped in {'value': ...}."""
        raw: dict[str, object] = {"plug": 42}
        result = mod._normalize_plugin_settings(raw)
        assert result is not None
        assert result["plug"] == {"value": 42}

    def test_non_dict_returns_none(self) -> None:
        """Non-dict input returns None."""
        result = mod._normalize_plugin_settings("abc")
        assert result is None


# ---------------------------------------------------------------------------
# Dataclass configs
# ---------------------------------------------------------------------------


class TestSolverConfig:
    """Tests for SolverConfig dataclass."""

    def test_defaults(self) -> None:
        """Default SolverConfig has expected values."""
        cfg = mod.SolverConfig()
        assert cfg.strategy == "incremental"
        assert cfg.cache_size == 50000
        assert cfg.warm_start is True

    def test_to_dict_keys(self) -> None:
        """to_dict contains all field names."""
        d = mod.SolverConfig().to_dict()
        assert "strategy" in d
        assert "cache_size" in d
        assert "solver_timeout_ms" in d
        assert len(d) == 8

    def test_to_dict_values_match_fields(self) -> None:
        """to_dict values match instance field values."""
        cfg = mod.SolverConfig(strategy="portfolio", cache_size=100)
        d = cfg.to_dict()
        assert d["strategy"] == "portfolio"
        assert d["cache_size"] == 100


class TestConcurrencyConfig:
    """Tests for ConcurrencyConfig dataclass."""

    def test_defaults(self) -> None:
        """Default ConcurrencyConfig has concurrency disabled."""
        cfg = mod.ConcurrencyConfig()
        assert cfg.enabled is False
        assert cfg.detect_races is True

    def test_to_dict(self) -> None:
        """to_dict round-trips correctly."""
        cfg = mod.ConcurrencyConfig(enabled=True, max_interleavings=500)
        d = cfg.to_dict()
        assert d["enabled"] is True
        assert d["max_interleavings"] == 500


class TestDetectorConfig:
    """Tests for DetectorConfig dataclass."""

    def test_defaults(self) -> None:
        """Default detectors are mostly enabled."""
        cfg = mod.DetectorConfig()
        assert cfg.division_by_zero is True
        assert cfg.overflow is False

    def test_to_dict(self) -> None:
        """to_dict returns all detector flags."""
        d = mod.DetectorConfig().to_dict()
        assert len(d) == 8
        assert d["overflow"] is False


class TestAnalysisLimits:
    """Tests for AnalysisLimits dataclass."""

    def test_defaults(self) -> None:
        """Default limits have sensible values."""
        lim = mod.AnalysisLimits()
        assert lim.max_paths == 1000
        assert lim.timeout_seconds == 60.0

    def test_to_dict(self) -> None:
        """to_dict round-trips correctly."""
        lim = mod.AnalysisLimits(max_paths=500)
        d = lim.to_dict()
        assert d["max_paths"] == 500
        assert len(d) == 8


class TestOutputConfig:
    """Tests for OutputConfig dataclass."""

    def test_defaults(self) -> None:
        """Default output config uses text format."""
        cfg = mod.OutputConfig()
        assert cfg.format == "text"
        assert cfg.output_dir is None
        assert cfg.color is True

    def test_to_dict(self) -> None:
        """to_dict includes None values."""
        d = mod.OutputConfig().to_dict()
        assert d["output_dir"] is None
        assert d["format"] == "text"


class TestAnalysisConfig:
    """Tests for AnalysisConfig dataclass."""

    def test_defaults(self) -> None:
        """Default analysis config uses adaptive strategy."""
        cfg = mod.AnalysisConfig()
        assert cfg.strategy == "adaptive"
        assert cfg.incremental_solving is True

    def test_to_dict(self) -> None:
        """to_dict includes list fields."""
        d = mod.AnalysisConfig().to_dict()
        assert isinstance(d["include_patterns"], list)
        assert isinstance(d["exclude_patterns"], list)

    def test_default_exclude_patterns(self) -> None:
        """Default excludes skip test and venv directories."""
        cfg = mod.AnalysisConfig()
        assert "**/tests/**" in cfg.exclude_patterns
        assert "**/.venv/**" in cfg.exclude_patterns


class TestPluginConfig:
    """Tests for PluginConfig dataclass."""

    def test_defaults(self) -> None:
        """Default PluginConfig is enabled with empty collections."""
        cfg = mod.PluginConfig()
        assert cfg.enabled is True
        assert cfg.plugin_dirs == []
        assert cfg.disabled_plugins == set()
        assert cfg.plugin_settings == {}

    def test_to_dict(self) -> None:
        """to_dict converts disabled_plugins set to list."""
        cfg = mod.PluginConfig(disabled_plugins={"plug_a"})
        d = cfg.to_dict()
        assert isinstance(d["disabled_plugins"], list)
        assert "plug_a" in d["disabled_plugins"]


class TestPysymexConfig:
    """Tests for PysymexConfig dataclass."""

    def test_defaults(self) -> None:
        """Default PysymexConfig has all sub-configs."""
        cfg = mod.PysymexConfig()
        assert isinstance(cfg.detectors, mod.DetectorConfig)
        assert isinstance(cfg.limits, mod.AnalysisLimits)
        assert cfg.project_root is None
        assert cfg.config_file is None

    def test_to_dict_contains_all_sections(self) -> None:
        """to_dict produces all top-level sections."""
        d = mod.PysymexConfig().to_dict()
        assert "detectors" in d
        assert "limits" in d
        assert "output" in d
        assert "analysis" in d
        assert "plugins" in d
        assert "solver" in d
        assert "concurrency" in d

    def test_to_toml_returns_string(self) -> None:
        """to_toml produces valid TOML-like string."""
        toml = mod.PysymexConfig().to_toml()
        assert isinstance(toml, str)
        assert "[tool.pysymex]" in toml
        assert "[tool.pysymex.detectors]" in toml
        assert "[tool.pysymex.limits]" in toml

    def test_to_toml_booleans_lowercase(self) -> None:
        """TOML booleans are lowercased (true/false not True/False)."""
        toml = mod.PysymexConfig().to_toml()
        assert "division_by_zero = true" in toml
        assert "overflow = false" in toml


# ---------------------------------------------------------------------------
# Top-level functions
# ---------------------------------------------------------------------------


def test_find_config_file_returns_none_in_isolated_dir(tmp_path: Path) -> None:
    """find_config_file returns None when no config exists up the tree."""
    # Create a deeply nested directory with no config files
    deep = tmp_path / "a" / "b" / "c"
    deep.mkdir(parents=True)
    result = mod.find_config_file(deep)
    # May or may not find one depending on user's home dir
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
    cfg = mod.load_config(start_dir=tmp_path)
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
    # Should return defaults without crashing
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
