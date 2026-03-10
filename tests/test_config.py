"""Tests for configuration system."""

import tempfile
from pathlib import Path

import pytest

from pysymex.config import (
    AnalysisConfig,
    AnalysisLimits,
    DetectorConfig,
    OutputConfig,
    PluginConfig,
    PysymexConfig,
    find_config_file,
    generate_default_config,
    init_config,
    load_config,
)


class TestDetectorConfig:
    """Tests for DetectorConfig."""

    def test_default_values(self):
        """Test default detector configuration."""
        config = DetectorConfig()

        assert config.division_by_zero is True
        assert config.assertion_errors is True
        assert config.index_errors is True
        assert config.type_errors is True
        assert config.overflow is False  # Off by default

    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = DetectorConfig()
        d = config.to_dict()

        assert "division_by_zero" in d
        assert "taint_enabled" in d
        assert isinstance(d["taint_sources"], list)


class TestAnalysisLimits:
    """Tests for AnalysisLimits."""

    def test_default_values(self):
        """Test default resource limits."""
        limits = AnalysisLimits()

        assert limits.max_paths == 1000
        assert limits.max_depth == 100
        assert limits.timeout_seconds == 60.0

    def test_custom_values(self):
        """Test custom resource limits."""
        limits = AnalysisLimits(max_paths=500, timeout_seconds=30.0)

        assert limits.max_paths == 500
        assert limits.timeout_seconds == 30.0

    def test_to_dict(self):
        """Test conversion to dictionary."""
        limits = AnalysisLimits()
        d = limits.to_dict()

        assert d["max_paths"] == 1000
        assert d["max_depth"] == 100


class TestOutputConfig:
    """Tests for OutputConfig."""

    def test_default_values(self):
        """Test default output configuration."""
        config = OutputConfig()

        assert config.format == "text"
        assert config.color is True
        assert config.verbose is False

    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = OutputConfig(format="json", color=False)
        d = config.to_dict()

        assert d["format"] == "json"
        assert d["color"] is False


class TestAnalysisConfig:
    """Tests for AnalysisConfig."""

    def test_default_values(self):
        """Test default analysis configuration."""
        config = AnalysisConfig()

        assert config.strategy == "dfs"
        assert config.loop_unroll_limit == 10

    def test_include_exclude_patterns(self):
        """Test include/exclude patterns."""
        config = AnalysisConfig()

        assert "**/*.py" in config.include_patterns
        assert any("test" in p for p in config.exclude_patterns)


class TestPluginConfig:
    """Tests for PluginConfig."""

    def test_default_values(self):
        """Test default plugin configuration."""
        config = PluginConfig()

        assert config.enabled is True
        assert len(config.plugin_dirs) == 0
        assert len(config.disabled_plugins) == 0


class TestPysymexConfig:
    """Tests for main configuration class."""

    def test_create_default(self):
        """Test creating default configuration."""
        config = PysymexConfig()

        assert config.detectors is not None
        assert config.limits is not None
        assert config.output is not None
        assert config.analysis is not None
        assert config.plugins is not None

    def test_to_dict(self):
        """Test conversion to dictionary."""
        config = PysymexConfig()
        d = config.to_dict()

        assert "detectors" in d
        assert "limits" in d
        assert "output" in d
        assert "analysis" in d
        assert "plugins" in d

    def test_to_toml(self):
        """Test generating TOML configuration."""
        config = PysymexConfig()
        toml = config.to_toml()

        assert "[tool.pysymex]" in toml
        assert "[tool.pysymex.detectors]" in toml
        assert "[tool.pysymex.limits]" in toml


class TestConfigLoading:
    """Tests for configuration file loading."""

    def test_load_nonexistent(self):
        """Test loading when no config file exists."""
        config = load_config(start_dir=Path("/nonexistent"))

        # Should return default config
        assert config is not None
        assert config.limits.max_paths == 1000

    def test_generate_default_config(self):
        """Test generating default configuration."""
        content = generate_default_config()

        assert "[tool.pysymex]" in content
        assert "max_paths" in content

    def test_init_config(self):
        """Test initializing configuration in directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            config_path = init_config(path)

            assert config_path.exists()
            assert config_path.name == "pysymex.toml"

            content = config_path.read_text()
            assert "[tool.pysymex]" in content

    def test_init_config_exists_raises(self):
        """Test that init raises if config exists."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)

            # Create first
            init_config(path)

            # Second should raise
            with pytest.raises(FileExistsError):
                init_config(path)

    def test_load_toml_config(self):
        """Test loading TOML configuration file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            config_path = path / "pysymex.toml"

            # Write custom config
            config_path.write_text(
                """
[tool.pysymex]

[tool.pysymex.limits]
max_paths = 500
timeout_seconds = 30.0

[tool.pysymex.detectors]
overflow = true
""",
                encoding="utf-8",
            )

            config = load_config(config_path)

            assert config.limits.max_paths == 500
            assert config.limits.timeout_seconds == 30.0
            assert config.detectors.overflow is True

    def test_find_config_file(self):
        """Test finding configuration file."""
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir)
            config_path = path / "pysymex.toml"
            config_path.write_text("[tool.pysymex]", encoding="utf-8")

            found = find_config_file(path)

            assert found is not None
            assert found == config_path
