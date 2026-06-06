"""Tests for pysymex.config dataclass models."""

from __future__ import annotations

from pathlib import Path

import pysymex.config as mod


def test_config_implementations_live_under_config_package() -> None:
    """Config implementation modules are owned by pysymex.config."""
    config_root = Path("pysymex") / "config"
    offenders = [
        str(path)
        for path in Path("pysymex").rglob("config.py")
        if not path.is_relative_to(config_root)
    ]
    assert offenders == []


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

    def test_to_resource_limits(self) -> None:
        """to_resource_limits maps profile fields to engine limits."""
        lim = mod.AnalysisLimits(max_paths=500, max_constraint_size=12)
        engine = lim.to_resource_limits()
        assert engine.max_paths == 500
        assert engine.max_constraints == 12


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


def test_scan_mode_catalog_is_symbolic_only() -> None:
    """CLI scan mode catalog documents symbolic execution as the only product mode."""
    assert mod.SCAN_MODE_CHOICES == ("symbolic",)
    assert mod.DEFAULT_SCAN_MODE == "symbolic"
