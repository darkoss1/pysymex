"""Configuration system for pysymex.
Supports TOML configuration files with project-level and user-level settings.
"""

from __future__ import annotations


import tomllib

from dataclasses import dataclass, field

from pathlib import Path

from typing import Any, cast

CONFIG_FILES = [
    "pysymex.toml",
    ".pysymex.toml",
    "pyproject.toml",
]


@dataclass
class SolverConfig:
    """Configuration for the Z3 solver subsystem (v0.4.0)."""

    strategy: str = "incremental"

    cache_size: int = 50000

    lazy_eval_threshold: int = 20

    compaction_interval: int = 50

    portfolio_timeout_ms: int = 100

    warm_start: bool = True

    simplify_constraints: bool = True

    solver_timeout_ms: int = 10000

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "strategy": self.strategy,
            "cache_size": self.cache_size,
            "lazy_eval_threshold": self.lazy_eval_threshold,
            "compaction_interval": self.compaction_interval,
            "portfolio_timeout_ms": self.portfolio_timeout_ms,
            "warm_start": self.warm_start,
            "simplify_constraints": self.simplify_constraints,
            "solver_timeout_ms": self.solver_timeout_ms,
        }


@dataclass
class ConcurrencyConfig:
    """Configuration for concurrency/async analysis (v0.4.0)."""

    enabled: bool = False

    detect_races: bool = True

    detect_deadlocks: bool = True

    async_analysis: bool = True

    max_interleavings: int = 1000

    dpor_enabled: bool = True

    lockset_analysis: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "enabled": self.enabled,
            "detect_races": self.detect_races,
            "detect_deadlocks": self.detect_deadlocks,
            "async_analysis": self.async_analysis,
            "max_interleavings": self.max_interleavings,
            "dpor_enabled": self.dpor_enabled,
            "lockset_analysis": self.lockset_analysis,
        }


@dataclass
class DetectorConfig:
    """Configuration for bug detectors."""

    division_by_zero: bool = True

    assertion_errors: bool = True

    index_errors: bool = True

    type_errors: bool = True

    key_errors: bool = True

    attribute_errors: bool = True

    overflow: bool = False

    null_pointer: bool = True

    taint_enabled: bool = False

    taint_sources: list[str] = field(default_factory=lambda: ["input", "request"])

    taint_sinks: list[str] = field(default_factory=lambda: ["exec", "eval", "sql"])

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "division_by_zero": self.division_by_zero,
            "assertion_errors": self.assertion_errors,
            "index_errors": self.index_errors,
            "type_errors": self.type_errors,
            "key_errors": self.key_errors,
            "attribute_errors": self.attribute_errors,
            "overflow": self.overflow,
            "null_pointer": self.null_pointer,
            "taint_enabled": self.taint_enabled,
            "taint_sources": self.taint_sources,
            "taint_sinks": self.taint_sinks,
        }


@dataclass
class AnalysisLimits:
    """Resource limits for analysis."""

    max_paths: int = 1000

    max_depth: int = 100

    max_iterations: int = 10000

    timeout_seconds: float = 60.0

    max_memory_mb: int = 1024

    max_constraint_size: int = 10000

    max_string_length: int = 1000

    max_list_length: int = 100

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "max_paths": self.max_paths,
            "max_depth": self.max_depth,
            "max_iterations": self.max_iterations,
            "timeout_seconds": self.timeout_seconds,
            "max_memory_mb": self.max_memory_mb,
            "max_constraint_size": self.max_constraint_size,
            "max_string_length": self.max_string_length,
            "max_list_length": self.max_list_length,
        }


@dataclass
class OutputConfig:
    """Configuration for output and reporting."""

    format: str = "text"

    output_dir: str | None = None

    color: bool = True

    verbose: bool = False

    quiet: bool = False

    show_paths: bool = True

    show_constraints: bool = False

    show_timing: bool = True

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "format": self.format,
            "output_dir": self.output_dir,
            "color": self.color,
            "verbose": self.verbose,
            "quiet": self.quiet,
            "show_paths": self.show_paths,
            "show_constraints": self.show_constraints,
            "show_timing": self.show_timing,
        }


@dataclass
class AnalysisConfig:
    """Configuration for analysis behavior."""

    strategy: str = "dfs"

    loop_unroll_limit: int = 10

    array_size_limit: int = 50

    string_solver: str = "z3str3"

    incremental_solving: bool = True

    constraint_caching: bool = True

    include_patterns: list[str] = field(default_factory=lambda: ["**/*.py"])

    exclude_patterns: list[str] = field(
        default_factory=lambda: [
            "**/test_*.py",
            "**/*_test.py",
            "**/tests/**",
            "**/.venv/**",
            "**/venv/**",
            "**/node_modules/**",
        ]
    )

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "strategy": self.strategy,
            "loop_unroll_limit": self.loop_unroll_limit,
            "array_size_limit": self.array_size_limit,
            "string_solver": self.string_solver,
            "incremental_solving": self.incremental_solving,
            "constraint_caching": self.constraint_caching,
            "include_patterns": self.include_patterns,
            "exclude_patterns": self.exclude_patterns,
        }


@dataclass
class PluginConfig:
    """Configuration for plugins."""

    enabled: bool = True

    plugin_dirs: list[str] = field(default_factory=list[str])

    disabled_plugins: set[str] = field(default_factory=set[str])

    plugin_settings: dict[str, dict[str, Any]] = field(default_factory=dict[str, dict[str, Any]])

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""

        return {
            "enabled": self.enabled,
            "plugin_dirs": self.plugin_dirs,
            "disabled_plugins": list(self.disabled_plugins),
            "plugin_settings": self.plugin_settings,
        }


@dataclass
class PysymexConfig:
    """Main configuration for pysymex."""

    detectors: DetectorConfig = field(default_factory=DetectorConfig)

    limits: AnalysisLimits = field(default_factory=AnalysisLimits)

    output: OutputConfig = field(default_factory=OutputConfig)

    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)

    plugins: PluginConfig = field(default_factory=PluginConfig)

    solver: SolverConfig = field(default_factory=SolverConfig)

    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)

    project_root: Path | None = None

    config_file: Path | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for serialization."""

        return {
            "detectors": self.detectors.to_dict(),
            "limits": self.limits.to_dict(),
            "output": self.output.to_dict(),
            "analysis": self.analysis.to_dict(),
            "plugins": self.plugins.to_dict(),
            "solver": self.solver.to_dict(),
            "concurrency": self.concurrency.to_dict(),
        }

    def to_toml(self) -> str:
        """Generate TOML configuration string."""

        lines = ["[tool.pysymex]", ""]

        lines.append("[tool.pysymex.detectors]")

        for key, value in self.detectors.to_dict().items():
            if isinstance(value, bool):
                lines.append(f"{key} = {str(value).lower()}")

            elif isinstance(value, list):
                items = ", ".join(f'"{v}"' for v in cast(list[str], value))

                lines.append(f"{key} = [{items}]")

            else:
                lines.append(f"{key} = {value}")

        lines.append("")

        lines.append("[tool.pysymex.limits]")

        for key, value in self.limits.to_dict().items():
            lines.append(f"{key} = {value}")

        lines.append("")

        lines.append("[tool.pysymex.output]")

        for key, value in self.output.to_dict().items():
            if isinstance(value, bool):
                lines.append(f"{key} = {str(value).lower()}")

            elif value is None:
                continue

            elif isinstance(value, str):
                lines.append(f'{key} = "{value}"')

            else:
                lines.append(f"{key} = {value}")

        lines.append("")

        lines.append("[tool.pysymex.analysis]")

        for key, value in self.analysis.to_dict().items():
            if isinstance(value, bool):
                lines.append(f"{key} = {str(value).lower()}")

            elif isinstance(value, list):
                items = ", ".join(f'"{v}"' for v in cast(list[str], value))

                lines.append(f"{key} = [{items}]")

            elif isinstance(value, str):
                lines.append(f'{key} = "{value}"')

            else:
                lines.append(f"{key} = {value}")

        return "\n".join(lines)


def find_config_file(start_dir: Path | None = None) -> Path | None:
    """Find configuration file by walking up directory tree."""

    if start_dir is None:
        start_dir = Path.cwd()

    current = start_dir.resolve()

    while current != current.parent:
        for config_name in CONFIG_FILES:
            config_path = current / config_name

            if config_path.exists():
                return config_path

        current = current.parent

    home = Path.home()

    for config_name in [".pysymex.toml", "pysymex.toml"]:
        config_path = home / config_name

        if config_path.exists():
            return config_path

    return None


def load_config(
    config_path: Path | None = None,
    start_dir: Path | None = None,
) -> PysymexConfig:
    """Load configuration from file or use defaults.
    Args:
        config_path: Explicit path to config file
        start_dir: Directory to start searching for config
    Returns:
        Loaded configuration
    """

    config = PysymexConfig()

    if config_path is None:
        config_path = find_config_file(start_dir)

    if config_path is None or not config_path.exists():
        return config

    config.config_file = config_path

    config.project_root = config_path.parent

    try:
        with open(config_path, "rb") as f:
            data = tomllib.load(f)

    except Exception as e:
        print(f"Warning: Failed to parse config file: {e}")

        return config

    if config_path.name == "pyproject.toml":
        shadow_data = data.get("tool", {}).get("pysymex", {})

    else:
        shadow_data = data.get("tool", {}).get("pysymex", data)

    _apply_config(config, shadow_data)

    return config


def _apply_config(config: PysymexConfig, data: dict[str, Any]) -> None:
    """Apply configuration data to config object."""

    if "detectors" in data:
        det_data = data["detectors"]

        for key in [
            "division_by_zero",
            "assertion_errors",
            "index_errors",
            "type_errors",
            "key_errors",
            "attribute_errors",
            "overflow",
            "null_pointer",
            "taint_enabled",
        ]:
            if key in det_data:
                setattr(config.detectors, key, det_data[key])

        if "taint_sources" in det_data:
            config.detectors.taint_sources = list(det_data["taint_sources"])

        if "taint_sinks" in det_data:
            config.detectors.taint_sinks = list(det_data["taint_sinks"])

    if "limits" in data:
        lim_data = data["limits"]

        for key in [
            "max_paths",
            "max_depth",
            "max_iterations",
            "timeout_seconds",
            "max_memory_mb",
            "max_constraint_size",
            "max_string_length",
            "max_list_length",
        ]:
            if key in lim_data:
                setattr(config.limits, key, lim_data[key])

    if "output" in data:
        out_data = data["output"]

        for key in [
            "format",
            "output_dir",
            "color",
            "verbose",
            "quiet",
            "show_paths",
            "show_constraints",
            "show_timing",
        ]:
            if key in out_data:
                setattr(config.output, key, out_data[key])

    if "analysis" in data:
        ana_data = data["analysis"]

        for key in [
            "strategy",
            "loop_unroll_limit",
            "array_size_limit",
            "string_solver",
            "incremental_solving",
            "constraint_caching",
        ]:
            if key in ana_data:
                setattr(config.analysis, key, ana_data[key])

        if "include_patterns" in ana_data:
            config.analysis.include_patterns = list(ana_data["include_patterns"])

        if "exclude_patterns" in ana_data:
            config.analysis.exclude_patterns = list(ana_data["exclude_patterns"])

    if "plugins" in data:
        plug_data = data["plugins"]

        if "enabled" in plug_data:
            config.plugins.enabled = plug_data["enabled"]

        if "plugin_dirs" in plug_data:
            config.plugins.plugin_dirs = list(plug_data["plugin_dirs"])

        if "disabled_plugins" in plug_data:
            config.plugins.disabled_plugins = set(plug_data["disabled_plugins"])

        if "plugin_settings" in plug_data:
            config.plugins.plugin_settings = dict(plug_data["plugin_settings"])


def generate_default_config() -> str:
    """Generate default configuration file content."""

    config = PysymexConfig()

    return config.to_toml()


def init_config(directory: Path | None = None) -> Path:
    """Initialize a new configuration file in the given directory.
    Args:
        directory: Directory to create config in (default: current)
    Returns:
        Path to created config file
    """

    if directory is None:
        directory = Path.cwd()

    config_path = directory / "pysymex.toml"

    if config_path.exists():
        raise FileExistsError(f"Config file already exists: {config_path}")

    content = generate_default_config()

    config_path.write_text(content, encoding="utf-8")

    return config_path


__all__ = [
    "PysymexConfig",
    "DetectorConfig",
    "AnalysisLimits",
    "OutputConfig",
    "AnalysisConfig",
    "PluginConfig",
    "SolverConfig",
    "ConcurrencyConfig",
    "load_config",
    "find_config_file",
    "generate_default_config",
    "init_config",
]
