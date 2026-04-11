# PySyMex: Python Symbolic Execution & Formal Verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 PySyMex Team
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""Configuration system for pysymex.

Supports TOML configuration files with project-level and user-level
settings.  Configuration is loaded from ``pysymex.toml``,
``.pysymex.toml``, or the ``[tool.pysymex]`` section of
``pyproject.toml``.

Use :func:`load_config` to locate and parse the nearest config file,
or :func:`init_config` to scaffold a new one.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import cast

CONFIG_FILES = [
    "pysymex.toml",
    ".pysymex.toml",
    "pyproject.toml",
]


@dataclass(frozen=True, slots=True)
class SolverConfig:
    """Configuration for the Z3 solver subsystem.

    Attributes:
        strategy: Solver strategy (``"incremental"``, ``"portfolio"``).
        cache_size: Maximum entries in the solver result cache.
        lazy_eval_threshold: Pending constraints before forcing a check.
        compaction_interval: Iterations between solver compactions.
        portfolio_timeout_ms: Timeout for portfolio sub-solvers.
        warm_start: Reuse solver state across queries.
        simplify_constraints: Apply Z3 simplification before solving.
        solver_timeout_ms: Per-query solver timeout in milliseconds.
    """

    strategy: str = "incremental"
    cache_size: int = 50000
    lazy_eval_threshold: int = 20
    compaction_interval: int = 50
    portfolio_timeout_ms: int = 100
    warm_start: bool = True
    simplify_constraints: bool = True
    solver_timeout_ms: int = 10000

    def to_dict(self) -> dict[str, object]:
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


@dataclass(frozen=True, slots=True)
class ConcurrencyConfig:
    """Configuration for concurrency and async analysis.

    Attributes:
        enabled: Master switch for concurrency analysis.
        detect_races: Detect data races between threads.
        detect_deadlocks: Detect potential deadlocks.
        async_analysis: Analyse async/await scheduling.
        max_interleavings: Max scheduling permutations to explore.
        dpor_enabled: Use Dynamic Partial Order Reduction.
        lockset_analysis: Use lockset-based race detection.
    """

    enabled: bool = False
    detect_races: bool = True
    detect_deadlocks: bool = True
    async_analysis: bool = True
    max_interleavings: int = 1000
    dpor_enabled: bool = True
    lockset_analysis: bool = True

    def to_dict(self) -> dict[str, object]:
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
    """Configuration for bug detectors.

    Each boolean flag enables or disables the corresponding detector.
    Taint-related options configure source/sink pairs for flow analysis.

    Attributes:
        division_by_zero: Detect division by zero.
        assertion_errors: Detect assertion failures.
        index_errors: Detect index-out-of-bounds.
        type_errors: Detect type mismatches.
        key_errors: Detect missing dictionary keys.
        attribute_errors: Detect missing attributes.
        overflow: Detect integer overflow (bounded analysis).
        null_pointer: Detect None dereferences.
        taint_enabled: Enable taint-flow analysis.
        taint_sources: Names of taint source functions.
        taint_sinks: Names of dangerous sink functions.
    """

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

    def to_dict(self) -> dict[str, object]:
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
    """Resource limits for analysis.

    Attributes:
        max_paths: Maximum execution paths to explore.
        max_depth: Maximum call/recursion depth per path.
        max_iterations: Global iteration budget.
        timeout_seconds: Wall-clock timeout in seconds.
        max_memory_mb: Memory limit in megabytes.
        max_constraint_size: Maximum number of Z3 constraints.
        max_string_length: Bound for symbolic string length.
        max_list_length: Bound for symbolic list length.
    """

    max_paths: int = 1000
    max_depth: int = 100
    max_iterations: int = 10000
    timeout_seconds: float = 60.0
    max_memory_mb: int = 1024
    max_constraint_size: int = 10000
    max_string_length: int = 1000
    max_list_length: int = 100

    def to_dict(self) -> dict[str, object]:
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
    """Configuration for output and reporting.

    Attributes:
        format: Output format (``"text"``, ``"json"``, ``"sarif"``).
        output_dir: Directory for report files (``None`` = stdout).
        color: Use ANSI colours in terminal output.
        verbose: Print detailed diagnostic output.
        quiet: Suppress non-essential output.
        show_paths: Include explored paths in the report.
        show_constraints: Include Z3 constraints in the report.
        show_timing: Include timing statistics in the report.
    """

    format: str = "text"
    output_dir: str | None = None
    color: bool = True
    verbose: bool = False
    quiet: bool = False
    show_paths: bool = True
    show_constraints: bool = False
    show_timing: bool = True

    def to_dict(self) -> dict[str, object]:
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
    """Configuration for analysis behaviour.

    Attributes:
        strategy: Path exploration strategy (``"chtd_native"``, ``"adaptive"``, etc.).
        loop_unroll_limit: Maximum loop iterations before widening.
        array_size_limit: Upper bound for symbolic array sizes.
        string_solver: Z3 string solver backend.
        incremental_solving: Use incremental Z3 solver.
        constraint_caching: Cache satisfiability results.
        include_patterns: Glob patterns for files to include.
        exclude_patterns: Glob patterns for files to exclude.
    """

    strategy: str = "adaptive"
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
            "**/tests_backup/**",
            "**/.venv/**",
            "**/venv/**",
            "**/node_modules/**",
        ]
    )

    def to_dict(self) -> dict[str, object]:
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
    """Configuration for plugins.

    Attributes:
        enabled: Master switch for the plugin system.
        plugin_dirs: Additional directories to scan for plugins.
        disabled_plugins: Set of plugin names to skip.
        plugin_settings: Per-plugin configuration dicts.
    """

    enabled: bool = True
    plugin_dirs: list[str] = field(default_factory=list)
    disabled_plugins: set[str] = field(default_factory=set)
    plugin_settings: dict[str, dict[str, object]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, object]:
        """Convert to dictionary."""
        return {
            "enabled": self.enabled,
            "plugin_dirs": self.plugin_dirs,
            "disabled_plugins": list(self.disabled_plugins),
            "plugin_settings": self.plugin_settings,
        }


@dataclass
class PysymexConfig:
    """Top-level configuration container for pysymex.

    Aggregates all sub-configurations.  Typically loaded from a TOML
    file via :func:`load_config`.

    Attributes:
        detectors: Bug detector toggles and taint settings.
        limits: Resource limits (paths, depth, time, memory).
        output: Output format and verbosity settings.
        analysis: Exploration strategy and solver options.
        plugins: Plugin system settings.
        solver: Z3 solver tuning parameters.
        concurrency: Threading/async analysis settings.
        project_root: Root directory of the project (set during load).
        config_file: Path to the loaded config file (set during load).
    """

    detectors: DetectorConfig = field(default_factory=DetectorConfig)
    limits: AnalysisLimits = field(default_factory=AnalysisLimits)
    output: OutputConfig = field(default_factory=OutputConfig)
    analysis: AnalysisConfig = field(default_factory=AnalysisConfig)
    plugins: PluginConfig = field(default_factory=PluginConfig)
    solver: SolverConfig = field(default_factory=SolverConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    project_root: Path | None = None
    config_file: Path | None = None

    def to_dict(self) -> dict[str, object]:
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
                items = ", ".join(f'"{v}"' for v in cast("list[str]", value))
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
                items = ", ".join(f'"{v}"' for v in cast("list[str]", value))
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
    except (OSError, ValueError) as e:
        print(f"Warning: Failed to parse config file: {e}")
        return config
    if config_path.name == "pyproject.toml":
        shadow_data = data.get("tool", {}).get("pysymex", {})
    else:
        shadow_data = data.get("tool", {}).get("pysymex", data)
    _apply_config(config, shadow_data)
    return config


def _apply_config(config: PysymexConfig, data: dict[str, object]) -> None:
    """Apply configuration data to config object."""
    if "detectors" in data:
        det_data = data["detectors"]
        if isinstance(det_data, dict):
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
                src = det_data["taint_sources"]
                if isinstance(src, list):
                    config.detectors.taint_sources = list(src)
            if "taint_sinks" in det_data:
                sinks = det_data["taint_sinks"]
                if isinstance(sinks, list):
                    config.detectors.taint_sinks = list(sinks)
    if "limits" in data:
        lim_data = data["limits"]
        if isinstance(lim_data, dict):
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
        if isinstance(out_data, dict):
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
        if isinstance(ana_data, dict):
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
                inc = ana_data["include_patterns"]
                if isinstance(inc, list):
                    config.analysis.include_patterns = list(inc)
            if "exclude_patterns" in ana_data:
                exc = ana_data["exclude_patterns"]
                if isinstance(exc, list):
                    config.analysis.exclude_patterns = list(exc)
    if "plugins" in data:
        plug_data = data["plugins"]
        if isinstance(plug_data, dict):
            if "enabled" in plug_data:
                config.plugins.enabled = bool(plug_data["enabled"])
            if "plugin_dirs" in plug_data:
                dirs = plug_data["plugin_dirs"]
                if isinstance(dirs, list):
                    config.plugins.plugin_dirs = list(dirs)
            if "disabled_plugins" in plug_data:
                disabled = plug_data["disabled_plugins"]
                if isinstance(disabled, (list, set)):
                    config.plugins.disabled_plugins = set(disabled)
            if "plugin_settings" in plug_data:
                settings = plug_data["plugin_settings"]
                if isinstance(settings, dict):
                    config.plugins.plugin_settings = dict(settings)


def generate_default_config() -> str:
    """Generate default configuration file content as a TOML string.

    Returns:
        A TOML-formatted string with all default settings.
    """
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
    "AnalysisConfig",
    "AnalysisLimits",
    "ConcurrencyConfig",
    "DetectorConfig",
    "OutputConfig",
    "PluginConfig",
    "PysymexConfig",
    "SolverConfig",
    "find_config_file",
    "generate_default_config",
    "init_config",
    "load_config",
]
