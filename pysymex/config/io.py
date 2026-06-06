# pysymex: python symbolic execution & formal verification
# Upstream Repository: https://github.com/darkoss1/pysymex
#
# Copyright (C) 2026 pysymex Team
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

"""Configuration file discovery, loading, and initialization."""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Protocol

from pysymex.config.defaults import CONFIG_FILE_NAMES
from pysymex.config.helpers import (
    normalize_object_dict,
    normalize_string_list,
)
from pysymex.config.root import PysymexConfig

CONFIG_FILES = list(CONFIG_FILE_NAMES)


class _ConfigLogger(Protocol):
    """Protocol defining the interface for the configuration subsystem logger."""

    def warning(self, message: str, *args: object) -> None:
        """Log a configuration warning message.

        Args:
            message (str): The message format string.
            *args (object): Format string arguments.
        """
        ...

    def info(self, message: str, *args: object) -> None:
        """Log a configuration informational message.

        Args:
            message (str): The message format string.
            *args (object): Format string arguments.
        """
        ...


def _logger() -> _ConfigLogger:
    """Retrieve the configuration subsystem logger instance.

    Returns:
        _ConfigLogger: The initialized configuration logger.
    """
    from pysymex.logger import get_logger

    return get_logger(__name__)


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
    for config_name in (".pysymex.toml", "pysymex.toml"):
        config_path = home / config_name
        if config_path.exists():
            return config_path
    return None


def load_config(
    config_path: Path | None = None,
    start_dir: Path | None = None,
) -> PysymexConfig:
    """Load configuration from file or use defaults."""
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
        _logger().warning("Failed to parse config file %s: %s", config_path, e)
        return config
    if config_path.name == "pyproject.toml":
        shadow_data = data.get("tool", {}).get("pysymex", {})
    else:
        shadow_data = data.get("tool", {}).get("pysymex", data)
    apply_config(config, shadow_data)
    return config


def apply_config(config: PysymexConfig, data: dict[str, object]) -> None:
    """Apply configuration data to config object."""
    det_data = normalize_object_dict(data.get("detectors"))
    if det_data is not None:
        for key in (
            "division_by_zero",
            "assertion_errors",
            "index_errors",
            "type_errors",
            "key_errors",
            "attribute_errors",
            "overflow",
            "null_pointer",
        ):
            if key in det_data:
                setattr(config.detectors, key, det_data[key])

    lim_data = normalize_object_dict(data.get("limits"))
    if lim_data is not None:
        for key in (
            "max_paths",
            "max_depth",
            "max_iterations",
            "timeout_seconds",
            "max_memory_mb",
            "max_constraint_size",
            "max_string_length",
            "max_list_length",
        ):
            if key in lim_data:
                setattr(config.limits, key, lim_data[key])

    out_data = normalize_object_dict(data.get("output"))
    if out_data is not None:
        for key in (
            "format",
            "output_dir",
            "color",
            "verbose",
            "quiet",
            "show_paths",
            "show_constraints",
            "show_timing",
        ):
            if key in out_data:
                setattr(config.output, key, out_data[key])

    ana_data = normalize_object_dict(data.get("analysis"))
    if ana_data is not None:
        for key in (
            "strategy",
            "loop_unroll_limit",
            "array_size_limit",
            "string_solver",
            "incremental_solving",
            "constraint_caching",
        ):
            if key in ana_data:
                setattr(config.analysis, key, ana_data[key])
        normalized_include = normalize_string_list(ana_data.get("include_patterns"))
        if normalized_include is not None:
            config.analysis.include_patterns = normalized_include
        normalized_exclude = normalize_string_list(ana_data.get("exclude_patterns"))
        if normalized_exclude is not None:
            config.analysis.exclude_patterns = normalized_exclude


def generate_default_config() -> str:
    """Generate default configuration file content as a TOML string."""
    config = PysymexConfig()
    return config.to_toml()


def init_config(directory: Path | None = None) -> Path:
    """Initialize a new configuration file in the given directory."""
    if directory is None:
        directory = Path.cwd()
    config_path = directory / "pysymex.toml"
    if config_path.exists():
        raise FileExistsError(f"Config file already exists: {config_path}")
    content = generate_default_config()
    config_path.write_text(content, encoding="utf-8")
    _logger().info("Initialized config file: %s", config_path)
    return config_path
