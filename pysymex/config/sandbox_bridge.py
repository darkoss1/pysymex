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

"""Sandbox bridge configuration normalization."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING

from pysymex.logger import get_logger
from pysymex.sandbox.bridge.schema import normalize_mapping

if TYPE_CHECKING:
    from pysymex.sandbox import SandboxConfig

logger = get_logger(__name__)


def parse_module_list(value: object) -> frozenset[str] | None:
    """Parse a comma-separated module list into ``frozenset[str]``."""
    if not isinstance(value, str):
        return None
    modules = [item.strip() for item in value.split(",")]
    filtered = [module for module in modules if module]
    if not filtered:
        return frozenset()
    return frozenset(filtered)


def to_int(value: object, default: int) -> int:
    """Convert a value to an integer, falling back to a default value on failure.

    Args:
        value (object): The value to convert.
        default (int): The default integer to return if conversion fails.

    Returns:
        int: The converted integer value, or the default.
    """
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return default
    return default


def to_float(value: object, default: float) -> float:
    """Convert a value to a float, falling back to a default value on failure.

    Args:
        value (object): The value to convert.
        default (float): The default float to return if conversion fails.

    Returns:
        float: The converted float value, or the default.
    """
    if isinstance(value, bool):
        return float(int(value))
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        try:
            return float(value.strip())
        except ValueError:
            return default
    return default


def to_bool(value: object, default: bool) -> bool:
    """Convert a value to a boolean, falling back to a default value on failure.

    Args:
        value (object): The value to convert.
        default (bool): The default boolean to return if conversion fails.

    Returns:
        bool: The converted boolean value, or the default.
    """
    if isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value != 0
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return default


def sandbox_config_fingerprint(sandbox_config: Mapping[str, object] | None) -> str:
    """Generate a deterministic fingerprint hash string for a sandbox configuration mapping.

    This fingerprint is used to identify cached configurations for sandbox instances.

    Args:
        sandbox_config (Mapping[str, object] | None): The sandbox configuration mapping.

    Returns:
        str: A JSON string fingerprint of sorted config items.
    """
    config_items: list[tuple[str, str]] = []
    if sandbox_config is not None:
        for key, value in sorted(sandbox_config.items(), key=lambda item: str(item[0])):
            config_items.append((str(key), repr(value)))
    return json.dumps(config_items, ensure_ascii=True, separators=(",", ":"))


def make_sandbox_config(
    overrides: Mapping[str, object] | None = None,
) -> SandboxConfig:
    """Create a SandboxConfig instance from the provided configuration overrides.

    This function normalizes the configuration parameters defining the security boundaries,
    resource limits, and capability permissions for the execution sandbox.

    Security Boundaries and Isolation:
        - Limits CPU time (seconds) and memory allocations (megabytes).
        - Restrains file system read/write pathways, process execution, and network access.
        - Specifies allowed import modules to isolate execution from unsafe native packages.
        - Platform-specific limits (e.g., memory and CPU limits) are applied according to the
          available backend capabilities.

    Args:
        overrides (Mapping[str, object] | None): Optional configuration overrides to apply.

    Returns:
        SandboxConfig: The constructed and normalized SandboxConfig instance.

    Raises:
        SandboxSetupError: If the backend configuration or validation fails.
    """
    from pysymex.sandbox import SandboxBackend, SandboxConfig
    from pysymex.sandbox.errors import SandboxSetupError
    from pysymex.sandbox.types import ResourceLimits, SecurityCapabilities

    raw = dict(overrides or {})
    aliases = {
        "timeout": "timeout_seconds",
        "max_memory_mb": "memory_mb",
        "max_cpu_seconds": "cpu_seconds",
        "max_output_bytes": "max_output_bytes",
    }

    known_keys = {
        "timeout_seconds",
        "cpu_seconds",
        "memory_mb",
        "max_processes",
        "max_file_descriptors",
        "max_file_size_mb",
        "max_output_bytes",
        "max_result_bytes",
        "backend",
        "working_directory",
        "environment",
        "python_executable",
        "wasm_python_module",
        "capture_output",
        "allow_stdin",
        "_block_network",
        "_block_filesystem",
        "_block_process_spawn",
        "required_capabilities",
    }

    normalized: dict[str, object] = {}
    for key, value in raw.items():
        norm_key = aliases.get(key, key)
        if norm_key not in known_keys:
            import warnings

            logger.warning("Unknown sandbox config key: %s", key)
            warnings.warn(f"Unknown sandbox config key: {key}")
        normalized[norm_key] = value

    default_config = SandboxConfig()
    default_limits = default_config.limits
    limits = ResourceLimits(
        timeout_seconds=to_float(
            normalized.get("timeout_seconds", default_limits.timeout_seconds),
            default_limits.timeout_seconds,
        ),
        cpu_seconds=to_int(
            normalized.get("cpu_seconds", default_limits.cpu_seconds),
            default_limits.cpu_seconds,
        ),
        memory_mb=to_int(
            normalized.get("memory_mb", default_limits.memory_mb),
            default_limits.memory_mb,
        ),
        max_processes=to_int(
            normalized.get("max_processes", default_limits.max_processes),
            default_limits.max_processes,
        ),
        max_file_descriptors=to_int(
            normalized.get("max_file_descriptors", default_limits.max_file_descriptors),
            default_limits.max_file_descriptors,
        ),
        max_file_size_mb=to_int(
            normalized.get("max_file_size_mb", default_limits.max_file_size_mb),
            default_limits.max_file_size_mb,
        ),
        max_output_bytes=to_int(
            normalized.get("max_output_bytes", default_limits.max_output_bytes),
            default_limits.max_output_bytes,
        ),
        max_result_bytes=to_int(
            normalized.get("max_result_bytes", default_limits.max_result_bytes),
            default_limits.max_result_bytes,
        ),
    )

    backend_raw = normalized.get("backend")
    backend: SandboxBackend | None = None
    if isinstance(backend_raw, SandboxBackend):
        backend = backend_raw
    elif isinstance(backend_raw, str):
        backend_key = backend_raw.strip().upper()
        backend = SandboxBackend.__members__.get(backend_key)
        if backend is None:
            raise SandboxSetupError(f"Unknown sandbox backend: {backend_raw!r}")

    working_dir_raw = normalized.get("working_directory", None)
    if isinstance(working_dir_raw, Path):
        working_directory = working_dir_raw
    elif isinstance(working_dir_raw, str):
        working_directory = Path(working_dir_raw)
    else:
        working_directory = None

    env_raw = normalized.get("environment")
    environment: dict[str, str] = {}
    normalized_env = normalize_mapping(env_raw)
    if normalized_env is not None:
        for key, value in normalized_env.items():
            environment[key] = str(value)

    python_executable_raw = normalized.get("python_executable")
    python_executable = python_executable_raw if isinstance(python_executable_raw, str) else None

    wasm_python_module_raw = normalized.get("wasm_python_module")
    if isinstance(wasm_python_module_raw, Path):
        wasm_python_module = wasm_python_module_raw
    elif isinstance(wasm_python_module_raw, str):
        wasm_python_module = Path(wasm_python_module_raw)
    else:
        wasm_python_module = None

    capture_output = to_bool(normalized.get("capture_output", True), True)
    allow_stdin = to_bool(normalized.get("allow_stdin", False), False)
    block_network = to_bool(normalized.get("_block_network", True), True)
    block_filesystem = to_bool(normalized.get("_block_filesystem", True), True)
    block_process_spawn = to_bool(normalized.get("_block_process_spawn", True), True)

    required_caps: SecurityCapabilities | None = None
    required_caps_raw = normalized.get("required_capabilities")
    if isinstance(required_caps_raw, SecurityCapabilities):
        required_caps = required_caps_raw
    else:
        required_caps_data = normalize_mapping(required_caps_raw)
        if required_caps_data is not None:
            required_caps = SecurityCapabilities(
                process_isolation=to_bool(
                    required_caps_data.get("process_isolation", False), False
                ),
                filesystem_jail=to_bool(required_caps_data.get("filesystem_jail", False), False),
                network_blocking=to_bool(required_caps_data.get("network_blocking", False), False),
                syscall_filtering=to_bool(
                    required_caps_data.get("syscall_filtering", False), False
                ),
                memory_limits=to_bool(required_caps_data.get("memory_limits", False), False),
                cpu_limits=to_bool(required_caps_data.get("cpu_limits", False), False),
                process_limits=to_bool(required_caps_data.get("process_limits", False), False),
            )

    return SandboxConfig(
        limits=limits,
        backend=backend,
        working_directory=working_directory,
        environment=environment,
        python_executable=python_executable,
        wasm_python_module=wasm_python_module,
        capture_output=capture_output,
        allow_stdin=allow_stdin,
        required_capabilities=required_caps,
        _block_network=block_network,
        _block_filesystem=block_filesystem,
        _block_process_spawn=block_process_spawn,
    )


__all__ = [
    "make_sandbox_config",
    "parse_module_list",
    "sandbox_config_fingerprint",
    "to_bool",
    "to_float",
    "to_int",
]
