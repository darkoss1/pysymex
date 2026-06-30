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
import warnings
from pathlib import Path
from typing import TYPE_CHECKING

from pysymex._internal.config.coercion import ConfigCoercion
from pysymex._internal.config.sandbox.types import (
    SandboxBackend,
    SandboxConfig,
    SandboxResourceLimits,
    SecurityCapabilities,
)
from pysymex._internal.logging.root import get_logger
from pysymex._internal.sandbox.bridge.schema import SandboxSchema
from pysymex._internal.sandbox.errors import SandboxSetupError

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = get_logger(__name__)


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


def _normalize_sandbox_overrides(overrides: Mapping[str, object] | None) -> dict[str, object]:
    """Warn about unknown sandbox override keys."""
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
        "capture_output",
        "allow_stdin",
        "_block_network",
        "_block_filesystem",
        "_block_process_spawn",
        "required_capabilities",
    }
    normalized: dict[str, object] = {}
    for key, value in dict(overrides or {}).items():
        if key not in known_keys:
            logger.warning("Unknown sandbox config key: %s", key)
            warnings.warn(f"Unknown sandbox config key: {key}", stacklevel=2)
        normalized[key] = value
    return normalized


def _int_limit(
    normalized: Mapping[str, object],
    name: str,
    default_limits: SandboxResourceLimits,
) -> int:
    """Read and coerce one integer resource-limit field."""
    default_value = getattr(default_limits, name)
    return ConfigCoercion.to_int(normalized.get(name, default_value), default_value)


def _build_resource_limits(
    normalized: Mapping[str, object],
    default_limits: SandboxResourceLimits,
) -> SandboxResourceLimits:
    """Build the resource-limit section of a sandbox config."""
    return SandboxResourceLimits(
        timeout_seconds=ConfigCoercion.to_float(
            normalized.get("timeout_seconds", default_limits.timeout_seconds),
            default_limits.timeout_seconds,
        ),
        cpu_seconds=_int_limit(normalized, "cpu_seconds", default_limits),
        memory_mb=_int_limit(normalized, "memory_mb", default_limits),
        max_processes=_int_limit(normalized, "max_processes", default_limits),
        max_file_descriptors=_int_limit(normalized, "max_file_descriptors", default_limits),
        max_file_size_mb=_int_limit(normalized, "max_file_size_mb", default_limits),
        max_output_bytes=_int_limit(normalized, "max_output_bytes", default_limits),
        max_result_bytes=_int_limit(normalized, "max_result_bytes", default_limits),
    )


def _resolve_backend(value: object) -> SandboxBackend | None:
    """Resolve a configured backend enum or backend string."""
    if value is None:
        return None
    if isinstance(value, SandboxBackend):
        return value
    if isinstance(value, str):
        backend = SandboxBackend.__members__.get(value.strip().upper())
        if backend is not None:
            return backend
        msg = f"Unknown sandbox backend: {value!r}"
        raise SandboxSetupError(msg)
    return None


def _resolve_working_directory(value: object) -> Path | None:
    """Resolve a working-directory override into a Path."""
    if isinstance(value, Path):
        return value
    if isinstance(value, str):
        return Path(value)
    return None


def _resolve_environment(value: object) -> dict[str, str]:
    """Normalize a sandbox environment mapping to string keys and values."""
    environment: dict[str, str] = {}
    normalized_env = SandboxSchema.mapping(value)
    if normalized_env is not None:
        for key, item in normalized_env.items():
            environment[key] = str(item)
    return environment


def _bool_option(
    normalized: Mapping[str, object],
    name: str,
    default: bool,
) -> bool:
    """Read and coerce a strict boolean option."""
    return ConfigCoercion.to_bool(normalized.get(name, default), default, accept_float=False)


def _required_capability_bool(data: Mapping[str, object], name: str) -> bool:
    """Read one required-capability flag."""
    return ConfigCoercion.to_bool(data.get(name, False), False, accept_float=False)


def _resolve_required_capabilities(value: object) -> SecurityCapabilities | None:
    """Resolve optional required sandbox security capabilities."""
    if isinstance(value, SecurityCapabilities):
        return value
    required_caps_data = SandboxSchema.mapping(value)
    if required_caps_data is None:
        return None
    return SecurityCapabilities(
        process_isolation=_required_capability_bool(required_caps_data, "process_isolation"),
        filesystem_jail=_required_capability_bool(required_caps_data, "filesystem_jail"),
        network_blocking=_required_capability_bool(required_caps_data, "network_blocking"),
        syscall_filtering=_required_capability_bool(required_caps_data, "syscall_filtering"),
        memory_limits=_required_capability_bool(required_caps_data, "memory_limits"),
        cpu_limits=_required_capability_bool(required_caps_data, "cpu_limits"),
        process_limits=_required_capability_bool(required_caps_data, "process_limits"),
    )


def make_sandbox_config(
    overrides: Mapping[str, object] | None = None,
) -> SandboxConfig:
    """Create a SandboxConfig instance from the provided configuration overrides.

    This function normalizes the configuration parameters defining the security boundaries,
    resource limits, and capability permissions for the execution sandbox.

    Raises:
        SandboxSetupError: If the backend configuration or validation fails.

    """
    normalized = _normalize_sandbox_overrides(overrides)
    default_config = SandboxConfig()
    python_executable_raw = normalized.get("python_executable")
    return SandboxConfig(
        limits=_build_resource_limits(normalized, default_config.limits),
        backend=_resolve_backend(normalized.get("backend")),
        working_directory=_resolve_working_directory(normalized.get("working_directory")),
        environment=_resolve_environment(normalized.get("environment")),
        python_executable=(
            python_executable_raw if isinstance(python_executable_raw, str) else None
        ),
        capture_output=_bool_option(normalized, "capture_output", True),
        allow_stdin=_bool_option(normalized, "allow_stdin", False),
        required_capabilities=_resolve_required_capabilities(
            normalized.get("required_capabilities"),
        ),
        _block_network=_bool_option(normalized, "_block_network", True),
        _block_filesystem=_bool_option(normalized, "_block_filesystem", True),
        _block_process_spawn=_bool_option(normalized, "_block_process_spawn", True),
    )
