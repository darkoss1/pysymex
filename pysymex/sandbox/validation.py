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

"""Validation helpers for sandbox and API input safety.

This module hosts path, bounds, config, and function-name validation
previously exposed via ``pysymex.security``.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from pysymex._constants import (
    FORBIDDEN_PATH_PATTERNS,
    MAX_DEPTH,
    MAX_FILE_SIZE,
    MAX_ITERATIONS,
    MAX_PATHS,
    MAX_TIMEOUT,
)
from pysymex.sandbox.execution import ResourceLimitError, SecurityError


class PathTraversalError(SecurityError):
    """Raised when a path traversal attack is detected."""


@dataclass
class SecurityConfig:
    """Configuration for security controls."""

    allow_absolute_paths: bool = True
    allow_symlinks: bool = False
    allowed_directories: list[str] | None = None

    max_memory_mb: int = 512
    max_cpu_seconds: int = 60

    sandbox_builtins: bool = True
    allow_file_io: bool = False
    allow_network: bool = False


def validate_path(
    path: str | Path,
    *,
    must_exist: bool = True,
    must_be_file: bool = True,
    allowed_extensions: list[str] | None = None,
    base_directory: str | Path | None = None,
) -> Path:
    """Validate a file path for safety."""
    path = Path(path)

    path_str = str(path)
    for pattern in FORBIDDEN_PATH_PATTERNS:
        if pattern in path_str:
            raise PathTraversalError(f"Path contains forbidden pattern '{pattern}': {path}")

    resolved = path.resolve()
    base: Path | None = None

    if base_directory is not None:
        base = Path(base_directory).resolve()
        try:
            resolved.relative_to(base)
        except ValueError as exc:
            raise PathTraversalError(
                f"Path escapes base directory: {path} is not within {base}"
            ) from exc

    if path.is_symlink():
        target = path.resolve()
        if base is not None:
            try:
                target.relative_to(base)
            except ValueError as exc:
                raise PathTraversalError(
                    f"Symlink target escapes base: {path} -> {target}"
                ) from exc

    if must_exist and not resolved.exists():
        raise FileNotFoundError(f"Path does not exist: {resolved}")

    if must_be_file and resolved.exists() and not resolved.is_file():
        raise SecurityError(f"Path is not a file: {resolved}")

    if allowed_extensions is not None:
        allowed_lower = {e.lower() for e in allowed_extensions}
        if resolved.suffix.lower() not in allowed_lower:
            raise SecurityError(
                f"File extension not allowed: {resolved.suffix}. Allowed: {allowed_extensions}"
            )

    if resolved.exists() and resolved.is_file():
        size = resolved.stat().st_size
        if size > MAX_FILE_SIZE:
            raise ResourceLimitError(f"File too large: {size} bytes (max: {MAX_FILE_SIZE})")

    return resolved


def validate_bounds(
    value: int,
    name: str,
    min_value: int = 0,
    max_value: int | None = None,
) -> int:
    """Validate an integer is within bounds."""
    if value < min_value:
        raise ValueError(f"{name} must be >= {min_value}, got {value}")
    if max_value is not None and value > max_value:
        raise ValueError(f"{name} must be <= {max_value}, got {value}")
    return value


def validate_config(
    max_paths: int = 1000,
    max_depth: int = 100,
    max_iterations: int = 10000,
    timeout: float = 60.0,
) -> dict[str, object]:
    """Validate execution configuration parameters."""
    return {
        "max_paths": validate_bounds(max_paths, "max_paths", 1, MAX_PATHS),
        "max_depth": validate_bounds(max_depth, "max_depth", 1, MAX_DEPTH),
        "max_iterations": validate_bounds(
            max_iterations,
            "max_iterations",
            1,
            MAX_ITERATIONS,
        ),
        "timeout": min(max(0.1, timeout), MAX_TIMEOUT),
    }


def sanitize_function_name(name: str) -> str:
    """Sanitize a function name for safe use."""
    if not name:
        raise ValueError("Function name cannot be empty")

    if not name.replace("_", "").isalnum():
        raise ValueError(f"Invalid function name: {name}")

    if name[0].isdigit():
        raise ValueError(f"Function name cannot start with digit: {name}")

    import keyword

    if keyword.iskeyword(name):
        raise ValueError(f"Function name is a Python keyword: {name}")

    return name


__all__ = [
    "PathTraversalError",
    "ResourceLimitError",
    "SecurityConfig",
    "SecurityError",
    "sanitize_function_name",
    "validate_bounds",
    "validate_config",
    "validate_path",
]
