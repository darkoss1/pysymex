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

"""Validation helpers for sandbox and API input safety.

This module hosts path, bounds, config, and function-name validation
previously exposed via ``pysymex.security``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

from pysymex._internal.sandbox.errors import ResourceLimitError, SecurityError

MAX_FILE_SIZE: Final[int] = 10 * 1024 * 1024

FORBIDDEN_PATH_PATTERNS: Final[tuple[str, ...]] = (
    "..",
    "~",
    "\\\\",
)


class PathTraversalError(SecurityError):
    """Raised when a path traversal attack is detected."""


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
            msg = f"Path contains forbidden pattern '{pattern}': {path}"
            raise PathTraversalError(msg)

    resolved = path.resolve()
    base: Path | None = None

    if base_directory is not None:
        base = Path(base_directory).resolve()
        try:
            resolved.relative_to(base)
        except ValueError as exc:
            msg = f"Path escapes base directory: {path} is not within {base}"
            raise PathTraversalError(
                msg,
            ) from exc

    if path.is_symlink():
        target = path.resolve()
        if base is not None:
            try:
                target.relative_to(base)
            except ValueError as exc:
                msg = f"Symlink target escapes base: {path} -> {target}"
                raise PathTraversalError(
                    msg,
                ) from exc

    if must_exist and not resolved.exists():
        msg = f"Path does not exist: {resolved}"
        raise FileNotFoundError(msg)

    if must_be_file and resolved.exists() and not resolved.is_file():
        msg = f"Path is not a file: {resolved}"
        raise SecurityError(msg)

    if allowed_extensions is not None:
        allowed_lower = {e.lower() for e in allowed_extensions}
        if resolved.suffix.lower() not in allowed_lower:
            msg = f"File extension not allowed: {resolved.suffix}. Allowed: {allowed_extensions}"
            raise SecurityError(
                msg,
            )

    if resolved.exists() and resolved.is_file():
        size = resolved.stat().st_size
        if size > MAX_FILE_SIZE:
            msg = f"File too large: {size} bytes (max: {MAX_FILE_SIZE})"
            raise ResourceLimitError(msg)

    return resolved


def validate_bounds(
    value: int,
    name: str,
    min_value: int = 0,
    max_value: int | None = None,
) -> int:
    """Validate an integer is within bounds."""
    if value < min_value:
        msg = f"{name} must be >= {min_value}, got {value}"
        raise ValueError(msg)
    if max_value is not None and value > max_value:
        msg = f"{name} must be <= {max_value}, got {value}"
        raise ValueError(msg)
    return value


def validate_config(
    max_paths: int | None = None,
    max_depth: int | None = None,
    max_iterations: int | None = None,
    timeout: float | None = None,
) -> dict[str, object]:
    """Validate elective host limits without imposing sandbox policy on them."""
    return {
        "max_paths": _validate_optional_positive(max_paths, "max_paths"),
        "max_depth": _validate_optional_positive(max_depth, "max_depth"),
        "max_iterations": _validate_optional_positive(max_iterations, "max_iterations"),
        "timeout": _validate_optional_positive_float(timeout, "timeout"),
    }


def _validate_optional_positive(value: int | None, name: str) -> int | None:
    """Validate a positive elective integer limit."""
    return validate_bounds(value, name, 1) if value is not None else None


def _validate_optional_positive_float(value: float | None, name: str) -> float | None:
    """Validate a positive elective floating-point limit."""
    if value is not None and value <= 0.0:
        msg = f"{name} must be > 0, got {value}"
        raise ValueError(msg)
    return value


def sanitize_function_name(name: str) -> str:
    """Sanitize a function name for safe use."""
    if not name:
        msg = "Function name cannot be empty"
        raise ValueError(msg)

    if not name.replace("_", "").isalnum():
        msg = f"Invalid function name: {name}"
        raise ValueError(msg)

    if name[0].isdigit():
        msg = f"Function name cannot start with digit: {name}"
        raise ValueError(msg)

    import keyword

    if keyword.iskeyword(name):
        msg = f"Function name is a Python keyword: {name}"
        raise ValueError(msg)

    return name
