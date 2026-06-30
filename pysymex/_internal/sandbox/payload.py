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

"""Prepare public sandbox execution payloads before backend handoff.

The public runner owns lifecycle and backend selection. This module owns
attacker-controlled source bytes, staged filenames, and supplemental-file size
limits before any isolation backend receives them.
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from .paths import sanitize_extra_files, validate_sandbox_filename

if TYPE_CHECKING:
    from pysymex._internal.config.sandbox.types import SandboxResourceLimits


def prepare_file_execution_payload(
    file_path: str | Path,
    *,
    limits: SandboxResourceLimits,
    extra_files: dict[str, bytes] | None,
) -> tuple[bytes, str, dict[str, bytes]]:
    """Read and validate a filesystem source file for sandbox execution.

    Args:
        file_path: Path to the Python source file to execute.
        limits: Resource limits used for supplemental-file payload bounds.
        extra_files: Optional staged files copied beside the target source.

    Returns:
        Code bytes, validated target filename, and sanitized supplemental files.

    Raises:
        FileNotFoundError: If `file_path` does not exist.
        ValueError: If `file_path` is not a file or staging policy rejects the
            target filename or supplemental files.

    """
    source_path = Path(file_path)
    if not source_path.exists():
        msg = f"File not found: {source_path}"
        raise FileNotFoundError(msg)
    if not source_path.is_file():
        msg = f"Not a file: {source_path}"
        raise ValueError(msg)

    target_name = source_path.name
    validate_sandbox_filename(target_name)
    sanitized_files = sanitize_extra_files(extra_files)
    _enforce_extra_file_limits(sanitized_files, limits)
    return source_path.read_bytes(), target_name, sanitized_files


def prepare_code_execution_payload(
    code: str | bytes,
    *,
    filename: str,
    limits: SandboxResourceLimits,
    extra_files: dict[str, bytes] | None,
) -> tuple[bytes, str, dict[str, bytes]]:
    """Validate direct source code and supplemental files for execution.

    Args:
        code: Python source code as text or bytes.
        filename: Virtual filename staged for the code.
        limits: Resource limits used for supplemental-file payload bounds.
        extra_files: Optional staged files copied beside the target source.

    Returns:
        Code bytes, validated target filename, and sanitized supplemental files.

    Raises:
        ValueError: If staging policy rejects `filename` or supplemental files.

    """
    validate_sandbox_filename(filename)
    sanitized_files = sanitize_extra_files(extra_files)
    _enforce_extra_file_limits(sanitized_files, limits)
    return _source_bytes(code), filename, sanitized_files


def _source_bytes(code: str | bytes) -> bytes:
    """Return UTF-8 encoded source bytes without altering byte inputs."""
    if isinstance(code, str):
        return code.encode("utf-8")
    return code


def _enforce_extra_file_limits(
    extra_files: dict[str, bytes],
    limits: SandboxResourceLimits,
) -> None:
    """Enforce conservative limits for supplementary files copied to jail."""
    max_files = 256
    if len(extra_files) > max_files:
        msg = f"Too many extra files: {len(extra_files)} (max {max_files})"
        raise ValueError(msg)

    per_file_limit = limits.max_file_size_mb * 1024 * 1024
    total_limit = per_file_limit * 4
    total_bytes = 0
    for path, content in extra_files.items():
        size = len(content)
        if size > per_file_limit:
            msg = f"extra_files entry too large for {path!r}: {size} bytes (max {per_file_limit})"
            raise ValueError(
                msg,
            )
        total_bytes += size
        if total_bytes > total_limit:
            msg = f"Combined extra_files payload too large: {total_bytes} bytes (max {total_limit})"
            raise ValueError(
                msg,
            )
