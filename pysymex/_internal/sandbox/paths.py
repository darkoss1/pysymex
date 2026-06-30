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

"""Shared sandbox staging path policy.

The runner and isolation backends both stage attacker-controlled names into a
jail. Keep path normalization here so direct backend callers cannot bypass a
policy enforced by the public runner.
"""

from __future__ import annotations

from pathlib import Path
from typing import Final

SAFE_SANDBOX_FILENAME_CHARS: Final[frozenset[str]] = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-.",
)

_WINDOWS_RESERVED_DEVICE_STEMS: Final[frozenset[str]] = frozenset(
    (
        "CON",
        "PRN",
        "AUX",
        "NUL",
        "CONIN$",
        "CONOUT$",
        *(f"COM{i}" for i in range(1, 10)),
        *(f"LPT{i}" for i in range(1, 10)),
    ),
)
_WINDOWS_ILLEGAL_PATH_CHARS: Final[frozenset[str]] = frozenset('<>"|?*')
_BLOCKED_SUPPLEMENTAL_FILE_SUFFIXES: Final[frozenset[str]] = frozenset(
    (
        ".bat",
        ".cmd",
        ".com",
        ".dll",
        ".dylib",
        ".exe",
        ".msi",
        ".pth",
        ".pyc",
        ".pyd",
        ".pyo",
        ".ps1",
        ".scr",
        ".so",
        ".vbs",
    ),
)


def _reject_reserved_path_segment(
    part: str,
    *,
    context: str,
    original: str,
) -> None:
    """Reject path segments that normalize unsafely on Windows.

    Args:
        part: Single normalized path segment to inspect.
        context: Human-readable operation name included in failures.
        original: Original caller-supplied path included in failures.

    Raises:
        ValueError: If the segment has trailing spaces or dots, control or
            illegal Windows characters, or a reserved device stem.

    """
    if part.endswith((" ", ".")):
        msg = f"{context} path segment has unsafe trailing space/dot: {original!r}"
        raise ValueError(msg)
    if any(ord(ch) < 32 for ch in part):
        msg = f"{context} path segment contains control character: {original!r}"
        raise ValueError(msg)
    if any(ch in _WINDOWS_ILLEGAL_PATH_CHARS for ch in part):
        msg = f"{context} path segment contains illegal character: {original!r}"
        raise ValueError(msg)

    stem = part.split(".", 1)[0].rstrip(" .").upper()
    if stem in _WINDOWS_RESERVED_DEVICE_STEMS:
        msg = f"{context} path segment uses reserved device name: {original!r}"
        raise ValueError(msg)


def safe_relative_parts(path_text: str, *, context: str) -> tuple[str, ...]:
    """Validate a relative staged path and return normalized segments.

    Args:
        path_text: User-supplied relative path to validate.
        context: Human-readable operation name included in failures.

    Returns:
        Non-empty path segments with slash forms normalized for validation.

    Raises:
        ValueError: If the path is absolute, drive- or stream-qualified,
            traversing, option-like, empty after normalization, or unsafe
            under Windows path normalization rules.

    """
    normalized = path_text.replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        msg = f"{context} path must be relative: {path_text!r}"
        raise ValueError(msg)
    if ":" in normalized:
        msg = f"{context} path must not include drive prefix or stream: {path_text!r}"
        raise ValueError(msg)

    parts = tuple(part for part in normalized.split("/") if part not in {"", "."})
    if not parts:
        msg = f"{context} path resolves to empty path: {path_text!r}"
        raise ValueError(msg)
    if any(part == ".." for part in parts):
        msg = f"{context} path traversal is not allowed: {path_text!r}"
        raise ValueError(msg)
    if any(part.startswith("-") for part in parts):
        msg = f"{context} path segment starts with '-': {path_text!r}"
        raise ValueError(msg)
    for part in parts:
        _reject_reserved_path_segment(part, context=context, original=path_text)
    return parts


def canonicalize_sandbox_relative_path(path_text: str, *, context: str) -> str:
    """Validate a staged relative path and join its segments with slashes.

    Args:
        path_text: User-supplied relative path to normalize.
        context: Human-readable operation name included in failures.

    Returns:
        Validated path text using POSIX-style separators.

    Raises:
        ValueError: If `safe_relative_parts` rejects the supplied path.

    """
    return "/".join(safe_relative_parts(path_text, context=context))


def validate_sandbox_filename(name: str, *, context: str = "filename") -> None:
    """Validate a single filename accepted for a staged target source file.

    Args:
        name: Candidate target filename.
        context: Human-readable operation name included in failures.

    Raises:
        ValueError: If `name` is not one relative segment, begins with a dot,
            or includes characters outside the target filename allowlist.

    """
    parts = safe_relative_parts(name, context=context)
    if len(parts) != 1:
        msg = f"{context} must not include path separators: {name!r}"
        raise ValueError(msg)
    filename = parts[0]
    if filename.startswith("."):
        msg = f"{context} starts with dangerous character: {name!r}"
        raise ValueError(msg)
    if not all(ch in SAFE_SANDBOX_FILENAME_CHARS for ch in filename):
        msg = f"{context} contains illegal characters: {name!r}"
        raise ValueError(msg)


def validate_extra_file_path(path_text: str, *, context: str = "extra_files") -> str:
    """Validate a supplemental staged path and reject executable-like suffixes.

    Args:
        path_text: Candidate relative path for a staged supplemental file.
        context: Human-readable operation name included in failures.

    Returns:
        Validated path text using POSIX-style separators.

    Raises:
        ValueError: If path normalization fails or the final suffix is in the
            blocked executable/native suffix set.

    """
    normalized = canonicalize_sandbox_relative_path(path_text, context=context)
    suffix = Path(normalized).suffix.lower()
    if suffix in _BLOCKED_SUPPLEMENTAL_FILE_SUFFIXES:
        msg = f"{context} path has blocked executable/native suffix: {path_text!r}"
        raise ValueError(msg)
    return normalized


def sanitize_extra_files(extra_files: dict[str, bytes] | None) -> dict[str, bytes]:
    """Normalize supplemental-file paths and copy their byte payloads.

    Args:
        extra_files: Mapping of staged relative paths to byte-like payloads,
            or `None`.

    Returns:
        A new mapping keyed by normalized paths with `bytes` payload values.

    Raises:
        ValueError: If a supplemental path violates staging policy.

    """
    if not extra_files:
        return {}

    sanitized: dict[str, bytes] = {}
    for rel_path, content in extra_files.items():
        normalized = validate_extra_file_path(str(rel_path), context="extra_files")
        sanitized[normalized] = bytes(content)
    return sanitized


def jail_relative_path(jail_root: Path, path_text: str, *, context: str) -> Path:
    """Build a staged path beneath a jail after policy and containment checks.

    Args:
        jail_root: Directory used as the sandbox staging root.
        path_text: Candidate relative path to stage.
        context: Operation name; `extra_files` also enables supplemental-file
            suffix restrictions.

    Returns:
        The un-resolved candidate path below `jail_root`.

    Raises:
        ValueError: If path policy rejects the input or resolved containment
            would escape the jail root.

    Limitations:
        This function validates the candidate path before a later filesystem
        operation; it does not itself create files or prevent later races.

    """
    if context == "extra_files":
        normalized = validate_extra_file_path(path_text, context=context)
        parts = tuple(normalized.split("/"))
    else:
        parts = safe_relative_parts(path_text, context=context)
    candidate = jail_root.joinpath(*parts)
    resolved = candidate.resolve(strict=False)
    if resolved != jail_root and jail_root not in resolved.parents:
        msg = f"Refusing to write outside sandbox jail: {path_text!r}"
        raise ValueError(msg)
    return candidate
