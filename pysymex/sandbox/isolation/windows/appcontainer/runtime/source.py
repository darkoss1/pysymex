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

"""Filtered CPython runtime source discovery for Windows AppContainer."""

from __future__ import annotations

import os
from pathlib import Path

from ..shared import (
    RUNTIME_ALLOWED_NATIVE_EXTENSIONS,
    RUNTIME_EXCLUDED_DIR_NAMES,
    RUNTIME_EXCLUDED_FILE_PREFIXES,
)


def iter_runtime_source_files(source_root: Path) -> list[tuple[str, Path]]:
    """Return runtime files under a Python installation root."""
    files: list[tuple[str, Path]] = []
    executable = source_root / "python.exe"
    if executable.is_file() and not executable.is_symlink():
        files.append(("python.exe", executable))

    for source_file in sorted(source_root.glob("*.dll"), key=lambda path: path.name.lower()):
        if source_file.is_file() and not source_file.is_symlink():
            files.append((source_file.name, source_file))

    source_dlls = source_root / "DLLs"
    if source_dlls.is_dir() and not source_dlls.is_symlink():
        files.extend(_iter_filtered_runtime_tree(source_dlls, "DLLs"))

    source_lib = source_root / "Lib"
    if source_lib.is_dir() and not source_lib.is_symlink():
        files.extend(_iter_filtered_runtime_tree(source_lib, "Lib"))
    return files


def _iter_filtered_runtime_tree(
    directory: Path,
    relative_prefix: str,
) -> list[tuple[str, Path]]:
    """Return non-excluded runtime files below ``directory``."""
    files: list[tuple[str, Path]] = []
    with os.scandir(directory) as entries:
        scanned = sorted(entries, key=lambda entry: entry.name.lower())
        ignored = _runtime_copy_ignore([entry.name for entry in scanned])
        for entry in scanned:
            if entry.name in ignored or entry.is_symlink():
                continue
            relative_path = f"{relative_prefix}/{entry.name}"
            entry_path = Path(entry.path)
            if entry.is_dir(follow_symlinks=False):
                files.extend(_iter_filtered_runtime_tree(entry_path, relative_path))
            elif entry.is_file(follow_symlinks=False):
                files.append((relative_path, entry_path))
    return files


def _runtime_copy_ignore(names: list[str]) -> set[str]:
    """Return names that should not be copied into the runtime cache."""
    ignored: set[str] = set()
    for name in names:
        lower_name = name.lower()
        if lower_name in RUNTIME_EXCLUDED_DIR_NAMES:
            ignored.add(name)
            continue
        if lower_name.startswith(RUNTIME_EXCLUDED_FILE_PREFIXES):
            ignored.add(name)
            continue
        if lower_name.endswith((".pyc", ".pyo")):
            ignored.add(name)
            continue
        if lower_name.endswith(".pyd") and lower_name not in RUNTIME_ALLOWED_NATIVE_EXTENSIONS:
            ignored.add(name)
    return ignored
