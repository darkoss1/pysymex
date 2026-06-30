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

"""Canonical repository scanning workflows."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Unpack, cast

if TYPE_CHECKING:
    from pysymex._internal.config.api.runtime import (
        ScanDirectoryConfigKwargs,
        ScanFileConfigKwargs,
        ScanPathConfigKwargs,
    )
    from pysymex._internal.scanner.types import ScanResult

_DIRECTORY_ONLY_OPTIONS = frozenset(("pattern", "workers"))
_FILE_ONLY_OPTIONS = frozenset(("execution_observer", "confirm_issues", "replay_timeout"))


def file(path: str | Path, **options: Unpack[ScanFileConfigKwargs]) -> ScanResult:
    """Scan one Python file and return its aggregated result."""
    from pysymex._internal.scanner.file import scan_file

    return scan_file(path, **options)


def directory(path: str | Path, **options: Unpack[ScanDirectoryConfigKwargs]) -> list[ScanResult]:
    """Scan matching Python files below a directory."""
    from pysymex._internal.scanner.directory.scan import scan_directory

    return scan_directory(path, **options)


def path(target: str | Path, **options: Unpack[ScanPathConfigKwargs]) -> ScanResult | list[ScanResult]:
    """Scan a file or directory, choosing the workflow from the filesystem target."""
    target_path = Path(target)
    if target_path.is_dir():
        _reject_options(options, _FILE_ONLY_OPTIONS, "directory scans")
        return directory(target_path, **cast("ScanDirectoryConfigKwargs", options))
    _reject_options(options, _DIRECTORY_ONLY_OPTIONS, "file scans")
    return file(target_path, **cast("ScanFileConfigKwargs", options))


def _reject_options(
    options: object,
    unsupported_options: frozenset[str],
    workflow_name: str,
) -> None:
    """Reject workflow-specific options that cannot apply to the selected target kind."""
    if not isinstance(options, Mapping):
        return
    option_mapping = cast("Mapping[str, object]", options)
    unsupported = sorted(unsupported_options.intersection(option_mapping))
    if unsupported:
        names = ", ".join(unsupported)
        msg = f"{workflow_name} do not accept option(s): {names}"
        raise TypeError(msg)


__all__ = [
    "directory",
    "file",
    "path",
]
