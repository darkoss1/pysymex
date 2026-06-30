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

"""Package name and package-root detection for compile-only scan loading."""

from __future__ import annotations

import contextlib
import sys
import threading
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

_PACKAGE_IMPORT_PATH_LOCK = threading.RLock()


def detect_package_name(file_path: Path) -> tuple[str, str]:
    """Detect the module name and package name for a given file."""
    parts: list[str] = [file_path.stem]
    current = file_path.parent
    package_parts: list[str] = []

    while current and (current / "__init__.py").exists():
        parts.insert(0, current.name)
        package_parts.insert(0, current.name)
        current = current.parent

    full_name = ".".join(parts)
    package_name = ".".join(package_parts)
    return full_name, package_name


def find_package_root(file_path: Path) -> Path | None:
    """Find the root of the package containing the given file."""
    current = file_path.resolve().parent
    root = None
    while current and (current / "__init__.py").exists():
        root = current.parent
        current = current.parent
    return root


@contextlib.contextmanager
def scoped_package_import_path(file_path: Path) -> Generator[None]:
    """Expose a target package root only for the lifetime of one file scan.

    Finds the package root directory for the given file and inserts it at the
    head of ``sys.path`` to allow resolution of sibling and relative imports.
    Ensures safe concurrent modifications using a re-entrant lock.

    Args:
        file_path: Path to the target source file being scanned.

    Side Effects:
        Temporarily modifies ``sys.path`` during the context block.

    """
    package_root = find_package_root(file_path)
    if package_root is None:
        yield
        return

    root_text = str(package_root)
    with _PACKAGE_IMPORT_PATH_LOCK:
        inserted = root_text not in sys.path
        if inserted:
            sys.path.insert(0, root_text)
        try:
            yield
        finally:
            if inserted and root_text in sys.path:
                sys.path.remove(root_text)
