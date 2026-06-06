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

"""pysymex Scanner -- batch symbolic-scan orchestration hub.

Owns per-file and per-directory scan workflows, ``ScanResult`` aggregation,
and CLI entrypoints. Module loading and AST preflight live under
``pysymex.analysis.scan.loading`` and ``pysymex.analysis.scan.preflight``; the VM and
detectors live under ``pysymex.execution`` and ``pysymex.analysis.detectors``.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Usage as module::

    from pysymex import scan_file, scan_directory
    results = scan_file("path/to/file.py")
    results = scan_directory("path/to/folder")

Usage as CLI::

    python -m pysymex.scanner [--dir FOLDER] [--log LOG_FILE]
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from pysymex.lazy import lazy_dir, lazy_getattr

if TYPE_CHECKING:
    from pysymex.scanner.cli import main
    from pysymex.scanner.directory import scan_directory as scan_directory
    from pysymex.scanner.file import scan_file as scan_file
    from pysymex.scanner.summary import print_final_summary as print_final_summary
    from pysymex.scanner.types import (
        ScanResult as ScanResult,
        ScanResultBuilder as ScanResultBuilder,
        ScanSession as ScanSession,
    )

_EXPORTS: dict[str, tuple[str, str]] = {
    "ScanResult": ("pysymex.scanner.types", "ScanResult"),
    "ScanResultBuilder": ("pysymex.scanner.types", "ScanResultBuilder"),
    "ScanSession": ("pysymex.scanner.types", "ScanSession"),
    "main": ("pysymex.scanner.cli", "main"),
    "print_final_summary": ("pysymex.scanner.summary", "print_final_summary"),
    "scan_directory": ("pysymex.scanner.directory", "scan_directory"),
    "scan_file": ("pysymex.scanner.file", "scan_file"),
}


def __getattr__(name: str) -> object:
    """Resolve a registered scanner export on first attribute access.

    Returns:
        The imported module attribute resolved dynamically.
    """
    return lazy_getattr(name, __name__, _EXPORTS, globals())


def __dir__() -> list[str]:
    """Return lazily exported scanner names for introspection.

    Returns:
        A list of exported scanner attribute names.
    """
    return lazy_dir(_EXPORTS, globals(), include_namespace=False)


__all__: list[str] = [
    "ScanResult",
    "ScanResultBuilder",
    "ScanSession",
    "main",
    "print_final_summary",
    "scan_directory",
    "scan_file",
]

if __name__ == "__main__":
    from pysymex.scanner.cli import main

    main()
