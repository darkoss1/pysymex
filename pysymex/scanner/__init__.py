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

"""pysymex Scanner -- public hub.

Lazy-loaded: symbols are resolved on first access via ``__getattr__``.

Re-exports from ``scanner_types`` (dataclasses) and ``scanner_core`` (logic).

Usage as module::

    from pysymex import scan_file, scan_directory
    results = scan_file("path/to/file.py")
    results = scan_directory("path/to/folder")

Usage as CLI::

    python -m pysymex.scanner [--dir FOLDER] [--log LOG_FILE]
"""

from __future__ import annotations

from importlib import import_module
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pysymex.scanner.core import (
        analyze_file as analyze_file,
        analyze_source as analyze_source,
        get_code_objects_with_context as get_code_objects_with_context,
        main as main,
        on_file_event as on_file_event,
        print_final_summary as print_final_summary,
        scan_directory as scan_directory,
        scan_file as scan_file,
    )
    from pysymex.scanner.types import (
        ScanResult as ScanResult,
        ScanResultBuilder as ScanResultBuilder,
        ScanSession as ScanSession,
    )
    from pysymex.scanner.async_scanner import scan_directory_async as scan_directory_async

_EXPORTS: dict[str, tuple[str, str]] = {
    "ScanResult": ("pysymex.scanner.types", "ScanResult"),
    "ScanResultBuilder": ("pysymex.scanner.types", "ScanResultBuilder"),
    "ScanSession": ("pysymex.scanner.types", "ScanSession"),
    "analyze_file": ("pysymex.scanner.core", "analyze_file"),
    "analyze_source": ("pysymex.scanner.core", "analyze_source"),
    "get_code_objects_with_context": ("pysymex.scanner.core", "get_code_objects_with_context"),
    "main": ("pysymex.scanner.core", "main"),
    "on_file_event": ("pysymex.scanner.core", "on_file_event"),
    "print_final_summary": ("pysymex.scanner.core", "print_final_summary"),
    "scan_directory": ("pysymex.scanner.core", "scan_directory"),
    "scan_file": ("pysymex.scanner.core", "scan_file"),
    "scan_directory_async": ("pysymex.scanner.async_scanner", "scan_directory_async"),
}


def __getattr__(name: str) -> object:
    """Getattr."""
    target = _EXPORTS.get(name)
    if target is None:
        raise AttributeError(f"module 'pysymex.scanner' has no attribute {name!r}")
    module_path, attr_name = target
    module = import_module(module_path)
    value = getattr(module, attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Dir."""
    return list(_EXPORTS.keys())


__all__: list[str] = [
    "ScanResult",
    "ScanResultBuilder",
    "ScanSession",
    "analyze_file",
    "analyze_source",
    "get_code_objects_with_context",
    "main",
    "on_file_event",
    "print_final_summary",
    "scan_directory",
    "scan_directory_async",
    "scan_file",
]

if __name__ == "__main__":
    from pysymex.scanner.core import main

    main()
