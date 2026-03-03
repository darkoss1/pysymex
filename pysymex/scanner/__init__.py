"""
pysymex Scanner – public hub
==============================
Re-exports from ``scanner_types`` (dataclasses) and ``scanner_core`` (logic).

Usage as module:
    from pysymex import scan_file, scan_directory
    results = scan_file("path/to/file.py")
    results = scan_directory("path/to/folder")
Usage as CLI:
    python -m pysymex.scanner [--dir FOLDER] [--log LOG_FILE]
"""

from pysymex.scanner.core import analyze_file as analyze_file

from pysymex.scanner.core import get_code_objects_with_context as get_code_objects_with_context

from pysymex.scanner.core import main as main

from pysymex.scanner.core import on_file_event as on_file_event

from pysymex.scanner.core import print_final_summary as print_final_summary

from pysymex.scanner.core import scan_directory as scan_directory

from pysymex.scanner.core import scan_file as scan_file

from pysymex.scanner.core import session as session

from pysymex.scanner.types import ScanResult as ScanResult

from pysymex.scanner.types import ScanSession as ScanSession

__all__ = [
    "ScanResult",
    "ScanSession",
    "analyze_file",
    "get_code_objects_with_context",
    "main",
    "on_file_event",
    "print_final_summary",
    "scan_directory",
    "scan_file",
    "session",
]


if __name__ == "__main__":
    main()
