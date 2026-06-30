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

"""Console-based scan reporter for CLI output.

Implements the :class:`~pysymex._internal.scanner.protocols.ScanReporter`
protocol — all emoji / colour / progress-bar logic lives here, keeping
scanner execution free of presentation concerns.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from pysymex._internal.cli.output import CliOutput
from pysymex._internal.reporting.summary import summarize_scan_results
from pysymex._internal.scanner.types import ScanResult

if TYPE_CHECKING:
    from collections.abc import Sequence


def _as_scan_result(value: object) -> ScanResult | None:
    """Cast a generic object to a ScanResult instance if compatible.

    Args:
        value (object): The object to cast.

    Returns:
        ScanResult | None: The ScanResult instance if compatible, otherwise None.

    """
    return value if isinstance(value, ScanResult) else None


def _iter_object_mapping_items(value: object) -> list[tuple[str, object]]:
    """Return mapping items as ``(str, object)`` pairs when possible."""
    if not isinstance(value, dict):
        return []
    result: list[tuple[str, object]] = []
    mapping = cast("dict[object, object]", value)
    for key, item_value in mapping.items():
        result.append((str(key), item_value))
    return result


class ConsoleScanReporter:
    """Pretty-prints scan progress and results to stdout.

    This is the default reporter wired in by CLI entry-points.  Library
    users can pass ``reporter=None`` to ``scan_directory`` for silent
    operation, or supply their own ``ScanReporter``-compatible object.
    """

    def __init__(self, show_stats: bool = False) -> None:
        """Initialize reporter.

        Args:
            show_stats: Whether to display performance statistics.

        """
        self.show_stats = show_stats

    def on_file_start(self, file_path: object) -> None:
        """On file start."""
        CliOutput.safe_print(f"\n{'=' * 70}")
        CliOutput.safe_print(f"[SCAN] Scanning: {file_path}")
        CliOutput.safe_print("=" * 70)

    def on_file_done(self, file_path: object, result: object) -> None:
        """On file done."""
        _ = file_path
        scan_result = _as_scan_result(result)
        if scan_result is None:
            CliOutput.safe_print("\n[X] Invalid scan result")
            return
        if scan_result.issues:
            CliOutput.safe_print(f"\n[!] Found {len(scan_result.issues)} potential issues:\n")
            for issue in scan_result.issues:
                CliOutput.safe_print(
                    f"   - [{issue['kind']}] {issue['message']} (Line {issue['line']})",
                )
                counterexample = issue.get("counterexample")
                for var, val in _iter_object_mapping_items(counterexample):
                    CliOutput.safe_print(f"       - {var} = {val}")
        elif scan_result.error:
            CliOutput.safe_print(f"\n[X] {scan_result.error}")
        elif hasattr(scan_result, "degraded_passes") and scan_result.degraded_passes:
            CliOutput.safe_print(
                f"\n[!] Analysis degraded: {', '.join(scan_result.degraded_passes)}",
            )
        else:
            CliOutput.safe_print("\n[OK] No issues found!")
        stats_line = (
            f"\n   [STATS] {scan_result.code_objects} code objects"
            f" | {scan_result.paths_explored} paths explored"
        )
        if self.show_stats:
            stats_line += f" | Time: {scan_result.elapsed_time:.2f}s | Avg Memory: {scan_result.avg_memory_mb:.2f} MB"
        CliOutput.safe_print(stats_line)

    def on_issue(self, issue: dict[str, object]) -> None:
        """Callback triggered when a new issue is discovered during the scan.

        Prints the issue kind, message, and line number to standard output.

        Args:
            issue (dict[str, object]): A dictionary containing details of the discovered issue.

        """
        CliOutput.safe_print(f"   - [{issue['kind']}] {issue['message']} (Line {issue['line']})")

    def on_error(self, file_path: object, error: str) -> None:
        """Callback triggered when a file scanning error occurs.

        Prints the error details to standard output.

        Args:
            file_path (object): The path of the file that failed to scan.
            error (str): The error message string describing the failure.

        """
        _ = file_path
        CliOutput.safe_print(f"\n[X] {error}")

    def on_progress(
        self,
        completed: int,
        total: int,
        file_path: object,
        result: object | None,
    ) -> None:
        """On progress."""
        status = "[OK]"
        if result is None or getattr(result, "error", None):
            status = "[X]"
        elif getattr(result, "degraded_passes", []):
            status = "[!]"
        else:
            typed_result = _as_scan_result(result)
            if typed_result is not None and typed_result.issues:
                status = f"[!] {len(typed_result.issues)}"
        CliOutput.safe_print(CliOutput.progress_line(completed, total, file_path, status))

    def on_status(self, message: str) -> None:
        """Print a generic status message."""
        CliOutput.safe_print(message)

    def on_summary(self, results: Sequence[object], total_files: int) -> None:
        """On summary."""
        typed_results = [r for r in results if isinstance(r, ScanResult)]
        summary = summarize_scan_results(typed_results, total_files)
        CliOutput.safe_print(
            f"\nSummary: {summary.total_issues} issues in "
            f"{summary.files_with_issues}/{len(results)} files",
        )
        if summary.errors:
            CliOutput.safe_print(f" ({summary.errors} errors, {summary.degraded} degraded)")
        elif summary.degraded:
            CliOutput.safe_print(f" ({summary.degraded} degraded)")
        else:
            CliOutput.safe_print()
        if summary.missing_files:
            CliOutput.safe_print(f"  [!] {summary.missing_files} file(s) could not be scanned")
