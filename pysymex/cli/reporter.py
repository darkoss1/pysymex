# pysymex: Python Symbolic Execution & Formal Verification
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

Implements the :class:`~pysymex.analysis.detectors.protocols.ScanReporter`
protocol — all emoji / colour / progress-bar logic lives here, keeping
``scanner.core`` free of presentation concerns.
"""

from __future__ import annotations

import sys
from collections.abc import Sequence
from pathlib import Path

from pysymex.scanner.types import ScanResult, ScanSession


def _descending_count(item: tuple[str, int]) -> int:
    return -item[1]


def _as_scan_result(value: object) -> ScanResult | None:
    return value if isinstance(value, ScanResult) else None


def _as_scan_session(value: object) -> ScanSession | None:
    return value if isinstance(value, ScanSession) else None


def _safe_print(message: str = "") -> None:
    """Print text safely across console encodings (e.g. cp1252 on Windows)."""
    try:
        print(message)
    except UnicodeEncodeError:
        encoding = sys.stdout.encoding or "utf-8"
        fallback = message.encode(encoding, errors="replace").decode(encoding, errors="replace")
        print(fallback)


def _iter_object_mapping_items(value: object) -> list[tuple[str, object]]:
    """Return mapping items as ``(str, object)`` pairs when possible."""
    if not isinstance(value, dict):
        return []
    result: list[tuple[str, object]] = []
    raw_map: dict[object, object] = value  # type: ignore[reportUnknownVariableType]  # value is dict[Unknown, Unknown] after isinstance check
    for key, item_value in raw_map.items():
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
        _safe_print(f"\n{'=' * 70}")
        _safe_print(f"[SCAN] Scanning: {file_path}")
        _safe_print("=" * 70)

    def on_file_done(self, file_path: object, result: object) -> None:
        """On file done."""
        _ = file_path
        scan_result = _as_scan_result(result)
        if scan_result is None:
            _safe_print("\n[X] Invalid scan result")
            return
        if scan_result.issues:
            _safe_print(f"\n[!] Found {len(scan_result.issues)} potential issues:\n")
            for issue in scan_result.issues:
                _safe_print(f"   - [{issue['kind']}] {issue['message']} (Line {issue['line']})")
                counterexample = issue.get("counterexample")
                for var, val in _iter_object_mapping_items(counterexample):
                    _safe_print(f"       - {var} = {val}")
        elif scan_result.error:
            _safe_print(f"\n[X] {scan_result.error}")
        else:
            _safe_print("\n[OK] No issues found!")
        stats_line = (
            f"\n   [STATS] {scan_result.code_objects} code objects"
            f" | {scan_result.paths_explored} paths explored"
        )
        if self.show_stats:
            stats_line += f" | Time: {scan_result.elapsed_time:.2f}s | Avg Memory: {scan_result.avg_memory_mb:.2f} MB"
        _safe_print(stats_line)

    def on_issue(self, issue: dict[str, object]) -> None:
        _safe_print(f"   - [{issue['kind']}] {issue['message']} (Line {issue['line']})")

    def on_error(self, file_path: object, error: str) -> None:
        _ = file_path
        _safe_print(f"\n[X] {error}")

    def on_progress(
        self,
        completed: int,
        total: int,
        file_path: object,
        result: object | None,
    ) -> None:
        """On progress."""
        pct = completed * 100 // total if total else 0
        name = Path(str(file_path)).name if file_path else "?"
        status = "[OK]"
        if result is None or getattr(result, "error", None):
            status = "[X]"
        else:
            typed_result = _as_scan_result(result)
            if typed_result is not None and typed_result.issues:
                status = f"[!] {len(typed_result.issues)}"
        _safe_print(f"[{completed}/{total}] ({pct}%) {name} {status}")

    def on_status(self, message: str) -> None:
        """Print a generic status message."""
        _safe_print(message)

    def on_summary(self, results: Sequence[object], total_files: int) -> None:
        """On summary."""
        typed_results = [r for r in results if isinstance(r, ScanResult)]
        total_issues = sum(len(r.issues) for r in typed_results)
        files_with_issues = sum(1 for r in typed_results if r.issues)
        errors = sum(1 for r in typed_results if r.error)
        _safe_print(
            f"\nSummary: {total_issues} issues in {files_with_issues}/{len(results)} files",
        )
        if errors:
            _safe_print(f" ({errors} errors)")
        else:
            _safe_print()
        if len(results) < total_files:
            _safe_print(f"  [!] {total_files - len(results)} file(s) could not be scanned")

    def on_session_summary(self, session: object) -> None:
        """Print a formatted session summary (watch-mode or full scan)."""
        typed_session = _as_scan_session(session)
        if typed_session is None:
            _safe_print("\n[X] Invalid scan session")
            return
        summary = typed_session.get_summary()
        _safe_print(f"\n\n{'=' * 70}")
        _safe_print("[SUMMARY] SESSION SUMMARY")
        _safe_print("=" * 70)
        _safe_print(f"   Files scanned:     {summary['files_scanned']}")
        _safe_print(f"   Files with issues: {summary['files_with_issues']}")
        _safe_print(f"   Files clean:       {summary['files_clean']}")
        _safe_print(f"   Files with errors: {summary['files_error']}")
        _safe_print(f"   Total issues:      {summary['total_issues']}")
        if self.show_stats:
            _safe_print(f"   Total time:        {summary.get('total_time', 0.0):.2f}s")
            _safe_print(f"   Avg memory:        {summary.get('avg_memory', 0.0):.2f} MB")
        _safe_print()
        issue_breakdown = summary.get("issue_breakdown")
        _safe_print("   Issue breakdown:")
        for kind, count in sorted(issue_breakdown.items(), key=_descending_count):
            bar = "#" * min(count, 30)
            _safe_print(f"      {kind:<25} {count:>4} {bar}")
        _safe_print(f"\n   [LOG] Log saved to: {typed_session.log_file}")
        _safe_print("=" * 70)
